// Package vnc is the agent's VNC screenshot transport. It speaks just
// enough of the RFB protocol (RFC 6143, version 3.8) to negotiate a
// no-auth session, request one full-framebuffer update in Raw encoding,
// and hand back a PNG.
//
// Scope:
//
//   - Only the "None" security type is supported. Servers that require
//     a password or VeNCrypt are rejected — natlas-agent has no
//     credentials store and exposing one here is out of scope.
//   - Only the Raw encoding is requested. Compression encodings (Tight,
//     ZRLE, Hextile, etc.) are useful for interactive sessions; for a
//     one-shot screenshot the bandwidth cost is irrelevant and the
//     decoders aren't worth the complexity.
//   - One FramebufferUpdateRequest, then we stop. Server-initiated
//     side messages (Bell, ServerCutText, SetColourMapEntries) are
//     drained until the first FramebufferUpdate arrives.
//
// The transport is deliberately defensive about server-controlled
// sizes: a hard cap on framebuffer dimensions stops a hostile server
// from convincing us to allocate gigabytes of RGBA. The cap is high
// enough (8192x8192) that real desktops fit comfortably.
package vnc

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	"image/png"
	"io"
	"net"
	"strconv"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

var tracer = otel.Tracer("natlas/agent/screenshots/vnc")

// maxFramebufferPixels caps the product of width*height we'll accept
// from a server's ServerInit. 8192*8192*4 bytes ≈ 256 MiB worst-case
// allocation per capture — still bounded, but large enough that real
// 4K+ desktops fit.
const maxFramebufferPixels = 8192 * 8192

// Options configures the VNC capturer.
type Options struct {
	// CaptureTimeout caps the entire connect → handshake → framebuffer
	// → PNG-encode cycle. Defaults to 15s if zero.
	CaptureTimeout time.Duration

	// DialTimeout caps just the TCP connect. Defaults to 5s if zero,
	// or CaptureTimeout if that's smaller.
	DialTimeout time.Duration
}

// Capturer is the agent-side screenshots.Capturer for VNC targets.
//
// Unlike the chromedp capturer there's no long-lived resource to
// bootstrap — each call opens a fresh TCP connection. That's the right
// shape for VNC: sessions are cheap, and pooling across hosts buys
// nothing.
type Capturer struct {
	opts Options
}

// New returns a Capturer with the given options.
func New(opts Options) *Capturer {
	if opts.CaptureTimeout <= 0 {
		opts.CaptureTimeout = 15 * time.Second
	}
	if opts.DialTimeout <= 0 || opts.DialTimeout > opts.CaptureTimeout {
		opts.DialTimeout = 5 * time.Second
		if opts.DialTimeout > opts.CaptureTimeout {
			opts.DialTimeout = opts.CaptureTimeout
		}
	}
	return &Capturer{opts: opts}
}

// Capture connects to target:port, completes an RFB handshake, requests
// a single full-framebuffer update in Raw encoding, and returns the
// PNG-encoded image.
//
// service must be "VNC" — the screenshots package only routes VNC ports
// here, but we re-check so a misconfigured orchestrator fails loudly.
func (c *Capturer) Capture(ctx context.Context, target string, port int, service string) ([]byte, error) {
	if service != "VNC" {
		return nil, fmt.Errorf("vnc capturer: unsupported service %q", service)
	}

	ctx, span := tracer.Start(ctx, "screenshot.vnc",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("target", target),
			attribute.Int("port", port),
			attribute.String("service", service),
		),
	)
	defer span.End()

	ctx, cancel := context.WithTimeout(ctx, c.opts.CaptureTimeout)
	defer cancel()

	addr := net.JoinHostPort(target, strconv.Itoa(port))
	dialer := net.Dialer{Timeout: c.opts.DialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		span.SetStatus(codes.Error, "dial: "+err.Error())
		return nil, fmt.Errorf("vnc capturer: dial %s: %w", addr, err)
	}
	defer conn.Close()

	// Close the connection if the parent context cancels mid-IO so
	// blocking reads return promptly. SetDeadline alone covers the
	// hard timeout; this covers explicit cancellation.
	stopWatch := make(chan struct{})
	defer close(stopWatch)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-stopWatch:
		}
	}()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	img, err := captureFramebuffer(conn)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		// Distinguish ctx cancellation from a real protocol failure so
		// the caller's "timed out vs broken server" telemetry is honest.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, fmt.Errorf("vnc capturer: %s on %s: %w", ctxErr, addr, err)
		}
		return nil, fmt.Errorf("vnc capturer: %s: %w", addr, err)
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "png encode: "+err.Error())
		return nil, fmt.Errorf("vnc capturer: png encode: %w", err)
	}
	span.SetAttributes(
		attribute.Int("png_bytes", buf.Len()),
		attribute.Int("fb_width", img.Bounds().Dx()),
		attribute.Int("fb_height", img.Bounds().Dy()),
	)
	return buf.Bytes(), nil
}

// captureFramebuffer drives the full RFB conversation on conn and
// returns the first complete framebuffer it receives. conn is left
// open; the caller owns the lifetime.
func captureFramebuffer(conn io.ReadWriter) (*image.RGBA, error) {
	if err := handshakeProtocol(conn); err != nil {
		return nil, err
	}
	if err := handshakeSecurity(conn); err != nil {
		return nil, err
	}
	width, height, err := init38(conn)
	if err != nil {
		return nil, err
	}
	if width == 0 || height == 0 {
		return nil, fmt.Errorf("server reports empty framebuffer (%dx%d)", width, height)
	}
	if int(width)*int(height) > maxFramebufferPixels {
		return nil, fmt.Errorf("framebuffer %dx%d exceeds %d pixel cap",
			width, height, maxFramebufferPixels)
	}

	if err := setPixelFormat(conn); err != nil {
		return nil, fmt.Errorf("set pixel format: %w", err)
	}
	if err := setEncodings(conn); err != nil {
		return nil, fmt.Errorf("set encodings: %w", err)
	}
	if err := framebufferUpdateRequest(conn, width, height); err != nil {
		return nil, fmt.Errorf("fb update request: %w", err)
	}
	return readFramebufferUpdate(conn, width, height)
}

// -----------------------------------------------------------------------------
// Handshake
// -----------------------------------------------------------------------------

// handshakeProtocol exchanges the 12-byte ProtocolVersion strings.
// We always negotiate down to 3.8 — it's the most-widely-implemented
// version and the security flow we depend on (SecurityResult on a
// "None" choice) is mandatory there but optional in 3.3/3.7.
func handshakeProtocol(conn io.ReadWriter) error {
	var srv [12]byte
	if _, err := io.ReadFull(conn, srv[:]); err != nil {
		return fmt.Errorf("read server protocol version: %w", err)
	}
	if !bytes.HasPrefix(srv[:], []byte("RFB ")) || srv[11] != '\n' {
		return fmt.Errorf("unexpected server greeting %q", srv[:])
	}
	if _, err := conn.Write([]byte("RFB 003.008\n")); err != nil {
		return fmt.Errorf("write client protocol version: %w", err)
	}
	return nil
}

// handshakeSecurity runs the RFB 3.8 security negotiation. We require
// type 1 (None); anything else (VNCAuth, VeNCrypt, Tight) is rejected
// because we don't ship credential handling.
func handshakeSecurity(conn io.ReadWriter) error {
	var count [1]byte
	if _, err := io.ReadFull(conn, count[:]); err != nil {
		return fmt.Errorf("read security count: %w", err)
	}
	if count[0] == 0 {
		// Server refused the connection. The reason follows as a
		// length-prefixed string and is the most useful diagnostic.
		reason, _ := readU32String(conn)
		return fmt.Errorf("server refused connection: %s", reason)
	}
	types := make([]byte, count[0])
	if _, err := io.ReadFull(conn, types); err != nil {
		return fmt.Errorf("read security types: %w", err)
	}
	if !bytes.ContainsRune(types, 1) {
		return fmt.Errorf("server offers no acceptable security types (got %v); natlas-agent only supports None", types)
	}
	if _, err := conn.Write([]byte{1}); err != nil {
		return fmt.Errorf("write security choice: %w", err)
	}

	var result [4]byte
	if _, err := io.ReadFull(conn, result[:]); err != nil {
		return fmt.Errorf("read security result: %w", err)
	}
	if binary.BigEndian.Uint32(result[:]) != 0 {
		reason, _ := readU32String(conn)
		return fmt.Errorf("security handshake failed: %s", reason)
	}
	return nil
}

// init38 sends ClientInit and parses ServerInit, returning the
// framebuffer dimensions. We ignore the server's pixel format here —
// we re-negotiate ours via SetPixelFormat — but still drain the bytes.
func init38(conn io.ReadWriter) (width, height uint16, err error) {
	if _, err := conn.Write([]byte{1}); err != nil { // shared = 1
		return 0, 0, fmt.Errorf("write client init: %w", err)
	}
	var hdr [24]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return 0, 0, fmt.Errorf("read server init: %w", err)
	}
	width = binary.BigEndian.Uint16(hdr[0:2])
	height = binary.BigEndian.Uint16(hdr[2:4])
	// hdr[4:20] is the server's PixelFormat; we ignore it.
	nameLen := binary.BigEndian.Uint32(hdr[20:24])
	if nameLen > 1024 {
		// Pathological name length — RFB names are typically a hostname
		// or a short label. Refuse rather than blindly allocating.
		return 0, 0, fmt.Errorf("server init name length %d implausibly large", nameLen)
	}
	if nameLen > 0 {
		if _, err := io.CopyN(io.Discard, conn, int64(nameLen)); err != nil {
			return 0, 0, fmt.Errorf("read desktop name: %w", err)
		}
	}
	return width, height, nil
}

// -----------------------------------------------------------------------------
// Outbound: SetPixelFormat, SetEncodings, FramebufferUpdateRequest
// -----------------------------------------------------------------------------

// preferredPixelFormat is what we ask the server to send us in:
// 32 bits per pixel, depth 24, big-endian on the wire, true-color,
// with R in the most-significant byte of the 32-bit word. With
// big_endian_flag=1 and shifts {R:16,G:8,B:0}, each pixel comes off
// the wire as the four bytes [pad, R, G, B] — easy to copy into
// image.RGBA.Pix (we just shift A=255 in).
var preferredPixelFormat = [16]byte{
	32,   // bits_per_pixel
	24,   // depth
	1,    // big_endian_flag
	1,    // true_color_flag
	0, 255, // red_max   (big-endian uint16) = 255
	0, 255, // green_max
	0, 255, // blue_max
	16, // red_shift
	8,  // green_shift
	0,  // blue_shift
	0, 0, 0, // padding
}

func setPixelFormat(conn io.ReadWriter) error {
	var msg [20]byte
	msg[0] = 0 // SetPixelFormat
	// msg[1:4] padding
	copy(msg[4:], preferredPixelFormat[:])
	_, err := conn.Write(msg[:])
	return err
}

// setEncodings tells the server we only know Raw. The server is
// required to honor this; even if it would prefer something denser
// it'll fall back to Raw for our rectangles.
func setEncodings(conn io.ReadWriter) error {
	const numEncodings = 1
	var msg [4 + numEncodings*4]byte
	msg[0] = 2 // SetEncodings
	// msg[1] padding
	binary.BigEndian.PutUint16(msg[2:4], numEncodings)
	binary.BigEndian.PutUint32(msg[4:8], 0) // Raw
	_, err := conn.Write(msg[:])
	return err
}

func framebufferUpdateRequest(conn io.ReadWriter, width, height uint16) error {
	var msg [10]byte
	msg[0] = 3 // FramebufferUpdateRequest
	msg[1] = 0 // incremental=0 (full update)
	// x=0, y=0
	binary.BigEndian.PutUint16(msg[6:8], width)
	binary.BigEndian.PutUint16(msg[8:10], height)
	_, err := conn.Write(msg[:])
	return err
}

// -----------------------------------------------------------------------------
// Inbound: drain side-messages, then assemble the framebuffer
// -----------------------------------------------------------------------------

// readFramebufferUpdate reads server messages until it sees a
// FramebufferUpdate (type 0), then assembles all of its Raw-encoded
// rectangles into a single RGBA image of size width×height.
//
// Other server messages (Bell, ServerCutText, SetColourMapEntries)
// are valid and may arrive before the first FramebufferUpdate; we
// drain them rather than treating them as errors.
func readFramebufferUpdate(conn io.Reader, width, height uint16) (*image.RGBA, error) {
	img := image.NewRGBA(image.Rect(0, 0, int(width), int(height)))

	for {
		var msgType [1]byte
		if _, err := io.ReadFull(conn, msgType[:]); err != nil {
			return nil, fmt.Errorf("read server message type: %w", err)
		}
		switch msgType[0] {
		case 0: // FramebufferUpdate
			return assembleFramebufferUpdate(conn, img)
		case 1: // SetColourMapEntries
			if err := skipSetColourMapEntries(conn); err != nil {
				return nil, err
			}
		case 2: // Bell — no payload
		case 3: // ServerCutText
			if err := skipServerCutText(conn); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("unexpected server message type %d", msgType[0])
		}
	}
}

func assembleFramebufferUpdate(conn io.Reader, img *image.RGBA) (*image.RGBA, error) {
	var hdr [3]byte // 1 padding + 2 num-rectangles
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return nil, fmt.Errorf("read fb update header: %w", err)
	}
	numRects := binary.BigEndian.Uint16(hdr[1:3])
	for i := uint16(0); i < numRects; i++ {
		var rect [12]byte
		if _, err := io.ReadFull(conn, rect[:]); err != nil {
			return nil, fmt.Errorf("read rect %d header: %w", i, err)
		}
		x := binary.BigEndian.Uint16(rect[0:2])
		y := binary.BigEndian.Uint16(rect[2:4])
		w := binary.BigEndian.Uint16(rect[4:6])
		h := binary.BigEndian.Uint16(rect[6:8])
		encoding := int32(binary.BigEndian.Uint32(rect[8:12]))
		if encoding != 0 {
			// We requested Raw-only; a server that ignores SetEncodings
			// or sends pseudo-encodings (Cursor=-239, DesktopSize=-223,
			// LastRect=-224) is misbehaving for our purposes.
			return nil, fmt.Errorf("rect %d uses unsupported encoding %d (Raw-only)", i, encoding)
		}
		if err := readRawRect(conn, img, int(x), int(y), int(w), int(h)); err != nil {
			return nil, fmt.Errorf("read rect %d pixels: %w", i, err)
		}
	}
	return img, nil
}

// readRawRect reads w*h pixels (4 bytes each in our chosen format)
// and copies them into img at offset (x,y). The wire format is
// [pad, R, G, B] per pixel; we rewrite as [R, G, B, 255] in RGBA.Pix.
func readRawRect(conn io.Reader, img *image.RGBA, x, y, w, h int) error {
	if w == 0 || h == 0 {
		return nil
	}
	bounds := img.Bounds()
	if x < 0 || y < 0 || x+w > bounds.Dx() || y+h > bounds.Dy() {
		return fmt.Errorf("rect (%d,%d %dx%d) escapes framebuffer %dx%d",
			x, y, w, h, bounds.Dx(), bounds.Dy())
	}

	row := make([]byte, w*4)
	for ry := 0; ry < h; ry++ {
		if _, err := io.ReadFull(conn, row); err != nil {
			return err
		}
		dst := img.Pix[(y+ry)*img.Stride+x*4:]
		for px := 0; px < w; px++ {
			// wire: [pad, R, G, B] → RGBA: [R, G, B, 255]
			dst[px*4+0] = row[px*4+1]
			dst[px*4+1] = row[px*4+2]
			dst[px*4+2] = row[px*4+3]
			dst[px*4+3] = 255
		}
	}
	return nil
}

func skipSetColourMapEntries(conn io.Reader) error {
	var hdr [5]byte // padding(1) + first-color(2) + num-colors(2)
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return fmt.Errorf("read SetColourMapEntries header: %w", err)
	}
	n := binary.BigEndian.Uint16(hdr[3:5])
	if _, err := io.CopyN(io.Discard, conn, int64(n)*6); err != nil {
		return fmt.Errorf("skip SetColourMapEntries body: %w", err)
	}
	return nil
}

func skipServerCutText(conn io.Reader) error {
	var hdr [7]byte // padding(3) + length(4)
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return fmt.Errorf("read ServerCutText header: %w", err)
	}
	n := binary.BigEndian.Uint32(hdr[3:7])
	if n > 1<<20 {
		// Same reasoning as init38: don't trust a hostile length.
		return errors.New("ServerCutText length implausibly large")
	}
	if _, err := io.CopyN(io.Discard, conn, int64(n)); err != nil {
		return fmt.Errorf("skip ServerCutText body: %w", err)
	}
	return nil
}

// readU32String reads a length-prefixed string used by the
// security-rejection and SecurityResult-failure paths.
func readU32String(conn io.Reader) (string, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return "", err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n == 0 {
		return "", nil
	}
	if n > 4096 {
		return "", errors.New("reason string implausibly large")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}
