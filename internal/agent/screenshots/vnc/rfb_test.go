package vnc

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"image/png"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// serverScript drives one accepted connection. Helpers below produce
// scripts for the common cases; tests can also build bespoke scripts
// when they need to assert on what the client sent.
type serverScript func(t *testing.T, conn net.Conn)

func runServer(t *testing.T, script serverScript) (addr string, cleanup func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		script(t, conn)
	}()
	return ln.Addr().String(), func() {
		_ = ln.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	}
}

// happyPathScript runs a clean RFB 3.8 handshake and serves a
// width×height framebuffer where every pixel is solid (r,g,b).
//
// It also records the bytes the client sent in `recvd` so tests can
// assert the negotiated pixel format and update request shape.
func happyPathScript(width, height uint16, r, g, b byte, recvd *bytes.Buffer, mu *sync.Mutex) serverScript {
	return func(t *testing.T, conn net.Conn) {
		t.Helper()
		write := func(p []byte) {
			if _, err := conn.Write(p); err != nil {
				t.Errorf("server write: %v", err)
			}
		}
		read := func(n int) []byte {
			buf := make([]byte, n)
			if _, err := io.ReadFull(conn, buf); err != nil {
				t.Errorf("server read %d: %v", n, err)
				return nil
			}
			mu.Lock()
			recvd.Write(buf)
			mu.Unlock()
			return buf
		}

		write([]byte("RFB 003.008\n"))
		read(12) // client protocol version

		write([]byte{1, 1}) // 1 security type, None
		read(1)             // client picks
		write([]byte{0, 0, 0, 0}) // SecurityResult OK

		read(1) // ClientInit

		// ServerInit: width, height, pixel format (16 bytes — anything,
		// we ignore), name length, name.
		var srvInit [24]byte
		binary.BigEndian.PutUint16(srvInit[0:2], width)
		binary.BigEndian.PutUint16(srvInit[2:4], height)
		// PixelFormat bytes 4..20 — leave zeros, we replace via SetPixelFormat.
		binary.BigEndian.PutUint32(srvInit[20:24], 4)
		write(srvInit[:])
		write([]byte("test"))

		read(20) // SetPixelFormat
		read(8)  // SetEncodings (header + 1 encoding)
		read(10) // FramebufferUpdateRequest

		// FramebufferUpdate response:
		//   type=0, padding=0, num-rects=1, rect=[x,y,w,h,encoding=Raw], pixels
		var hdr [4]byte
		hdr[0] = 0 // msg type
		binary.BigEndian.PutUint16(hdr[2:4], 1) // num rects
		write(hdr[:])
		var rect [12]byte
		binary.BigEndian.PutUint16(rect[4:6], width)
		binary.BigEndian.PutUint16(rect[6:8], height)
		// encoding=0 (Raw) already zero
		write(rect[:])

		// pixels: wire format [pad, R, G, B]
		row := make([]byte, int(width)*4)
		for i := 0; i < int(width); i++ {
			row[i*4+1] = r
			row[i*4+2] = g
			row[i*4+3] = b
		}
		for i := 0; i < int(height); i++ {
			write(row)
		}
	}
}

func TestCapture_HappyPath(t *testing.T) {
	var recvd bytes.Buffer
	var mu sync.Mutex

	addr, cleanup := runServer(t, happyPathScript(8, 6, 0x12, 0x34, 0x56, &recvd, &mu))
	defer cleanup()

	host, portStr, _ := net.SplitHostPort(addr)
	port := 0
	if _, err := parsePort(portStr, &port); err != nil {
		t.Fatalf("parse port: %v", err)
	}

	c := New(Options{CaptureTimeout: 3 * time.Second})
	pngBytes, err := c.Capture(context.Background(), host, port, "VNC")
	if err != nil {
		t.Fatalf("capture: %v", err)
	}

	img, err := png.Decode(bytes.NewReader(pngBytes))
	if err != nil {
		t.Fatalf("decode png: %v", err)
	}
	if img.Bounds().Dx() != 8 || img.Bounds().Dy() != 6 {
		t.Fatalf("bounds: want 8x6, got %dx%d", img.Bounds().Dx(), img.Bounds().Dy())
	}
	r, g, b, _ := img.At(4, 3).RGBA()
	// image/color returns 16-bit channels; downshift to 8-bit.
	if byte(r>>8) != 0x12 || byte(g>>8) != 0x34 || byte(b>>8) != 0x56 {
		t.Errorf("center pixel: want 12/34/56, got %02x/%02x/%02x",
			byte(r>>8), byte(g>>8), byte(b>>8))
	}

	// Verify the client sent the expected SetPixelFormat: client → server
	// sequence is [protocolVer(12) | securityChoice(1) | clientInit(1) |
	// setPixelFormat(20) | setEncodings(8) | fbUpdateReq(10)].
	mu.Lock()
	defer mu.Unlock()
	got := recvd.Bytes()
	if len(got) < 12+1+1+20+8+10 {
		t.Fatalf("client sent only %d bytes; expected at least %d", len(got), 12+1+1+20+8+10)
	}
	setPF := got[14:34]
	if setPF[0] != 0 {
		t.Errorf("SetPixelFormat msg type: want 0, got %d", setPF[0])
	}
	pf := setPF[4:20]
	if pf[0] != 32 || pf[1] != 24 || pf[2] != 1 || pf[3] != 1 {
		t.Errorf("pixel format prefix: want [32 24 1 1], got %v", pf[:4])
	}
	// shifts: R=16, G=8, B=0 at bytes 10..12 of the pixel format.
	if pf[10] != 16 || pf[11] != 8 || pf[12] != 0 {
		t.Errorf("pixel format shifts: want R=16 G=8 B=0, got R=%d G=%d B=%d",
			pf[10], pf[11], pf[12])
	}
	fbReq := got[42:52]
	if fbReq[0] != 3 || fbReq[1] != 0 {
		t.Errorf("FramebufferUpdateRequest: want msg=3 incremental=0, got msg=%d inc=%d",
			fbReq[0], fbReq[1])
	}
	if binary.BigEndian.Uint16(fbReq[6:8]) != 8 ||
		binary.BigEndian.Uint16(fbReq[8:10]) != 6 {
		t.Errorf("FramebufferUpdateRequest w/h: want 8x6, got %dx%d",
			binary.BigEndian.Uint16(fbReq[6:8]),
			binary.BigEndian.Uint16(fbReq[8:10]))
	}
}

func TestCapture_RejectsAuthRequired(t *testing.T) {
	addr, cleanup := runServer(t, func(t *testing.T, conn net.Conn) {
		_, _ = conn.Write([]byte("RFB 003.008\n"))
		_, _ = io.ReadFull(conn, make([]byte, 12))
		// Offer only VNCAuth (type 2) — we should refuse.
		_, _ = conn.Write([]byte{1, 2})
	})
	defer cleanup()

	host, portStr, _ := net.SplitHostPort(addr)
	port := 0
	_, _ = parsePort(portStr, &port)

	c := New(Options{CaptureTimeout: 2 * time.Second})
	_, err := c.Capture(context.Background(), host, port, "VNC")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "None") {
		t.Errorf("expected 'None' in error, got: %v", err)
	}
}

func TestCapture_ServerRefusesConnection(t *testing.T) {
	addr, cleanup := runServer(t, func(t *testing.T, conn net.Conn) {
		_, _ = conn.Write([]byte("RFB 003.008\n"))
		_, _ = io.ReadFull(conn, make([]byte, 12))
		// security count = 0, then u32-prefixed reason
		_, _ = conn.Write([]byte{0})
		reason := []byte("too many connections")
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(reason)))
		_, _ = conn.Write(lenBuf[:])
		_, _ = conn.Write(reason)
	})
	defer cleanup()

	host, portStr, _ := net.SplitHostPort(addr)
	port := 0
	_, _ = parsePort(portStr, &port)

	c := New(Options{CaptureTimeout: 2 * time.Second})
	_, err := c.Capture(context.Background(), host, port, "VNC")
	if err == nil || !strings.Contains(err.Error(), "too many connections") {
		t.Fatalf("expected reason to surface, got: %v", err)
	}
}

func TestCapture_RejectsOversizeFramebuffer(t *testing.T) {
	addr, cleanup := runServer(t, func(t *testing.T, conn net.Conn) {
		_, _ = conn.Write([]byte("RFB 003.008\n"))
		_, _ = io.ReadFull(conn, make([]byte, 12))
		_, _ = conn.Write([]byte{1, 1})
		_, _ = io.ReadFull(conn, make([]byte, 1))
		_, _ = conn.Write([]byte{0, 0, 0, 0})
		_, _ = io.ReadFull(conn, make([]byte, 1)) // ClientInit
		// ServerInit claiming 16384x16384 — over our cap.
		var srvInit [24]byte
		binary.BigEndian.PutUint16(srvInit[0:2], 16384)
		binary.BigEndian.PutUint16(srvInit[2:4], 16384)
		binary.BigEndian.PutUint32(srvInit[20:24], 0) // no name
		_, _ = conn.Write(srvInit[:])
	})
	defer cleanup()

	host, portStr, _ := net.SplitHostPort(addr)
	port := 0
	_, _ = parsePort(portStr, &port)

	c := New(Options{CaptureTimeout: 2 * time.Second})
	_, err := c.Capture(context.Background(), host, port, "VNC")
	if err == nil || !strings.Contains(err.Error(), "cap") {
		t.Fatalf("expected pixel-cap error, got: %v", err)
	}
}

func TestCapture_DrainsBellBeforeFBU(t *testing.T) {
	var recvd bytes.Buffer
	var mu sync.Mutex
	addr, cleanup := runServer(t, func(t *testing.T, conn net.Conn) {
		t.Helper()
		_, _ = conn.Write([]byte("RFB 003.008\n"))
		_, _ = io.ReadFull(conn, make([]byte, 12))
		_, _ = conn.Write([]byte{1, 1})
		_, _ = io.ReadFull(conn, make([]byte, 1))
		_, _ = conn.Write([]byte{0, 0, 0, 0})
		_, _ = io.ReadFull(conn, make([]byte, 1))
		var srvInit [24]byte
		binary.BigEndian.PutUint16(srvInit[0:2], 2)
		binary.BigEndian.PutUint16(srvInit[2:4], 1)
		_, _ = conn.Write(srvInit[:])
		_, _ = io.ReadFull(conn, make([]byte, 20)) // SetPixelFormat
		_, _ = io.ReadFull(conn, make([]byte, 8))  // SetEncodings
		_, _ = io.ReadFull(conn, make([]byte, 10)) // FramebufferUpdateRequest

		// Send Bell (msg type 2, no payload) and ServerCutText (type 3,
		// 3 padding + length + bytes) before the framebuffer update.
		_, _ = conn.Write([]byte{2})
		_, _ = conn.Write([]byte{3, 0, 0, 0, 0, 0, 0, 3, 'h', 'i', '!'})

		// Now a real FramebufferUpdate for a 2x1 image, blue pixel + red pixel.
		_, _ = conn.Write([]byte{0, 0, 0, 1})       // type, pad, 1 rect
		_, _ = conn.Write([]byte{0, 0, 0, 0, 0, 2, 0, 1, 0, 0, 0, 0}) // rect 0,0 2x1 raw
		_, _ = conn.Write([]byte{0, 0, 0, 0xff})    // pad, R=0, G=0, B=0xff (blue)
		_, _ = conn.Write([]byte{0, 0xff, 0, 0})    // pad, R=0xff, G=0, B=0    (red)

		mu.Lock()
		recvd.WriteString("done")
		mu.Unlock()
	})
	defer cleanup()

	host, portStr, _ := net.SplitHostPort(addr)
	port := 0
	_, _ = parsePort(portStr, &port)

	c := New(Options{CaptureTimeout: 3 * time.Second})
	pngBytes, err := c.Capture(context.Background(), host, port, "VNC")
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	img, err := png.Decode(bytes.NewReader(pngBytes))
	if err != nil {
		t.Fatalf("decode png: %v", err)
	}
	if img.Bounds().Dx() != 2 || img.Bounds().Dy() != 1 {
		t.Fatalf("bounds: want 2x1, got %dx%d", img.Bounds().Dx(), img.Bounds().Dy())
	}
	r0, g0, b0, _ := img.At(0, 0).RGBA()
	r1, g1, b1, _ := img.At(1, 0).RGBA()
	if byte(r0>>8) != 0 || byte(g0>>8) != 0 || byte(b0>>8) != 0xff {
		t.Errorf("pixel 0: want 0/0/ff, got %02x/%02x/%02x", byte(r0>>8), byte(g0>>8), byte(b0>>8))
	}
	if byte(r1>>8) != 0xff || byte(g1>>8) != 0 || byte(b1>>8) != 0 {
		t.Errorf("pixel 1: want ff/0/0, got %02x/%02x/%02x", byte(r1>>8), byte(g1>>8), byte(b1>>8))
	}
}

func TestCapture_RejectsNonRawEncoding(t *testing.T) {
	addr, cleanup := runServer(t, func(t *testing.T, conn net.Conn) {
		_, _ = conn.Write([]byte("RFB 003.008\n"))
		_, _ = io.ReadFull(conn, make([]byte, 12))
		_, _ = conn.Write([]byte{1, 1})
		_, _ = io.ReadFull(conn, make([]byte, 1))
		_, _ = conn.Write([]byte{0, 0, 0, 0})
		_, _ = io.ReadFull(conn, make([]byte, 1))
		var srvInit [24]byte
		binary.BigEndian.PutUint16(srvInit[0:2], 4)
		binary.BigEndian.PutUint16(srvInit[2:4], 4)
		_, _ = conn.Write(srvInit[:])
		_, _ = io.ReadFull(conn, make([]byte, 20))
		_, _ = io.ReadFull(conn, make([]byte, 8))
		_, _ = io.ReadFull(conn, make([]byte, 10))

		// FramebufferUpdate with one rectangle in Tight (encoding 7) — refuse.
		_, _ = conn.Write([]byte{0, 0, 0, 1})
		var rect [12]byte
		binary.BigEndian.PutUint16(rect[4:6], 4)
		binary.BigEndian.PutUint16(rect[6:8], 4)
		binary.BigEndian.PutUint32(rect[8:12], 7) // Tight
		_, _ = conn.Write(rect[:])
	})
	defer cleanup()

	host, portStr, _ := net.SplitHostPort(addr)
	port := 0
	_, _ = parsePort(portStr, &port)

	c := New(Options{CaptureTimeout: 2 * time.Second})
	_, err := c.Capture(context.Background(), host, port, "VNC")
	if err == nil || !strings.Contains(err.Error(), "encoding 7") {
		t.Fatalf("expected encoding-rejection error, got: %v", err)
	}
}

func TestCapture_RejectsBadGreeting(t *testing.T) {
	addr, cleanup := runServer(t, func(t *testing.T, conn net.Conn) {
		_, _ = conn.Write([]byte("NOT_A_VNC_!\n"))
	})
	defer cleanup()

	host, portStr, _ := net.SplitHostPort(addr)
	port := 0
	_, _ = parsePort(portStr, &port)

	c := New(Options{CaptureTimeout: 2 * time.Second})
	_, err := c.Capture(context.Background(), host, port, "VNC")
	if err == nil || !strings.Contains(err.Error(), "unexpected server greeting") {
		t.Fatalf("expected greeting error, got: %v", err)
	}
}

func TestCapture_ContextCancel(t *testing.T) {
	// Server accepts and then blocks indefinitely — client should
	// give up when the context is cancelled.
	addr, cleanup := runServer(t, func(t *testing.T, conn net.Conn) {
		_, _ = conn.Write([]byte("RFB 003.008\n"))
		<-time.After(5 * time.Second)
	})
	defer cleanup()

	host, portStr, _ := net.SplitHostPort(addr)
	port := 0
	_, _ = parsePort(portStr, &port)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	c := New(Options{CaptureTimeout: 5 * time.Second})
	start := time.Now()
	_, err := c.Capture(ctx, host, port, "VNC")
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected cancellation error, got nil")
	}
	if elapsed > 2*time.Second {
		t.Errorf("cancellation took %s; expected fast unblock", elapsed)
	}
}

func TestCapture_RejectsUnsupportedService(t *testing.T) {
	c := New(Options{CaptureTimeout: time.Second})
	_, err := c.Capture(context.Background(), "127.0.0.1", 1, "HTTP")
	if err == nil || !strings.Contains(err.Error(), "unsupported service") {
		t.Fatalf("expected unsupported-service error, got: %v", err)
	}
}

// parsePort is a tiny helper that avoids importing strconv just for tests
// to keep the test file's import list short.
func parsePort(s string, out *int) (int, error) {
	n := 0
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return 0, errors.New("non-digit in port")
		}
		n = n*10 + int(ch-'0')
	}
	*out = n
	return n, nil
}
