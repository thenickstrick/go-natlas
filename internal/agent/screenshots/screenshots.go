// Package screenshots is the agent-side orchestrator that turns a finished
// scan into per-port image bytes ready for upload. The two transports
// (chromedp for HTTP/HTTPS, RFB for VNC) live in subpackages and are
// pluggable via the Capturer interface — tests substitute stubs without
// dragging in Chrome or a VNC server.
package screenshots

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"strings"

	"github.com/thenickstrick/go-natlas/internal/metrics"
	"github.com/thenickstrick/go-natlas/internal/protocol"
)

// Service tags the kind of screenshot we captured. They double as the
// X-Natlas-Service header value on the multipart upload so the server can
// preserve them in the indexed document.
const (
	ServiceHTTP  = "HTTP"
	ServiceHTTPS = "HTTPS"
	ServiceVNC   = "VNC"
)

// Captured is one raw screenshot ready to be uploaded. The agent computes
// the SHA-256 itself so the server can verify (and so the agent can attach
// the same hash to the Result.Screenshots metadata).
type Captured struct {
	Port    int
	Service string
	Data    []byte
	Hash    string
}

// Capturer is the per-transport interface. Implementations are expected to
// honor ctx cancellation (kill the headless browser tab, close the VNC
// connection, etc.) and return promptly on timeout.
type Capturer interface {
	Capture(ctx context.Context, target string, port int, service string) ([]byte, error)
}

// Orchestrator walks a scan result, classifies open ports as HTTP / HTTPS /
// VNC, and dispatches each to the appropriate Capturer. Either transport
// may be nil; nil capturers cause the matching ports to be silently skipped.
type Orchestrator struct {
	Web Capturer // handles HTTP + HTTPS
	VNC Capturer // handles VNC
}

// Capture iterates ports and returns the captured screenshots. Per-port
// failures are logged and skipped — one bad port shouldn't cost the whole
// host's worth of screenshots.
func (o *Orchestrator) Capture(ctx context.Context, target string, ports []protocol.Port) []Captured {
	if o == nil {
		return nil
	}
	out := make([]Captured, 0, len(ports))
	for _, p := range ports {
		if p.State != "open" {
			continue
		}
		service, capturer := o.dispatch(p)
		if capturer == nil {
			continue
		}
		data, err := capturer.Capture(ctx, target, p.Number, service)
		if err != nil {
			slog.WarnContext(ctx, "screenshot failed",
				"target", target, "port", p.Number, "service", service, "err", err)
			continue
		}
		if len(data) == 0 {
			continue
		}
		sum := sha256.Sum256(data)
		out = append(out, Captured{
			Port:    p.Number,
			Service: service,
			Data:    data,
			Hash:    hex.EncodeToString(sum[:]),
		})
		metrics.ScreenshotCaptured(ctx, service)
	}
	return out
}

// dispatch picks the right capturer for a port. The classification rules
// mirror the Python natlas behavior:
//
//   - service.tunnel == "ssl" → HTTPS via web capturer
//   - service name matches an http-like service → HTTP/HTTPS via web capturer
//   - service name == "vnc" or port in 5900..5910 → VNC via vnc capturer
//
// Anything else → no screenshot.
func (o *Orchestrator) dispatch(p protocol.Port) (string, Capturer) {
	name := strings.ToLower(p.Service.Name)
	tunnel := strings.ToLower(p.Service.Tunnel)

	switch {
	case isVNC(p):
		return ServiceVNC, o.VNC
	case tunnel == "ssl" && isHTTPLike(name):
		return ServiceHTTPS, o.Web
	case name == "https" || name == "ssl/http" || name == "https-alt":
		return ServiceHTTPS, o.Web
	case isHTTPLike(name):
		return ServiceHTTP, o.Web
	}
	return "", nil
}

func isHTTPLike(name string) bool {
	switch name {
	case "http", "http-alt", "http-proxy", "http-mgmt", "websocket", "ws", "wss":
		return true
	}
	return false
}

func isVNC(p protocol.Port) bool {
	if strings.ToLower(p.Service.Name) == "vnc" {
		return true
	}
	if p.Protocol == "tcp" && p.Number >= 5900 && p.Number <= 5910 {
		return true
	}
	return false
}
