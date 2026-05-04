package screenshots_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/thenickstrick/go-natlas/internal/agent/screenshots"
	"github.com/thenickstrick/go-natlas/internal/protocol"
)

// stubCapturer returns a deterministic body containing the target+port+service
// so tests can assert dispatch routing without standing up real transports.
type stubCapturer struct {
	tag string
}

func (s *stubCapturer) Capture(_ context.Context, target string, port int, service string) ([]byte, error) {
	if target == "" {
		return nil, errors.New("empty target")
	}
	return []byte(s.tag + ":" + target + ":" + service + ":" + intToStr(port)), nil
}

func intToStr(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

func TestOrchestratorDispatchesByService(t *testing.T) {
	web := &stubCapturer{tag: "web"}
	vnc := &stubCapturer{tag: "vnc"}
	o := &screenshots.Orchestrator{Web: web, VNC: vnc}

	ports := []protocol.Port{
		{Number: 80, Protocol: "tcp", State: "open", Service: protocol.Service{Name: "http"}},
		{Number: 443, Protocol: "tcp", State: "open", Service: protocol.Service{Name: "https"}},
		{Number: 8443, Protocol: "tcp", State: "open", Service: protocol.Service{Name: "http", Tunnel: "ssl"}},
		{Number: 5900, Protocol: "tcp", State: "open", Service: protocol.Service{Name: "vnc"}},
		{Number: 22, Protocol: "tcp", State: "open", Service: protocol.Service{Name: "ssh"}},   // skipped
		{Number: 80, Protocol: "tcp", State: "filtered", Service: protocol.Service{Name: "http"}}, // skipped (not open)
	}
	got := o.Capture(context.Background(), "10.0.0.1", ports)
	if len(got) != 4 {
		t.Fatalf("expected 4 captures, got %d: %+v", len(got), got)
	}

	byPort := map[int]screenshots.Captured{}
	for _, c := range got {
		byPort[c.Port] = c
	}
	if byPort[80].Service != screenshots.ServiceHTTP {
		t.Errorf("port 80 should be HTTP, got %q", byPort[80].Service)
	}
	if byPort[443].Service != screenshots.ServiceHTTPS {
		t.Errorf("port 443 should be HTTPS, got %q", byPort[443].Service)
	}
	if byPort[8443].Service != screenshots.ServiceHTTPS {
		t.Errorf("port 8443 (http+ssl tunnel) should be HTTPS, got %q", byPort[8443].Service)
	}
	if byPort[5900].Service != screenshots.ServiceVNC {
		t.Errorf("port 5900 should be VNC, got %q", byPort[5900].Service)
	}

	// Hash matches sha256 of returned body.
	want := sha256.Sum256(byPort[80].Data)
	if byPort[80].Hash != hex.EncodeToString(want[:]) {
		t.Errorf("hash mismatch for port 80: row=%s sha=%s", byPort[80].Hash, hex.EncodeToString(want[:]))
	}
}

func TestOrchestratorNilCapturerSkips(t *testing.T) {
	o := &screenshots.Orchestrator{Web: nil, VNC: nil}
	got := o.Capture(context.Background(), "10.0.0.1", []protocol.Port{
		{Number: 80, Protocol: "tcp", State: "open", Service: protocol.Service{Name: "http"}},
	})
	if len(got) != 0 {
		t.Fatalf("nil capturer should produce no captures; got %+v", got)
	}
}

func TestOrchestratorNilReceiverSafe(t *testing.T) {
	var o *screenshots.Orchestrator
	if got := o.Capture(context.Background(), "x", nil); got != nil {
		t.Fatalf("nil orchestrator should return nil, got %+v", got)
	}
}
