//go:build integration

package scanner_test

import (
	"context"
	"os/exec"
	"testing"
	"time"

	"github.com/thenickstrick/go-natlas/internal/agent/scanner"
	"github.com/thenickstrick/go-natlas/internal/protocol"
)

// Runs a real nmap scan against 127.0.0.1 and asserts the result is shaped
// correctly. Gated behind -tags=integration because it requires nmap on PATH.
func TestScanLoopback(t *testing.T) {
	if _, err := exec.LookPath("nmap"); err != nil {
		t.Skip("nmap not available on PATH")
	}

	sc := scanner.New("", "", t.TempDir())
	work := &protocol.WorkItem{
		ScanID:     "integration-test",
		Target:     "127.0.0.1",
		ScanReason: protocol.ScanReasonManual,
		AgentConfig: protocol.AgentConfig{
			// Keep the scan cheap: no version detection, no OS detection, no
			// scripts. We just want "host is up, some port state".
			OnlyOpens:    true,
			ScanTimeoutS: 60,
			HostTimeoutS: 30,
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	r, err := sc.Scan(ctx, work)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if r.Target != "127.0.0.1" {
		t.Errorf("Target: got %q, want 127.0.0.1", r.Target)
	}
	if r.ScanStart.IsZero() || r.ScanStop.IsZero() {
		t.Errorf("timing not populated: %+v", r)
	}
	if len(r.XMLData) == 0 {
		t.Errorf("XMLData empty")
	}
	// Loopback may have 0 or more open ports depending on the host. The
	// invariant we really care about is "parse succeeded and shape is sane",
	// not a specific port count.
	t.Logf("loopback scan: up=%v, ports=%d, elapsed=%ds, ports_str=%q",
		r.IsUp, r.PortCount, r.ElapsedS, r.PortStr)
}
