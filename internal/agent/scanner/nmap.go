// Package scanner runs nmap as a subprocess and turns its XML output into a
// protocol.Result. Argument construction is a pure function (CommandArgs) so
// unit tests can cover it without invoking nmap.
package scanner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/thenickstrick/go-natlas/internal/protocol"
)

// Scanner is a reusable nmap runner. One Scanner is shared by every worker
// in the pool; Scan is safe for concurrent use (it writes to per-call temp
// directories).
type Scanner struct {
	NmapPath     string // full path to nmap; empty => "nmap" on PATH
	ServicesPath string // full path to custom services DB; empty => nmap default
	WorkDir      string // parent for per-scan temp dirs; empty => os.TempDir()
}

// New returns a Scanner with sensible defaults.
func New(nmapPath, servicesPath, workDir string) *Scanner {
	if nmapPath == "" {
		nmapPath = "nmap"
	}
	if workDir == "" {
		workDir = os.TempDir()
	}
	return &Scanner{NmapPath: nmapPath, ServicesPath: servicesPath, WorkDir: workDir}
}

// Scan runs nmap against work.Target using work.AgentConfig and returns a
// protocol.Result with the scan body populated. ctx governs the overall
// budget: cancelling it kills the nmap subprocess.
//
// On timeout the returned Result has TimedOut=true and whatever partial data
// nmap managed to flush before being killed.
func (s *Scanner) Scan(ctx context.Context, work *protocol.WorkItem) (*protocol.Result, error) {
	if work == nil {
		return nil, errors.New("scanner: nil work item")
	}
	if _, err := netip.ParseAddr(work.Target); err != nil {
		return nil, fmt.Errorf("scanner: invalid target %q: %w", work.Target, err)
	}

	dir, err := os.MkdirTemp(s.WorkDir, "natlas-scan-")
	if err != nil {
		return nil, fmt.Errorf("scanner: mkdir temp: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	outPrefix := filepath.Join(dir, "out")
	args := CommandArgs(&work.AgentConfig, s.ServicesPath, outPrefix, work.Target)

	// Overall timeout is the dispatcher-provided scanTimeout; hostTimeout is
	// already expressed in args. We add a small grace period so nmap can
	// flush its output files after --host-timeout fires.
	scanTimeout := time.Duration(work.AgentConfig.ScanTimeoutS) * time.Second
	if scanTimeout <= 0 {
		scanTimeout = 10 * time.Minute
	}
	scanCtx, cancel := context.WithTimeout(ctx, scanTimeout+10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(scanCtx, s.NmapPath, args...)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard

	startedAt := time.Now().UTC()
	runErr := cmd.Run()
	stoppedAt := time.Now().UTC()

	// Read output files regardless of exit status — nmap may have produced
	// partial artifacts before timing out. If the XML is empty we'll report a
	// synthesized "host down" result.
	xmlData, _ := os.ReadFile(outPrefix + ".xml")
	nmapData, _ := os.ReadFile(outPrefix + ".nmap")
	gnmapData, _ := os.ReadFile(outPrefix + ".gnmap")

	var result *protocol.Result
	if len(xmlData) > 0 {
		result, err = ParseXML(xmlData, work.Target)
		if err != nil {
			return nil, err
		}
	} else {
		result = &protocol.Result{
			Target:    work.Target,
			ScanStart: startedAt,
			ScanStop:  stoppedAt,
			ElapsedS:  int(stoppedAt.Sub(startedAt).Seconds()),
		}
	}

	// Backfill any fields the XML didn't populate (mostly relevant for timeout
	// or immediate-failure paths).
	if result.ScanStart.IsZero() {
		result.ScanStart = startedAt
	}
	if result.ScanStop.IsZero() {
		result.ScanStop = stoppedAt
	}
	if result.ElapsedS == 0 {
		result.ElapsedS = int(result.ScanStop.Sub(result.ScanStart).Seconds())
	}

	// Raw data blobs — the server keeps these for UI export.
	result.XMLData = string(xmlData)
	result.NmapData = string(nmapData)
	result.GNmapData = string(gnmapData)

	// Map the error outcome.
	if runErr != nil {
		if errors.Is(scanCtx.Err(), context.DeadlineExceeded) {
			result.TimedOut = true
			return result, nil
		}
		if ctx.Err() != nil {
			// Caller cancelled — propagate so the worker knows to stop.
			return result, ctx.Err()
		}
		// Non-zero exit without timeout. nmap exits non-zero for a few benign
		// reasons (host filtered, probe refused). We report the partial data
		// rather than failing hard; the server decides what to do with it.
		if _, ok := runErr.(*exec.ExitError); !ok {
			// Not a clean process exit — underlying OS error. Bubble up.
			return result, fmt.Errorf("nmap: run: %w", runErr)
		}
	}
	return result, nil
}

// CommandArgs returns the argv for an nmap invocation that matches the given
// AgentConfig against target. Exported so tests can assert shape without
// running nmap.
//
// Order matters for readability/diff-stability; this mirrors the table in
// deploy/docs for operator reference.
//
// --privileged is intentionally NOT here. Modern nmap auto-detects raw-socket
// capability: in the production container we grant cap_net_raw+eip on the
// nmap binary, which nmap sees via capability checks and uses raw sockets
// without --privileged. On a Mac dev host without sudo, omitting the flag
// avoids lying to nmap about privileges we don't have — callers who need
// --privileged should add it to a future Scanner.ExtraArgs field.
func CommandArgs(cfg *protocol.AgentConfig, servicesPath, outPrefix, target string) []string {
	args := []string{
		"-oA", outPrefix,
	}
	if servicesPath != "" {
		args = append(args, "--servicedb", servicesPath)
	}
	if cfg.VersionDetection {
		args = append(args, "-sV")
	}
	if cfg.OsDetection {
		args = append(args, "-O")
	}
	if cfg.OsScanLimit {
		args = append(args, "--osscan-limit")
	}
	if cfg.NoPing {
		args = append(args, "-Pn")
	}
	if cfg.OnlyOpens {
		args = append(args, "--open")
	}
	if cfg.UdpScan {
		args = append(args, "-sUS")
	}
	if cfg.EnableScripts && len(cfg.Scripts) > 0 {
		args = append(args, "--script="+strings.Join(cfg.Scripts, ","))
	}
	if cfg.ScriptTimeoutS > 0 {
		args = append(args, "--script-timeout="+strconv.Itoa(cfg.ScriptTimeoutS)+"s")
	}
	if cfg.HostTimeoutS > 0 {
		args = append(args, "--host-timeout="+strconv.Itoa(cfg.HostTimeoutS)+"s")
	}
	// IPv6 needs -6. The target parser has already validated this is a real IP,
	// so the ParseAddr here can't fail in normal use; we default to v4 on any
	// parse glitch.
	if addr, err := netip.ParseAddr(target); err == nil && addr.Is6() && !addr.Is4In6() {
		args = append(args, "-6")
	}
	args = append(args, target)
	return args
}
