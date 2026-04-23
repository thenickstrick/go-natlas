// Package api implements the agent-facing HTTP handlers under /api/v1. The
// three endpoints are:
//
//	GET  /api/v1/work       -- next target to scan
//	POST /api/v1/results    -- submit scan outcome
//	GET  /api/v1/services   -- custom nmap services DB + sha256
//
// Screenshots are a separate multipart endpoint handled in Phase 8.
package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"

	"github.com/thenickstrick/go-natlas/internal/protocol"
	"github.com/thenickstrick/go-natlas/internal/server/data"
	"github.com/thenickstrick/go-natlas/internal/server/scope"
)

// Handlers holds dependencies for the /api/v1 routes. It is intentionally
// small: most heavy lifting lives in the Store and ScopeManager.
type Handlers struct {
	Store   data.Store
	Scope   *scope.ScopeManager
	Version string // server version echoed into logs, not to clients
}

// Mount attaches all /api/v1/* routes to the given mux (chi.Router, really,
// but only http.Handler-level operations are used so we don't pin chi here).
type mux interface {
	Get(pattern string, h http.HandlerFunc)
	Post(pattern string, h http.HandlerFunc)
}

func (h *Handlers) Mount(r mux) {
	r.Get("/api/v1/work", h.GetWork)
	r.Post("/api/v1/results", h.PostResults)
	r.Get("/api/v1/services", h.GetServices)
}

// -----------------------------------------------------------------------------
// GET /api/v1/work
// -----------------------------------------------------------------------------

// GetWork implements the dispatcher:
//
//  1. If ?target=IP is present and acceptable, return that as a manual scan.
//  2. Otherwise, prefer a pending rescan_task (dispatch + return).
//  3. Otherwise, pull the next address from the ScopeManager (auto).
//
// The payload includes the current AgentConfig and services hash so agents
// can detect config drift and re-fetch services when needed.
func (h *Handlers) GetWork(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var (
		target     netip.Addr
		scanReason string
		rescanID   int64
	)

	if manual := r.URL.Query().Get("target"); manual != "" {
		addr, err := netip.ParseAddr(manual)
		if err != nil {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("invalid target %q: %v", manual, err), false)
			return
		}
		if !h.Scope.IsAcceptable(addr) {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("target out of scope: %s", addr), false)
			return
		}
		target = addr
		scanReason = protocol.ScanReasonManual
	} else {
		rescan, err := h.Store.RescanTaskNextPending(ctx)
		switch {
		case err == nil:
			target = rescan.Target
			scanReason = protocol.ScanReasonRequested
			rescanID = rescan.ID
		case errors.Is(err, data.ErrNotFound):
			addr, err := h.Scope.NextAddr(ctx)
			if err != nil {
				if errors.Is(err, scope.ErrNoScope) {
					writeErr(w, http.StatusNotFound, "no scope configured", true)
					return
				}
				writeErr(w, http.StatusInternalServerError, err.Error(), true)
				return
			}
			target = addr
			scanReason = protocol.ScanReasonAutomatic
		default:
			writeErr(w, http.StatusInternalServerError, fmt.Sprintf("rescan queue: %v", err), true)
			return
		}
	}

	cfg, err := h.Store.AgentConfigGet(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("agent_config: %v", err), true)
		return
	}
	services, err := h.Store.NatlasServicesGet(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("natlas_services: %v", err), true)
		return
	}

	scanID, err := newScanID()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("scan_id: %v", err), true)
		return
	}

	// Dispatch the rescan only after all pre-checks succeed; otherwise a
	// failed config lookup would leave the row marked dispatched with no work
	// actually on the wire.
	if rescanID != 0 {
		if err := h.Store.RescanTaskDispatch(ctx, rescanID); err != nil {
			writeErr(w, http.StatusInternalServerError, fmt.Sprintf("rescan dispatch: %v", err), true)
			return
		}
	}

	item := protocol.WorkItem{
		ScanID:       scanID,
		ScanReason:   scanReason,
		Target:       target.String(),
		Tags:         []string{}, // Phase 7 wires scope_item_tags lookup
		Type:         "nmap",
		AgentConfig:  configToWire(cfg),
		ServicesHash: services.SHA256,
	}
	writeJSON(w, http.StatusOK, item)
}

// -----------------------------------------------------------------------------
// POST /api/v1/results
// -----------------------------------------------------------------------------

// PostResults accepts a Result, re-validates the target against current
// scope, and closes out any matching rescan_task. Actual OpenSearch indexing
// lands in Phase 5; for Phase 4 we just acknowledge + optionally log.
func (h *Handlers) PostResults(w http.ResponseWriter, r *http.Request) {
	const maxBody = 32 << 20 // 32 MiB — plenty for JSON sans screenshots
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("read body: %v", err), false)
		return
	}
	if len(body) > maxBody {
		writeErr(w, http.StatusRequestEntityTooLarge, "body exceeds 32 MiB limit", false)
		return
	}
	var result protocol.Result
	if err := json.Unmarshal(body, &result); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("parse body: %v", err), false)
		return
	}
	if result.ScanID == "" || result.Target == "" {
		writeErr(w, http.StatusBadRequest, "scan_id and target are required", false)
		return
	}
	addr, err := netip.ParseAddr(result.Target)
	if err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("invalid target %q: %v", result.Target, err), false)
		return
	}
	// Defense-in-depth: re-validate scope on submit. A rogue or stale agent
	// could otherwise post results for addresses we never dispatched.
	if !h.Scope.IsAcceptable(addr) {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("target out of scope: %s", addr), false)
		return
	}

	// Complete the matching rescan_task if any. We look up by scan_id via the
	// store's existing indexes — for Phase 4 we just best-effort-complete.
	// The precise mapping (scan_id -> rescan_task.id) lives in the
	// rescan_task row after dispatch in Phase 6; here we noop.
	//
	// TODO(phase-5): index result into OpenSearch (latest + history).
	// TODO(phase-6): mark matching rescan_task complete + write scan_id back.

	writeJSON(w, http.StatusOK, map[string]any{
		"status":     "accepted",
		"scan_id":    result.ScanID,
		"port_count": result.PortCount,
	})
}

// -----------------------------------------------------------------------------
// GET /api/v1/services
// -----------------------------------------------------------------------------

func (h *Handlers) GetServices(w http.ResponseWriter, r *http.Request) {
	s, err := h.Store.NatlasServicesGet(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("natlas_services: %v", err), true)
		return
	}
	writeJSON(w, http.StatusOK, protocol.Services{SHA256: s.SHA256, Services: s.Services})
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

func configToWire(c data.AgentConfig) protocol.AgentConfig {
	scripts := c.Scripts
	if scripts == nil {
		scripts = []string{}
	}
	return protocol.AgentConfig{
		VersionDetection:      c.VersionDetection,
		OsDetection:           c.OsDetection,
		EnableScripts:         c.EnableScripts,
		OnlyOpens:             c.OnlyOpens,
		ScanTimeoutS:          int(c.ScanTimeoutS),
		WebScreenshots:        c.WebScreenshots,
		VncScreenshots:        c.VncScreenshots,
		WebScreenshotTimeoutS: int(c.WebScreenshotTimeoutS),
		VncScreenshotTimeoutS: int(c.VncScreenshotTimeoutS),
		ScriptTimeoutS:        int(c.ScriptTimeoutS),
		HostTimeoutS:          int(c.HostTimeoutS),
		OsScanLimit:           c.OsScanLimit,
		NoPing:                c.NoPing,
		UdpScan:               c.UdpScan,
		Scripts:               scripts,
	}
}

// newScanID returns a 16-byte random hex string. Not a UUID — a raw 128-bit
// random token is simpler and collision-safe for this scale.
func newScanID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string, retry bool) {
	writeJSON(w, code, protocol.ErrorResponse{Error: msg, Retry: retry})
}
