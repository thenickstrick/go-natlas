package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/thenickstrick/go-natlas/internal/protocol"
	"github.com/thenickstrick/go-natlas/internal/server/data"
	"github.com/thenickstrick/go-natlas/internal/server/httpserver/api"
	"github.com/thenickstrick/go-natlas/internal/server/scope"
)

// newTestServer builds a minimal Handlers over a SQLite store and ScopeManager
// preloaded with the given entries.
func newTestServer(t *testing.T, scopeEntries []scope.Entry) (*httptest.Server, data.Store) {
	t.Helper()
	store, err := data.NewSQLiteStore(context.Background(), filepath.Join(t.TempDir(), "test.sqlite"))
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(store.Close)

	sm, err := scope.NewScopeManager([]byte("test-seed-deterministic"))
	if err != nil {
		t.Fatalf("NewScopeManager: %v", err)
	}
	if err := sm.Load(scopeEntries); err != nil {
		t.Fatalf("Load: %v", err)
	}

	h := &api.Handlers{Store: store, Scope: sm}
	r := chi.NewRouter()
	h.Mount(r)

	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)
	return ts, store
}

func TestGetWorkNoScope(t *testing.T) {
	ts, _ := newTestServer(t, nil)
	resp, err := http.Get(ts.URL + "/api/v1/work")
	if err != nil {
		t.Fatalf("GET /api/v1/work: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status: got %d, want 404", resp.StatusCode)
	}
	var env protocol.ErrorResponse
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !env.Retry {
		t.Fatalf("no-scope error should be retryable")
	}
}

func TestGetWorkAutoReturnsInScopeAddress(t *testing.T) {
	entries := []scope.Entry{{CIDR: netip.MustParsePrefix("10.0.0.0/30")}}
	ts, _ := newTestServer(t, entries)

	resp, err := http.Get(ts.URL + "/api/v1/work")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d", resp.StatusCode)
	}
	var work protocol.WorkItem
	if err := json.NewDecoder(resp.Body).Decode(&work); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if work.ScanID == "" || len(work.ScanID) != 32 {
		t.Errorf("ScanID should be 32-char hex; got %q", work.ScanID)
	}
	if work.ScanReason != protocol.ScanReasonAutomatic {
		t.Errorf("ScanReason: got %q, want automatic", work.ScanReason)
	}
	addr, err := netip.ParseAddr(work.Target)
	if err != nil {
		t.Fatalf("Target invalid: %v", err)
	}
	if !netip.MustParsePrefix("10.0.0.0/30").Contains(addr) {
		t.Errorf("Target %v not in scope", addr)
	}
	// AgentConfig seeded defaults present.
	if work.AgentConfig.ScanTimeoutS == 0 {
		t.Errorf("AgentConfig defaults missing: %+v", work.AgentConfig)
	}
	if work.Type != "nmap" {
		t.Errorf("Type: got %q, want nmap", work.Type)
	}
}

func TestGetWorkManualTargetInScope(t *testing.T) {
	entries := []scope.Entry{{CIDR: netip.MustParsePrefix("10.0.0.0/30")}}
	ts, _ := newTestServer(t, entries)

	resp, err := http.Get(ts.URL + "/api/v1/work?target=10.0.0.1")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d", resp.StatusCode)
	}
	var work protocol.WorkItem
	_ = json.NewDecoder(resp.Body).Decode(&work)
	if work.Target != "10.0.0.1" || work.ScanReason != protocol.ScanReasonManual {
		t.Errorf("unexpected: %+v", work)
	}
}

func TestGetWorkManualTargetOutOfScope(t *testing.T) {
	entries := []scope.Entry{{CIDR: netip.MustParsePrefix("10.0.0.0/30")}}
	ts, _ := newTestServer(t, entries)

	resp, err := http.Get(ts.URL + "/api/v1/work?target=192.168.1.1")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", resp.StatusCode)
	}
}

func TestGetWorkRescanTakesPriority(t *testing.T) {
	entries := []scope.Entry{{CIDR: netip.MustParsePrefix("10.0.0.0/30")}}
	ts, store := newTestServer(t, entries)

	user, err := store.UserCreate(context.Background(), data.UserCreateParams{
		Email: "u@example.com", PasswordHash: "x", IsActive: true,
	})
	if err != nil {
		t.Fatalf("UserCreate: %v", err)
	}
	rescanTarget := netip.MustParseAddr("10.0.0.2")
	if _, err := store.RescanTaskCreate(context.Background(), user.ID, rescanTarget); err != nil {
		t.Fatalf("RescanTaskCreate: %v", err)
	}

	resp, err := http.Get(ts.URL + "/api/v1/work")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	var work protocol.WorkItem
	_ = json.NewDecoder(resp.Body).Decode(&work)
	if work.ScanReason != protocol.ScanReasonRequested {
		t.Errorf("ScanReason: got %q, want requested", work.ScanReason)
	}
	if work.Target != "10.0.0.2" {
		t.Errorf("Target: got %q, want 10.0.0.2", work.Target)
	}

	// Rescan row should now be marked dispatched.
	task, err := store.RescanTaskNextPending(context.Background())
	if err == nil {
		t.Errorf("RescanTaskNextPending should return ErrNotFound after dispatch; got %+v", task)
	}
}

func TestPostResultsValidatesScope(t *testing.T) {
	entries := []scope.Entry{{CIDR: netip.MustParsePrefix("10.0.0.0/30")}}
	ts, _ := newTestServer(t, entries)

	badResult := &protocol.Result{ScanID: "abc", Target: "192.168.1.1", IsUp: true}
	body, _ := json.Marshal(badResult)
	resp, err := http.Post(ts.URL+"/api/v1/results", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400 (out of scope)", resp.StatusCode)
	}
}

func TestPostResultsHappyPath(t *testing.T) {
	entries := []scope.Entry{{CIDR: netip.MustParsePrefix("10.0.0.0/30")}}
	ts, _ := newTestServer(t, entries)

	good := &protocol.Result{ScanID: "abc123", Target: "10.0.0.1", IsUp: true, PortCount: 2}
	body, _ := json.Marshal(good)
	resp, err := http.Post(ts.URL+"/api/v1/results", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want 200", resp.StatusCode)
	}
}

func TestGetServicesReturnsSeed(t *testing.T) {
	ts, _ := newTestServer(t, nil)
	resp, err := http.Get(ts.URL + "/api/v1/services")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d", resp.StatusCode)
	}
	var s protocol.Services
	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Seeded empty on migration.
	if s.Services != "" || s.SHA256 != "" {
		t.Errorf("expected seeded empty, got %+v", s)
	}
}
