package worker_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/thenickstrick/go-natlas/internal/agent/submit"
	"github.com/thenickstrick/go-natlas/internal/agent/worker"
	"github.com/thenickstrick/go-natlas/internal/protocol"
	"github.com/thenickstrick/go-natlas/internal/server/data"
	"github.com/thenickstrick/go-natlas/internal/server/httpserver/api"
	"github.com/thenickstrick/go-natlas/internal/server/scope"
)

// stubScanner fabricates a deterministic Result without invoking nmap.
type stubScanner struct {
	calls atomic.Int64
}

func (s *stubScanner) Scan(_ context.Context, work *protocol.WorkItem) (*protocol.Result, error) {
	s.calls.Add(1)
	now := time.Now().UTC()
	return &protocol.Result{
		Target:    work.Target,
		IsUp:      true,
		PortCount: 1,
		PortStr:   "22",
		ScanStart: now,
		ScanStop:  now,
		Ports: []protocol.Port{{
			ID: "22/tcp", Number: 22, Protocol: "tcp", State: "open",
			Service: protocol.Service{Name: "ssh"},
		}},
	}, nil
}

// submitTap is an http.Handler middleware that forwards to next while
// side-channeling every POST /api/v1/results body onto a channel.
func submitTap(next http.Handler, tap chan<- string, mu *sync.Mutex, sink *[]string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/api/v1/results" {
			body, _ := io.ReadAll(r.Body)
			_ = r.Body.Close()
			var res protocol.Result
			if err := json.Unmarshal(body, &res); err == nil {
				mu.Lock()
				*sink = append(*sink, res.ScanID)
				mu.Unlock()
				select {
				case tap <- res.ScanID:
				default:
				}
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
		next.ServeHTTP(w, r)
	})
}

// TestPoolFullLoop exercises the full Phase 4 dispatch/scan/submit loop:
// real HTTP handlers backed by SQLite + ScopeManager + a stub scanner.
// No nmap, no OpenSearch, no S3 required.
func TestPoolFullLoop(t *testing.T) {
	// --- Server side ---------------------------------------------------------
	store, err := data.NewSQLiteStore(context.Background(), filepath.Join(t.TempDir(), "e2e.sqlite"))
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(store.Close)

	sm, _ := scope.NewScopeManager([]byte("e2e-seed"))
	if err := sm.Load([]scope.Entry{{CIDR: netip.MustParsePrefix("10.0.0.0/29")}}); err != nil {
		t.Fatalf("Scope.Load: %v", err)
	}

	h := &api.Handlers{Store: store, Scope: sm}
	r := chi.NewRouter()
	h.Mount(r)

	submitted := make(chan string, 16)
	var mu sync.Mutex
	var posted []string
	srv := httptest.NewServer(submitTap(r, submitted, &mu, &posted))
	t.Cleanup(srv.Close)

	// --- Agent side ----------------------------------------------------------
	client, err := submit.New(submit.Config{
		ServerURL:      srv.URL,
		RequestTimeout: 5 * time.Second,
		MaxRetries:     3,
		BackoffBase:    5 * time.Millisecond,
		BackoffCap:     20 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("submit.New: %v", err)
	}
	sc := &stubScanner{}

	pool := worker.New(worker.Config{
		MaxWorkers:     2,
		AgentVersion:   "test",
		AgentIDLogTag:  "unit",
		PollBackoff:    5 * time.Millisecond,
		PollBackoffMax: 20 * time.Millisecond,
	}, client, sc)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	poolDone := make(chan error, 1)
	go func() { poolDone <- pool.Run(ctx) }()

	const want = 3
	got := 0
	deadline := time.After(2 * time.Second)
loop:
	for got < want {
		select {
		case <-submitted:
			got++
		case <-deadline:
			break loop
		}
	}
	cancel()
	<-poolDone

	if got < want {
		t.Fatalf("expected >= %d submissions, got %d (scanner calls=%d)", want, got, sc.calls.Load())
	}
	mu.Lock()
	defer mu.Unlock()
	for _, id := range posted {
		if id == "" {
			t.Fatalf("empty scan_id in submission")
		}
	}
}
