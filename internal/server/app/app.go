// Package app is the natlas-server bootstrap: it resolves configuration into
// live clients (Store over Postgres/SQLite, OpenSearch, object store), verifies
// each with a startup liveness check, runs database migrations, wires them
// into the HTTP server, and exposes a single Run method that blocks until the
// caller's context is cancelled.
//
// Any failure during New aborts startup with a readable error; the process
// exits non-zero. No background retries — if a dependency is down at boot,
// the supervisor should restart us.
package app

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/opensearch-project/opensearch-go/v4"

	"github.com/thenickstrick/go-natlas/internal/config"
	"github.com/thenickstrick/go-natlas/internal/server/data"
	"github.com/thenickstrick/go-natlas/internal/server/httpserver"
	"github.com/thenickstrick/go-natlas/internal/server/scope"
	"github.com/thenickstrick/go-natlas/internal/server/search"
	"github.com/thenickstrick/go-natlas/internal/server/sessions"
	"github.com/thenickstrick/go-natlas/internal/server/views"
)

// App owns every long-lived resource the server holds open.
type App struct {
	cfg      *config.Server
	store    data.Store
	scope    *scope.ScopeManager
	searcher search.Searcher
	s3       *minio.Client
	sessions *sessions.Manager
	views    *views.Renderer
	version  string
	httpSrv  *http.Server
}

// NewOpts carries optional runtime metadata that doesn't belong on Config
// (like the binary version stamped at link time).
type NewOpts struct {
	Version string
}

// New builds an App: one liveness check per dependency, then a ready-to-run
// HTTP server. Migrations are applied as part of store construction.
func New(ctx context.Context, cfg *config.Server, opts NewOpts) (*App, error) {
	a := &App{cfg: cfg, version: opts.Version}
	if a.version == "" {
		a.version = "dev"
	}

	if err := a.initStore(ctx); err != nil {
		a.close()
		return nil, err
	}
	if err := a.initScope(ctx); err != nil {
		a.close()
		return nil, err
	}
	if err := a.initOpenSearch(ctx); err != nil {
		a.close()
		return nil, err
	}
	if err := a.initObjectStore(ctx); err != nil {
		a.close()
		return nil, err
	}
	if err := a.initWeb(); err != nil {
		a.close()
		return nil, err
	}

	a.httpSrv = httpserver.New(cfg, httpserver.Deps{
		Store:    a.store,
		Scope:    a.scope,
		Searcher: a.searcher,
		S3:       a.s3,
		Sessions: a.sessions,
		Views:    a.views,
		Version:  a.version,
	})
	return a, nil
}

// initWeb builds the session manager and the template renderer. Both are
// process-lifetime dependencies; failures here are configuration bugs.
func (a *App) initWeb() error {
	a.sessions = sessions.New(sessions.Options{
		Lifetime: 24 * time.Hour,
		Secure:   strings.HasPrefix(a.cfg.PublicURL, "https://"),
	})
	r, err := views.New()
	if err != nil {
		return fmt.Errorf("views: %w", err)
	}
	a.views = r
	return nil
}

// Run starts the HTTP listener and blocks until ctx is cancelled or the
// listener returns an error. On shutdown, in-flight requests drain within
// 10 seconds and every backing client is closed.
func (a *App) Run(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() { errCh <- a.httpSrv.ListenAndServe() }()

	select {
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		err := a.httpSrv.Shutdown(sctx)
		a.close()
		return err
	case err := <-errCh:
		a.close()
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func (a *App) initStore(ctx context.Context) error {
	var (
		store data.Store
		err   error
	)
	switch a.cfg.Dialect() {
	case "postgres":
		store, err = data.NewPostgresStore(ctx, a.cfg.Postgres.URL)
		if err != nil {
			return fmt.Errorf("postgres store: %w", err)
		}
		slog.InfoContext(ctx, "postgres connected + migrations applied")
	case "sqlite":
		store, err = data.NewSQLiteStore(ctx, a.cfg.SQLite.Path)
		if err != nil {
			return fmt.Errorf("sqlite store: %w", err)
		}
		slog.InfoContext(ctx, "sqlite connected + migrations applied", "path", a.cfg.SQLite.Path)
	default:
		return fmt.Errorf("unknown dialect %q", a.cfg.Dialect())
	}
	a.store = store
	return nil
}

// initScope builds the scope manager, wires its cycle-complete callback into
// the scope_log table, and performs the initial load from the store. An empty
// scope is accepted — the agent API will simply 404 getwork until scope is
// populated via the admin routes.
func (a *App) initScope(ctx context.Context) error {
	seed, err := resolveScanSeed(a.cfg.ScanSeedHex)
	if err != nil {
		return fmt.Errorf("scan seed: %w", err)
	}
	mgr, err := scope.NewScopeManager(seed)
	if err != nil {
		return fmt.Errorf("scope manager: %w", err)
	}
	mgr.SetOnCycleComplete(func(ctx context.Context, msg string) {
		if err := a.store.ScopeLogAppend(ctx, msg); err != nil {
			slog.ErrorContext(ctx, "scope_log append", "err", err)
		}
	})

	items, err := a.store.ScopeItemListAll(ctx)
	if err != nil {
		return fmt.Errorf("scope load: %w", err)
	}
	entries := make([]scope.Entry, len(items))
	for i, it := range items {
		entries[i] = scope.Entry{CIDR: it.CIDR, IsBlacklist: it.IsBlacklist}
	}
	if err := mgr.Load(entries); err != nil {
		return fmt.Errorf("scope load: %w", err)
	}
	a.scope = mgr

	wl, bl := mgr.Sizes()
	slog.InfoContext(ctx, "scope loaded", "whitelist", wl, "blacklist", bl, "items", len(items))
	return nil
}

// resolveScanSeed returns the 32-byte key for the Permutation. A hex-encoded
// value from config overrides the default; empty input means generate a fresh
// random seed for this process lifetime.
func resolveScanSeed(hexSeed string) ([]byte, error) {
	if s := strings.TrimSpace(hexSeed); s != "" {
		b, err := hex.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("SCAN_SEED_HEX must be hex: %w", err)
		}
		if len(b) < 8 {
			return nil, fmt.Errorf("SCAN_SEED_HEX must decode to at least 8 bytes (got %d)", len(b))
		}
		return b, nil
	}
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("read random seed: %w", err)
	}
	return seed, nil
}

func (a *App) initOpenSearch(ctx context.Context) error {
	client, err := opensearch.NewClient(opensearch.Config{
		Addresses: []string{a.cfg.OpenSearch.URL},
		Username:  a.cfg.OpenSearch.Username,
		Password:  a.cfg.OpenSearch.Password,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: a.cfg.OpenSearch.Insecure}, // #nosec G402 — dev override
		},
	})
	if err != nil {
		return fmt.Errorf("opensearch client: %w", err)
	}

	// Liveness probe up front so a misconfigured URL fails before we try to
	// create indices and produce a less obvious error.
	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, a.cfg.OpenSearch.URL, nil)
	if err != nil {
		return fmt.Errorf("opensearch probe request: %w", err)
	}
	if a.cfg.OpenSearch.Username != "" {
		req.SetBasicAuth(a.cfg.OpenSearch.Username, a.cfg.OpenSearch.Password)
	}
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: a.cfg.OpenSearch.Insecure}, // #nosec G402
		},
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("opensearch probe: %w", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("opensearch probe: HTTP %d from %s", resp.StatusCode, a.cfg.OpenSearch.URL)
	}

	if err := search.Bootstrap(ctx, client); err != nil {
		return fmt.Errorf("opensearch bootstrap: %w", err)
	}
	a.searcher = search.New(client)
	slog.InfoContext(ctx, "opensearch connected + indices ensured", "url", a.cfg.OpenSearch.URL)
	return nil
}

func (a *App) initObjectStore(ctx context.Context) error {
	s3, err := minio.New(a.cfg.ObjectStore.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(a.cfg.ObjectStore.AccessKey, a.cfg.ObjectStore.SecretKey, ""),
		Secure: a.cfg.ObjectStore.UseTLS,
		Region: a.cfg.ObjectStore.Region,
	})
	if err != nil {
		return fmt.Errorf("s3 client: %w", err)
	}
	ok, err := s3.BucketExists(ctx, a.cfg.ObjectStore.Bucket)
	if err != nil {
		return fmt.Errorf("s3 bucket check: %w", err)
	}
	if !ok {
		return fmt.Errorf("s3 bucket %q does not exist (run `make garage-bootstrap` or equivalent)", a.cfg.ObjectStore.Bucket)
	}
	a.s3 = s3
	slog.InfoContext(ctx, "object store connected",
		"endpoint", a.cfg.ObjectStore.Endpoint,
		"bucket", a.cfg.ObjectStore.Bucket,
	)
	return nil
}

func (a *App) close() {
	if a.store != nil {
		a.store.Close()
		a.store = nil
	}
}
