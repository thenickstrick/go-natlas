// Package app is the natlas-server bootstrap: it resolves configuration into
// live clients (Postgres/SQLite, OpenSearch, object store), verifies each with
// a startup liveness check, wires them into the HTTP server, and exposes a
// single Run method that blocks until the caller's context is cancelled.
//
// Any failure during New aborts startup — the operator sees a readable error
// and the process exits non-zero. No background retry; if Postgres is down at
// boot, the supervisor should restart us.
package app

import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/opensearch-project/opensearch-go/v4"

	// Register pure-Go SQLite driver under the name "sqlite".
	_ "modernc.org/sqlite"

	"github.com/thenickstrick/go-natlas/internal/config"
	"github.com/thenickstrick/go-natlas/internal/server/httpserver"
)

// App owns every long-lived resource the server holds open.
type App struct {
	cfg *config.Server

	pg     *pgxpool.Pool
	sqlite *sql.DB
	os     *opensearch.Client
	s3     *minio.Client

	httpSrv *http.Server
}

// New builds an App, performs one liveness check per dependency, and returns
// a ready-to-run instance. The caller must eventually invoke Run.
func New(ctx context.Context, cfg *config.Server) (*App, error) {
	a := &App{cfg: cfg}

	if err := a.initDatabase(ctx); err != nil {
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

	a.httpSrv = httpserver.New(cfg, httpserver.Deps{
		Postgres:   a.pg,
		SQLite:     a.sqlite,
		OpenSearch: a.os,
		S3:         a.s3,
	})
	return a, nil
}

// Run starts the HTTP listener and blocks until ctx is cancelled or the
// listener returns an error. On shutdown it drains in-flight requests with
// a 10s grace period and closes all backing clients.
func (a *App) Run(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() { errCh <- a.httpSrv.ListenAndServe() }()

	select {
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		err := a.httpSrv.Shutdown(sctx)
		a.close()
		if err != nil {
			return err
		}
		return nil
	case err := <-errCh:
		a.close()
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func (a *App) initDatabase(ctx context.Context) error {
	switch a.cfg.Dialect() {
	case "postgres":
		pool, err := pgxpool.New(ctx, a.cfg.Postgres.URL)
		if err != nil {
			return fmt.Errorf("postgres pool: %w", err)
		}
		if err := pool.Ping(ctx); err != nil {
			pool.Close()
			return fmt.Errorf("postgres ping: %w", err)
		}
		a.pg = pool
		slog.InfoContext(ctx, "postgres connected")
	case "sqlite":
		db, err := sql.Open("sqlite", a.cfg.SQLite.Path)
		if err != nil {
			return fmt.Errorf("sqlite open: %w", err)
		}
		if err := db.PingContext(ctx); err != nil {
			_ = db.Close()
			return fmt.Errorf("sqlite ping: %w", err)
		}
		a.sqlite = db
		slog.InfoContext(ctx, "sqlite connected", "path", a.cfg.SQLite.Path)
	default:
		return fmt.Errorf("unknown dialect %q", a.cfg.Dialect())
	}
	return nil
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

	// Phase 1 liveness probe: raw HTTP GET against the cluster root. Switching
	// to the typed opensearchapi client happens in Phase 5 when we start
	// issuing real index/search calls.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.cfg.OpenSearch.URL, nil)
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

	a.os = client
	slog.InfoContext(ctx, "opensearch connected", "url", a.cfg.OpenSearch.URL)
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
	if a.pg != nil {
		a.pg.Close()
		a.pg = nil
	}
	if a.sqlite != nil {
		_ = a.sqlite.Close()
		a.sqlite = nil
	}
}
