// Package httpserver wires the chi router, its middleware stack, and the
// dependency handle passed to handlers. Handler groups live in subpackages
// (api, admin, auth, host, main, user) and are mounted here.
//
// Phase 1: only /healthz and /readyz are mounted. Real routes come in later
// phases; this file is the single place where routes get wired in.
package httpserver

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"
	"github.com/opensearch-project/opensearch-go/v4"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/thenickstrick/go-natlas/internal/config"
)

// Deps is the dependency handle shared by every handler.
type Deps struct {
	Postgres   *pgxpool.Pool // nil if SQLite is configured
	SQLite     *sql.DB       // nil if Postgres is configured
	OpenSearch *opensearch.Client
	S3         *minio.Client
}

// New returns a configured *http.Server ready for ListenAndServe.
func New(cfg *config.Server, deps Deps) *http.Server {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))

	r.Get("/healthz", healthz())
	r.Get("/readyz", readyz(deps))

	// otelhttp wraps the whole mux so every request produces a span whose
	// attributes include http.route, http.method, etc. It is a no-op when the
	// tracer provider is the OTel default (no-op) provider.
	handler := otelhttp.NewHandler(r, "natlas-server")

	return &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
}

func healthz() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

// readyz pings every dependency that has a cheap liveness check. It is
// intentionally stricter than /healthz: kubelet-style probes should use it
// as the readiness gate.
func readyz(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		status := map[string]string{}
		code := http.StatusOK

		if deps.Postgres != nil {
			if err := deps.Postgres.Ping(ctx); err != nil {
				status["postgres"] = err.Error()
				code = http.StatusServiceUnavailable
			} else {
				status["postgres"] = "ok"
			}
		}
		if deps.SQLite != nil {
			if err := deps.SQLite.PingContext(ctx); err != nil {
				status["sqlite"] = err.Error()
				code = http.StatusServiceUnavailable
			} else {
				status["sqlite"] = "ok"
			}
		}
		writeJSON(w, code, status)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
