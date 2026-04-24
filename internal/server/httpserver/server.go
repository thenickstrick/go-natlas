// Package httpserver wires the chi router, its middleware stack, and the
// dependency handle passed to handlers. Handler groups live in subpackages
// (api, admin, auth, host, main, user) and are mounted here.
//
// Phase 1: only /healthz and /readyz are mounted. Real routes come in later
// phases; this file is the single place where routes get wired in.
package httpserver

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/minio/minio-go/v7"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/thenickstrick/go-natlas/internal/config"
	"github.com/thenickstrick/go-natlas/internal/server/data"
	"github.com/thenickstrick/go-natlas/internal/server/httpserver/api"
	"github.com/thenickstrick/go-natlas/internal/server/httpserver/auth"
	"github.com/thenickstrick/go-natlas/internal/server/scope"
	"github.com/thenickstrick/go-natlas/internal/server/search"
)

// Deps is the dependency handle shared by every handler.
type Deps struct {
	Store    data.Store
	Scope    *scope.ScopeManager
	Searcher search.Searcher
	S3       *minio.Client
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

	// /api/v1 — agent-facing endpoints. Auth is middleware-gated; when
	// AGENT_AUTH_REQUIRED is false (dev default in compose) the middleware
	// is a pass-through so running `natlas-agent` locally needs no DB seed.
	handlers := &api.Handlers{Store: deps.Store, Scope: deps.Scope, Searcher: deps.Searcher}
	r.Route("/api/v1", func(apiR chi.Router) {
		apiR.Use(auth.AgentAuth(deps.Store, cfg.AgentAuthRequired))
		apiR.Get("/work", handlers.GetWork)
		apiR.Post("/results", handlers.PostResults)
		apiR.Get("/services", handlers.GetServices)
	})

	// otelhttp wraps the whole mux so every request produces a span. It is a
	// no-op when the tracer provider is the OTel default (no-op) provider.
	handler := otelhttp.NewHandler(r, "natlas-server")

	return &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
}

func healthz() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

// readyz pings the relational store. Kubelet-style probes should use it as
// the readiness gate; /healthz is a static liveness signal.
func readyz(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		status := map[string]string{}
		code := http.StatusOK

		if deps.Store != nil {
			if err := deps.Store.Ping(ctx); err != nil {
				status["db"] = err.Error()
				code = http.StatusServiceUnavailable
			} else {
				status["db"] = "ok"
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
