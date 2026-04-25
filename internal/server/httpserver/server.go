// Package httpserver wires the chi router and its middleware stack. Handler
// groups live in subpackages (api, auth, web) and are mounted here via two
// distinct subrouters:
//
//   - /api/v1/*   — agent-facing JSON. Sessionless. CSRF-free.
//   - everything else — user-facing HTML. Session-loaded, CSRF-protected.
//
// The split matters because the two families have incompatible security
// semantics: agents authenticate with bearer tokens and never touch cookies,
// while web routes rely on cookies and therefore must enforce CSRF.
package httpserver

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/gorilla/csrf"
	"github.com/minio/minio-go/v7"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/thenickstrick/go-natlas/internal/config"
	"github.com/thenickstrick/go-natlas/internal/server/assets"
	"github.com/thenickstrick/go-natlas/internal/server/data"
	"github.com/thenickstrick/go-natlas/internal/server/httpserver/api"
	"github.com/thenickstrick/go-natlas/internal/server/httpserver/auth"
	"github.com/thenickstrick/go-natlas/internal/server/httpserver/web"
	"github.com/thenickstrick/go-natlas/internal/server/scope"
	"github.com/thenickstrick/go-natlas/internal/server/search"
	"github.com/thenickstrick/go-natlas/internal/server/sessions"
	"github.com/thenickstrick/go-natlas/internal/server/views"
)

// Deps is the dependency handle shared by every handler.
type Deps struct {
	Store    data.Store
	Scope    *scope.ScopeManager
	Searcher search.Searcher
	S3       *minio.Client
	Sessions *sessions.Manager
	Views    *views.Renderer
	Version  string
}

// New returns a configured *http.Server ready for ListenAndServe.
func New(cfg *config.Server, deps Deps) *http.Server {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))

	// Unprotected infra routes. No sessions, no CSRF, no auth.
	r.Get("/healthz", healthz())
	r.Get("/readyz", readyz(deps))

	// Static assets. No session work needed.
	r.Handle("/static/*", http.StripPrefix("/static/", assets.Handler()))

	// Agent API (JSON, bearer auth, CSRF-exempt).
	apiHandlers := &api.Handlers{Store: deps.Store, Scope: deps.Scope, Searcher: deps.Searcher}
	r.Route("/api/v1", func(apiR chi.Router) {
		apiR.Use(auth.AgentAuth(deps.Store, cfg.AgentAuthRequired))
		apiR.Get("/work", apiHandlers.GetWork)
		apiR.Post("/results", apiHandlers.PostResults)
		apiR.Get("/services", apiHandlers.GetServices)
	})

	// Web routes. Session-loaded, CSRF-protected.
	if deps.Sessions != nil && deps.Views != nil {
		mountWebRoutes(r, cfg, deps)
	}

	// otelhttp wraps the whole mux so every request produces a span. It is a
	// no-op when the tracer provider is the OTel default (no-op) provider.
	handler := otelhttp.NewHandler(r, "natlas-server")

	return &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
}

func mountWebRoutes(r chi.Router, cfg *config.Server, deps Deps) {
	// gorilla/csrf requires an authenticated-key of 32 bytes. We derive it
	// from the configured SecretKey (the /32 prefix). Callers configure a
	// long random SecretKey; enforcement happens in config.validate.
	csrfKey := make([]byte, 32)
	copy(csrfKey, []byte(cfg.SecretKey))
	isHTTPS := strings.HasPrefix(cfg.PublicURL, "https://")
	csrfMiddleware := csrf.Protect(csrfKey,
		csrf.Secure(isHTTPS),
		csrf.Path("/"),
		csrf.HttpOnly(true),
		csrf.SameSite(csrf.SameSiteLaxMode),
		csrf.ErrorHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reason := csrf.FailureReason(r)
			http.Error(w, "csrf: "+reason.Error(), http.StatusForbidden)
		})),
	)
	// gorilla/csrf v1.7.3 defaults to "treat as HTTPS" for the Origin/Referer
	// check unless PlaintextHTTPContextKey is set in the request context. When
	// the operator runs over plain HTTP (dev compose, IPC behind a TLS proxy)
	// we mark requests accordingly so csrf doesn't reject every POST.
	plaintextHook := func(next http.Handler) http.Handler {
		if isHTTPS {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, csrf.PlaintextHTTPRequest(r))
		})
	}

	authH := &auth.WebHandlers{Store: deps.Store, Sessions: deps.Sessions, Views: deps.Views}
	webH := &web.Handlers{
		Store: deps.Store, Scope: deps.Scope, Searcher: deps.Searcher,
		Sessions: deps.Sessions, Views: deps.Views, Version: deps.Version,
	}

	r.Group(func(rWeb chi.Router) {
		rWeb.Use(deps.Sessions.Middleware)
		rWeb.Use(plaintextHook)
		rWeb.Use(csrfMiddleware)
		rWeb.Use(deps.Sessions.LoadCurrentUser(deps.Store))

		// Unauthenticated auth routes.
		rWeb.Get("/auth/login", authH.GetLogin)
		rWeb.Post("/auth/login", authH.PostLogin)
		rWeb.Post("/auth/logout", authH.PostLogout)
		rWeb.Post("/auth/bootstrap", authH.PostBootstrap)

		// Root redirect is public.
		rWeb.Get("/", webH.Root)

		// Authenticated pages.
		rWeb.Group(func(r chi.Router) {
			r.Use(sessions.RequireAuth())
			r.Get("/browse", webH.Browse)
			r.Get("/host/{ip}", webH.Host)
			r.Get("/status", webH.Status)
		})

		// Admin-only.
		rWeb.Group(func(r chi.Router) {
			r.Use(sessions.RequireAdmin())
			r.Get("/admin/scope", webH.AdminScope)
			r.Post("/admin/scope", webH.AdminScopeCreate)
			r.Post("/admin/scope/{id}/delete", webH.AdminScopeDelete)
		})
	})
}

func healthz() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

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
