// Package sessions wraps alexedwards/scs with natlas-specific helpers:
// storing/retrieving the authenticated user id, running an "attach current
// user" middleware that preloads the user once per request, and exposing a
// RequireAuth gate for protected web routes.
//
// Phase 6a uses the default in-memory scs store. Switching to PG/SQLite
// persistence is a drop-in change (Manager.Store = ...) — the interface
// here is unchanged.
package sessions

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/alexedwards/scs/v2"

	"github.com/thenickstrick/go-natlas/internal/server/data"
)

// Manager is a small façade around *scs.SessionManager. Kept as a distinct
// type so handler packages don't need to import scs directly.
type Manager struct {
	sm *scs.SessionManager
}

// Options configures a Manager. Secure=true is mandatory in production; set
// false only when serving plain HTTP in dev.
type Options struct {
	Lifetime time.Duration
	Secure   bool
}

// New returns a Manager with the default memory store. Callers wanting
// persistent sessions assign sm.Store before first use.
func New(opts Options) *Manager {
	sm := scs.New()
	if opts.Lifetime <= 0 {
		opts.Lifetime = 24 * time.Hour
	}
	sm.Lifetime = opts.Lifetime
	sm.Cookie.Name = "natlas_session"
	sm.Cookie.HttpOnly = true
	sm.Cookie.Secure = opts.Secure
	sm.Cookie.SameSite = http.SameSiteLaxMode
	sm.Cookie.Path = "/"
	return &Manager{sm: sm}
}

// Middleware returns the scs LoadAndSave middleware. Mount it on the web
// subrouter; the /api subrouter is session-free.
func (m *Manager) Middleware(next http.Handler) http.Handler {
	return m.sm.LoadAndSave(next)
}

// SetUserID records the authenticated user id. Call from login handlers.
func (m *Manager) SetUserID(ctx context.Context, id int64) {
	m.sm.Put(ctx, "user_id", id)
}

// UserID returns the stored user id, or 0 if no session.
func (m *Manager) UserID(ctx context.Context) int64 {
	v := m.sm.Get(ctx, "user_id")
	id, _ := v.(int64)
	return id
}

// Destroy clears the session — used on logout.
func (m *Manager) Destroy(ctx context.Context) error {
	return m.sm.Destroy(ctx)
}

// RenewToken rotates the session token; call on login to defeat session
// fixation attacks.
func (m *Manager) RenewToken(ctx context.Context) error {
	return m.sm.RenewToken(ctx)
}

// PutFlash stores a one-shot message retrievable on the next request.
func (m *Manager) PutFlash(ctx context.Context, msg string) {
	m.sm.Put(ctx, "flash", msg)
}

// PopFlash returns and clears any flash message, or "" if none.
func (m *Manager) PopFlash(ctx context.Context) string {
	v := m.sm.PopString(ctx, "flash")
	return v
}

// -----------------------------------------------------------------------------
// Middleware helpers
// -----------------------------------------------------------------------------

type userCtxKey struct{}

// UserFrom returns the user loaded for this request by LoadCurrentUser.
// Returns (zero, false) if no user is logged in.
func UserFrom(ctx context.Context) (data.User, bool) {
	u, ok := ctx.Value(userCtxKey{}).(data.User)
	return u, ok
}

// LoadCurrentUser returns middleware that looks up the session's user, if
// any, and attaches it to the request context. Failures are logged but do
// not abort the request — unauthenticated requests proceed with no user.
func (m *Manager) LoadCurrentUser(store data.Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := m.UserID(r.Context())
			if id == 0 {
				next.ServeHTTP(w, r)
				return
			}
			u, err := store.UserGetByID(r.Context(), id)
			if err != nil {
				// Session references a user that no longer exists, or a
				// transient DB error. Kill the session either way so the
				// user can re-authenticate cleanly.
				slog.WarnContext(r.Context(), "session: user lookup failed; destroying session", "user_id", id, "err", err)
				_ = m.Destroy(r.Context())
				next.ServeHTTP(w, r)
				return
			}
			ctx := context.WithValue(r.Context(), userCtxKey{}, u)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireAuth returns middleware that 302s to /auth/login when no user is
// attached. Handlers relying on this can read the user with UserFrom and
// assume it's present.
func RequireAuth() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, ok := UserFrom(r.Context()); !ok {
				http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireAdmin layers on top of RequireAuth: returns 403 on non-admin users.
func RequireAdmin() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u, ok := UserFrom(r.Context())
			if !ok {
				http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
				return
			}
			if !u.IsAdmin {
				http.Error(w, "admins only", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
