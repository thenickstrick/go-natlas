package auth

import (
	"errors"
	"net/http"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/thenickstrick/go-natlas/internal/server/data"
	"github.com/thenickstrick/go-natlas/internal/server/sessions"
	"github.com/thenickstrick/go-natlas/internal/server/views"
)

// WebHandlers owns the user-facing /auth routes: login, logout, and the
// first-launch admin-bootstrap endpoint.
type WebHandlers struct {
	Store    data.Store
	Sessions *sessions.Manager
	Views    *views.Renderer
}

// GetLogin renders the login form. If no users exist yet, the same page
// renders a first-launch admin-creation form instead. This is the ONLY way
// the first admin gets created without an out-of-band CLI, so it's
// deliberately permissive: any unauthenticated request can reach it.
func (h *WebHandlers) GetLogin(w http.ResponseWriter, r *http.Request) {
	count, err := h.Store.UserCount(r.Context())
	if err != nil {
		http.Error(w, "user count: "+err.Error(), http.StatusInternalServerError)
		return
	}
	h.Views.Render(w, r, h.Sessions, "auth/login", "Log in", map[string]any{
		"FirstLaunch": count == 0,
	})
}

// PostLogin authenticates email+password, rotates the session token, and
// redirects to /browse on success. Shown errors are deliberately vague.
func (h *WebHandlers) PostLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.renderLoginError(w, r, "", "Invalid form submission.")
		return
	}
	email := strings.TrimSpace(r.PostForm.Get("email"))
	password := r.PostForm.Get("password")

	user, err := h.Store.UserGetByEmail(r.Context(), email)
	if err != nil {
		// Unknown email and wrong password share the same user-visible error
		// message to avoid account enumeration.
		h.renderLoginError(w, r, email, "Invalid email or password.")
		return
	}
	if !user.IsActive {
		h.renderLoginError(w, r, email, "Account is inactive. Contact an administrator.")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		h.renderLoginError(w, r, email, "Invalid email or password.")
		return
	}

	if err := h.Sessions.RenewToken(r.Context()); err != nil {
		http.Error(w, "session: renew: "+err.Error(), http.StatusInternalServerError)
		return
	}
	h.Sessions.SetUserID(r.Context(), user.ID)
	h.Sessions.PutFlash(r.Context(), "Welcome back, "+user.Email+".")
	http.Redirect(w, r, "/browse", http.StatusSeeOther)
}

// PostLogout clears the session regardless of its prior contents.
func (h *WebHandlers) PostLogout(w http.ResponseWriter, r *http.Request) {
	_ = h.Sessions.Destroy(r.Context())
	http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
}

// PostBootstrap creates the first admin account. It refuses if any user
// already exists to prevent a compromised /auth/bootstrap endpoint from
// being used to add rogue admins.
func (h *WebHandlers) PostBootstrap(w http.ResponseWriter, r *http.Request) {
	count, err := h.Store.UserCount(r.Context())
	if err != nil {
		http.Error(w, "user count: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if count > 0 {
		http.Error(w, "bootstrap: already initialized", http.StatusConflict)
		return
	}
	if err := r.ParseForm(); err != nil {
		h.renderBootstrapError(w, r, "", "Invalid form submission.")
		return
	}
	email := strings.TrimSpace(r.PostForm.Get("email"))
	password := r.PostForm.Get("password")
	if email == "" || len(password) < 8 {
		h.renderBootstrapError(w, r, email, "Email required and password must be at least 8 characters.")
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		h.renderBootstrapError(w, r, email, "Unable to hash password: "+err.Error())
		return
	}
	user, err := h.Store.UserCreate(r.Context(), data.UserCreateParams{
		Email:        email,
		PasswordHash: string(hash),
		IsAdmin:      true,
		IsActive:     true,
	})
	if err != nil {
		h.renderBootstrapError(w, r, email, "Could not create user: "+err.Error())
		return
	}

	// Log the new user in immediately.
	if err := h.Sessions.RenewToken(r.Context()); err != nil {
		http.Error(w, "session: renew: "+err.Error(), http.StatusInternalServerError)
		return
	}
	h.Sessions.SetUserID(r.Context(), user.ID)
	h.Sessions.PutFlash(r.Context(), "Welcome, "+user.Email+". You are the first administrator.")
	http.Redirect(w, r, "/browse", http.StatusSeeOther)
}

func (h *WebHandlers) renderLoginError(w http.ResponseWriter, r *http.Request, email, msg string) {
	h.Views.Render(w, r, h.Sessions, "auth/login", "Log in", map[string]any{
		"Email":       email,
		"Error":       msg,
		"FirstLaunch": false,
	})
}

func (h *WebHandlers) renderBootstrapError(w http.ResponseWriter, r *http.Request, email, msg string) {
	h.Views.Render(w, r, h.Sessions, "auth/login", "Initial setup", map[string]any{
		"Email":       email,
		"Error":       msg,
		"FirstLaunch": true,
	})
}

// ErrInvalidCreds is the sentinel auth failure for unit tests that want to
// branch on it without string-matching.
var ErrInvalidCreds = errors.New("auth: invalid credentials")
