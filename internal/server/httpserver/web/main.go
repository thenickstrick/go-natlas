// Package web hosts the user-facing HTML handlers: root redirect, browse,
// host detail, server status, and the admin/scope page. Handlers are grouped
// by method receiver so they share the same Deps closure.
package web

import (
	"errors"
	"net/http"
	"net/netip"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/thenickstrick/go-natlas/internal/server/data"
	"github.com/thenickstrick/go-natlas/internal/server/scope"
	"github.com/thenickstrick/go-natlas/internal/server/search"
	"github.com/thenickstrick/go-natlas/internal/server/sessions"
	"github.com/thenickstrick/go-natlas/internal/server/views"
)

// Handlers owns every dependency the user-facing routes need. Kept as a
// single struct so plumbing stays obvious; these routes are tightly
// interrelated (browse -> host, admin mutates scope which browse reads).
type Handlers struct {
	Store    data.Store
	Scope    *scope.ScopeManager
	Searcher search.Searcher
	Sessions *sessions.Manager
	Views    *views.Renderer
	Version  string
}

// -----------------------------------------------------------------------------
// Root + Browse
// -----------------------------------------------------------------------------

// Root redirects to /browse for authenticated users and /auth/login for
// everyone else.
func (h *Handlers) Root(w http.ResponseWriter, r *http.Request) {
	if _, ok := sessions.UserFrom(r.Context()); ok {
		http.Redirect(w, r, "/browse", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
}

// Browse renders the search/paginate page. No-scope deployments are handled
// cleanly: Searcher.Search returns zero hits (or an error that we show).
func (h *Handlers) Browse(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	const limit = 50

	page, err := h.Searcher.Search(r.Context(), search.SearchOpts{
		Query: q, Limit: limit, Offset: offset,
	})
	if err != nil {
		http.Error(w, "search: "+err.Error(), http.StatusInternalServerError)
		return
	}
	data := map[string]any{
		"Query":      q,
		"Hits":       page.Hits,
		"Total":      page.Total,
		"PrevOffset": prevOffset(offset, limit),
		"NextOffset": nextOffset(offset, limit, page.Total),
	}
	h.Views.Render(w, r, h.Sessions, "browse", "Browse", data)
}

func prevOffset(offset, limit int) int {
	if offset <= 0 {
		return 0
	}
	p := offset - limit
	if p < 0 {
		p = 0
	}
	return p
}

func nextOffset(offset, limit int, total int64) int {
	if int64(offset+limit) >= total {
		return 0
	}
	return offset + limit
}

// -----------------------------------------------------------------------------
// Host detail
// -----------------------------------------------------------------------------

// Host renders the latest scan for an IP. Unknown hosts render a friendly
// empty state rather than a 404 so operators can paste an IP they expect to
// see soon.
func (h *Handlers) Host(w http.ResponseWriter, r *http.Request) {
	ipStr := chi.URLParam(r, "ip")
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		http.Error(w, "invalid IP", http.StatusBadRequest)
		return
	}
	doc, err := h.Searcher.GetLatest(r.Context(), addr)
	if errors.Is(err, search.ErrNotFound) {
		h.Views.Render(w, r, h.Sessions, "host/notfound", ipStr, map[string]any{"IP": ipStr})
		return
	}
	if err != nil {
		http.Error(w, "host: "+err.Error(), http.StatusInternalServerError)
		return
	}
	h.Views.Render(w, r, h.Sessions, "host/detail", ipStr, map[string]any{"Host": doc})
}

// -----------------------------------------------------------------------------
// Status
// -----------------------------------------------------------------------------

// Status renders a summary of the scope dispatcher plus server identity.
func (h *Handlers) Status(w http.ResponseWriter, r *http.Request) {
	whitelist, blacklist := h.Scope.Sizes()
	stats := h.Scope.Stats()
	data := map[string]any{
		"WhitelistSize":   whitelist,
		"BlacklistSize":   blacklist,
		"CyclesCompleted": stats.CyclesCompleted,
		"Cursor":          stats.Cursor,
		"CycleStart":      stats.CycleStart,
		"Version":         h.Version,
	}
	h.Views.Render(w, r, h.Sessions, "status", "Status", data)
}
