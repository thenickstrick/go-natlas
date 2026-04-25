package web

import (
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/thenickstrick/go-natlas/internal/server/data"
	"github.com/thenickstrick/go-natlas/internal/server/scope"
)

// AdminScope renders the scope management page. Both scope and blacklist
// items appear in one table, with badges distinguishing them.
func (h *Handlers) AdminScope(w http.ResponseWriter, r *http.Request) {
	items, err := h.Store.ScopeItemListAll(r.Context())
	if err != nil {
		http.Error(w, "scope: "+err.Error(), http.StatusInternalServerError)
		return
	}
	h.Views.Render(w, r, h.Sessions, "admin/scope", "Scope", map[string]any{
		"Items": items,
		"Count": len(items),
	})
}

// AdminScopeCreate accepts POSTed cidr + is_blacklist, persists the row,
// and hot-reloads ScopeManager so the dispatcher sees the change on the
// very next /api/v1/work call. Failures re-render the page with an error.
func (h *Handlers) AdminScopeCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.renderAdminScope(w, r, "Invalid form submission.")
		return
	}
	cidrStr := strings.TrimSpace(r.PostForm.Get("cidr"))
	isBlacklist := r.PostForm.Get("is_blacklist") == "1"

	prefix, err := netip.ParsePrefix(cidrStr)
	if err != nil {
		h.renderAdminScope(w, r, "Invalid CIDR: "+err.Error())
		return
	}
	prefix = prefix.Masked()

	// Compute first + last addresses. The range is used by operator-facing
	// exports and for future broadcast-skip logic; ScopeManager itself only
	// reads the prefix.
	startAddr := prefix.Addr()
	stopAddr := lastAddr(prefix)

	if _, err := h.Store.ScopeItemCreate(r.Context(), data.ScopeItemCreateParams{
		CIDR:        prefix,
		IsBlacklist: isBlacklist,
		StartAddr:   startAddr,
		StopAddr:    stopAddr,
	}); err != nil {
		h.renderAdminScope(w, r, "Could not create scope item: "+err.Error())
		return
	}
	if err := h.reloadScope(r); err != nil {
		h.renderAdminScope(w, r, "Scope saved but reload failed: "+err.Error())
		return
	}
	_ = h.Store.ScopeLogAppend(r.Context(), "admin added "+prefix.String()+" (blacklist="+strconv.FormatBool(isBlacklist)+")")
	h.Sessions.PutFlash(r.Context(), "Scope updated.")
	http.Redirect(w, r, "/admin/scope", http.StatusSeeOther)
}

// AdminScopeDelete removes a scope row and hot-reloads the dispatcher.
func (h *Handlers) AdminScopeDelete(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	if err := h.Store.ScopeItemDelete(r.Context(), id); err != nil {
		h.renderAdminScope(w, r, "Delete failed: "+err.Error())
		return
	}
	if err := h.reloadScope(r); err != nil {
		h.renderAdminScope(w, r, "Row removed but reload failed: "+err.Error())
		return
	}
	h.Sessions.PutFlash(r.Context(), "Scope item deleted.")
	http.Redirect(w, r, "/admin/scope", http.StatusSeeOther)
}

// renderAdminScope re-renders the admin page with an inline error. Used when
// mutation handlers want to show a failure without losing the current list.
func (h *Handlers) renderAdminScope(w http.ResponseWriter, r *http.Request, errMsg string) {
	items, _ := h.Store.ScopeItemListAll(r.Context())
	h.Views.Render(w, r, h.Sessions, "admin/scope", "Scope", map[string]any{
		"Items": items,
		"Count": len(items),
		"Error": errMsg,
	})
}

// reloadScope pulls the current scope from the store and swaps it into the
// in-memory ScopeManager.
func (h *Handlers) reloadScope(r *http.Request) error {
	items, err := h.Store.ScopeItemListAll(r.Context())
	if err != nil {
		return err
	}
	entries := make([]scope.Entry, len(items))
	for i, it := range items {
		entries[i] = scope.Entry{CIDR: it.CIDR, IsBlacklist: it.IsBlacklist}
	}
	return h.Scope.Load(entries)
}

// lastAddr returns the last address contained in a prefix. IPv4 fast path
// flips all host bits in a uint32; IPv6 uses As16 + a 128-bit host mask.
func lastAddr(p netip.Prefix) netip.Addr {
	if p.Addr().Is4() {
		b := p.Addr().As4()
		base := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
		host := uint32(1)<<uint(32-p.Bits()) - 1
		last := base | host
		return netip.AddrFrom4([4]byte{byte(last >> 24), byte(last >> 16), byte(last >> 8), byte(last)})
	}
	bytes := p.Addr().As16()
	flipBits := 128 - p.Bits()
	for i := 15; i >= 0 && flipBits > 0; i-- {
		if flipBits >= 8 {
			bytes[i] = 0xFF
			flipBits -= 8
		} else {
			bytes[i] |= byte(1<<uint(flipBits)) - 1
			flipBits = 0
		}
	}
	return netip.AddrFrom16(bytes)
}
