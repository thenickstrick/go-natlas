package web

import (
	"net/http"
	"net/netip"

	"github.com/go-chi/chi/v5"

	"github.com/thenickstrick/go-natlas/internal/server/sessions"
)

// HostRescan handles POST /host/{ip}/rescan: validates scope, creates a
// rescan_task owned by the current user, and redirects back to the host
// page with a flash message. The actual dispatch happens the next time an
// agent polls /api/v1/work.
//
// We intentionally do not deduplicate against existing pending rescans for
// the same IP — operators sometimes want to re-queue a target multiple
// times in a row, and the dispatcher's single-pop semantics already prevent
// over-dispatch.
func (h *Handlers) HostRescan(w http.ResponseWriter, r *http.Request) {
	user, ok := sessions.UserFrom(r.Context())
	if !ok {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}
	ipStr := chi.URLParam(r, "ip")
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		http.Error(w, "invalid IP", http.StatusBadRequest)
		return
	}
	if !h.Scope.IsAcceptable(addr) {
		h.Sessions.PutFlash(r.Context(), "Cannot rescan "+addr.String()+": out of scope.")
		http.Redirect(w, r, "/host/"+ipStr, http.StatusSeeOther)
		return
	}
	if _, err := h.Store.RescanTaskCreate(r.Context(), user.ID, addr); err != nil {
		http.Error(w, "rescan: "+err.Error(), http.StatusInternalServerError)
		return
	}
	h.Sessions.PutFlash(r.Context(), "Rescan queued for "+addr.String()+".")
	http.Redirect(w, r, "/host/"+ipStr, http.StatusSeeOther)
}
