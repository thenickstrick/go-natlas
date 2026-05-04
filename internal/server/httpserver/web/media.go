package web

import (
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/thenickstrick/go-natlas/internal/server/objectstore"
)

// hashRE pins the screenshot filename to a sha256 hex (64 chars) plus an
// optional .png suffix. Anything else is rejected before we touch the object
// store, both to keep the URL space tight and to defeat path-traversal
// shenanigans (the filename feeds the object key directly).
var hashRE = regexp.MustCompile(`^[0-9a-f]{64}(?:\.png)?$`)

// Media streams a screenshot PNG from the object store. URLs look like:
//
//	/media/<sha256>.png
//
// Hash-keyed URLs let us send aggressive immutable cache headers.
func (h *Handlers) Media(w http.ResponseWriter, r *http.Request) {
	if h.Objects == nil {
		http.Error(w, "object store not configured", http.StatusServiceUnavailable)
		return
	}
	name := chi.URLParam(r, "filename")
	if !hashRE.MatchString(name) {
		http.NotFound(w, r)
		return
	}
	hash := strings.TrimSuffix(name, ".png")
	body, contentType, size, err := h.Objects.Get(r.Context(), "screenshots/"+hash+".png")
	if errors.Is(err, objectstore.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "media: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer body.Close()

	if contentType == "" {
		contentType = "image/png"
	}
	w.Header().Set("Content-Type", contentType)
	if size > 0 {
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	}
	// Hash-addressed URLs are immutable by construction — same hash always
	// returns the same bytes. Browsers can cache forever.
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")

	if _, err := io.Copy(w, body); err != nil {
		// Connection torn down mid-stream; nothing useful to log.
		return
	}
}
