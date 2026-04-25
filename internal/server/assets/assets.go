// Package assets serves the server's embedded static files (CSS/JS) over
// HTTP under /static/. Files live in internal/server/assets/static and are
// compiled into the binary.
package assets

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed static
var staticFS embed.FS

// Handler returns an http.Handler that serves the embedded static tree with
// cache-friendly headers.
func Handler() http.Handler {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		// Fail loudly at process start if the embedded FS is malformed.
		panic("assets: fs.Sub: " + err.Error())
	}
	fileServer := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Static bundles are content-hashed neither here nor in Phase 6a;
		// keep caching conservative so operators editing assets don't have
		// to hard-reload. Bump to immutable-1y once we add hashed filenames.
		w.Header().Set("Cache-Control", "public, max-age=300")
		fileServer.ServeHTTP(w, r)
	})
}
