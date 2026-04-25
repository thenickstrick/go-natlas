// Package views is the html/template loader + renderer. Templates live in
// internal/server/views/templates and are embedded into the binary.
//
// Go templates share their "define" namespace across a single *template.Template
// set, so having every page declare {{define "content"}} would silently make
// them overwrite each other. We work around this by building a separate set
// per page: the layout (base.html.tmpl) is parsed once, then cloned per page
// and the page's own content block is attached to that clone.
package views

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"strings"
	"sync"

	"github.com/gorilla/csrf"

	"github.com/thenickstrick/go-natlas/internal/server/data"
	"github.com/thenickstrick/go-natlas/internal/server/sessions"
)

//go:embed all:templates
var templatesFS embed.FS

// Renderer holds one fully-parsed *template.Template per page. Each value
// already has "base" + its page's "content" definitions, so rendering is a
// straight ExecuteTemplate("base", ...) call without any cloning on the hot
// path.
type Renderer struct {
	pages map[string]*template.Template
	once  sync.Once
}

// Page is the consistent data envelope passed to every template.
type Page struct {
	CSRFToken string
	User      *data.User
	Flash     string
	PageTitle string
	Path      string
	Data      any
}

// New parses and returns a Renderer over the embedded template tree. Failures
// here are programmer errors — abort startup rather than defer.
func New() (*Renderer, error) {
	funcs := template.FuncMap{
		"join": func(sep string, items []string) string { return strings.Join(items, sep) },
	}

	// Read all template bytes first; we'll reuse the base bytes per page.
	type tmplFile struct {
		name string // e.g. "auth/login" or "base"
		body []byte
	}
	var files []tmplFile
	err := fs.WalkDir(templatesFS, "templates", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if !strings.HasSuffix(path, ".html.tmpl") {
			return nil
		}
		body, err := templatesFS.ReadFile(path)
		if err != nil {
			return err
		}
		name := strings.TrimPrefix(path, "templates/")
		name = strings.TrimSuffix(name, ".html.tmpl")
		files = append(files, tmplFile{name: name, body: body})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("views: walk templates: %w", err)
	}

	// Find the base layout's bytes once.
	var baseBody []byte
	for _, f := range files {
		if f.name == "base" {
			baseBody = f.body
			break
		}
	}
	if baseBody == nil {
		return nil, fmt.Errorf("views: base.html.tmpl missing")
	}

	// Parse one Template set per page. Each set gets: funcs, the base layout,
	// and the page's own body (which defines "content").
	pages := map[string]*template.Template{}
	for _, f := range files {
		if f.name == "base" {
			continue
		}
		t := template.New(f.name).Funcs(funcs)
		if _, err := t.Parse(string(baseBody)); err != nil {
			return nil, fmt.Errorf("parse base for %s: %w", f.name, err)
		}
		if _, err := t.Parse(string(f.body)); err != nil {
			return nil, fmt.Errorf("parse %s: %w", f.name, err)
		}
		pages[f.name] = t
	}
	return &Renderer{pages: pages}, nil
}

// Render executes the named page template under the base layout. name uses
// slash-separated paths relative to templates/ without the .html.tmpl suffix
// (e.g. "auth/login", "browse", "host/detail").
func (r *Renderer) Render(w http.ResponseWriter, req *http.Request, sm *sessions.Manager, name, title string, data any) {
	user, _ := sessions.UserFrom(req.Context())
	page := Page{
		CSRFToken: csrf.Token(req),
		Flash:     sm.PopFlash(req.Context()),
		PageTitle: title,
		Path:      req.URL.Path,
		Data:      data,
	}
	if user.ID != 0 {
		u := user
		page.User = &u
	}

	t, ok := r.pages[name]
	if !ok {
		http.Error(w, fmt.Sprintf("views: page %q not found", name), http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "base", page); err != nil {
		http.Error(w, fmt.Sprintf("views: execute %q: %v", name, err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(buf.Bytes())
}

// RenderFragment executes a named sub-template with no layout. For HTMX
// partials. The template must be defined (via {{define "<name>"}}) somewhere
// in the embedded tree.
func (r *Renderer) RenderFragment(w http.ResponseWriter, req *http.Request, name string, data any) {
	_ = req
	// Any page set can resolve any shared fragment, since fragments live as
	// named defines and are reachable from whichever set we pick. Use the
	// first page set we have — cheap and stable.
	var anySet *template.Template
	for _, t := range r.pages {
		anySet = t
		break
	}
	if anySet == nil {
		http.Error(w, "views: no templates loaded", http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := anySet.ExecuteTemplate(&buf, name, data); err != nil {
		http.Error(w, fmt.Sprintf("views: execute fragment %q: %v", name, err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(buf.Bytes())
}
