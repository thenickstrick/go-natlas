package web_test

import (
	"context"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/thenickstrick/go-natlas/internal/config"
	"github.com/thenickstrick/go-natlas/internal/server/data"
	"github.com/thenickstrick/go-natlas/internal/server/httpserver"
	"github.com/thenickstrick/go-natlas/internal/server/scope"
	"github.com/thenickstrick/go-natlas/internal/server/search"
	"github.com/thenickstrick/go-natlas/internal/server/sessions"
	"github.com/thenickstrick/go-natlas/internal/server/views"
)

// fakeSearcher is the minimum Searcher the web routes exercise. It returns an
// empty result set for every call, which is what a fresh deployment looks
// like.
type fakeSearcher struct{}

func (fakeSearcher) IndexResult(context.Context, search.Document) error { return nil }
func (fakeSearcher) GetLatest(context.Context, netip.Addr) (search.Document, error) {
	return search.Document{}, search.ErrNotFound
}
func (fakeSearcher) GetHistory(context.Context, netip.Addr, int, int) (search.Page, error) {
	return search.Page{}, nil
}
func (fakeSearcher) GetScanByID(context.Context, string) (search.Document, error) {
	return search.Document{}, search.ErrNotFound
}
func (fakeSearcher) Search(context.Context, search.SearchOpts) (search.Page, error) {
	return search.Page{}, nil
}
func (fakeSearcher) CountSince(context.Context, time.Time) (int64, error) { return 0, nil }
func (fakeSearcher) RandomHost(context.Context) (search.Document, error) {
	return search.Document{}, search.ErrNotFound
}
func (fakeSearcher) DeleteScan(context.Context, string) error { return nil }
func (fakeSearcher) Refresh(context.Context) error            { return nil }

// startServer boots a full in-process server with SQLite + fake Searcher +
// seeded ScopeManager. Returns the server + a cookie-jar-backed client so
// sessions persist across requests.
func startServer(t *testing.T) (*httptest.Server, *http.Client, data.Store) {
	t.Helper()
	store, err := data.NewSQLiteStore(context.Background(), filepath.Join(t.TempDir(), "web.sqlite"))
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(store.Close)

	sm, _ := scope.NewScopeManager([]byte("web-test-seed"))
	_ = sm.Load(nil)

	vr, err := views.New()
	if err != nil {
		t.Fatalf("views.New: %v", err)
	}
	sessMgr := sessions.New(sessions.Options{})

	cfg := &config.Server{
		HTTPAddr:          "127.0.0.1:0",
		PublicURL:         "http://127.0.0.1",
		SecretKey:         "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz",
		AgentAuthRequired: false,
	}
	handler := httpserver.New(cfg, httpserver.Deps{
		Store:    store,
		Scope:    sm,
		Searcher: fakeSearcher{},
		Sessions: sessMgr,
		Views:    vr,
		Version:  "test",
	}).Handler

	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar: jar,
		// Keep redirects opt-in so tests can assert 303/302 explicitly.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return ts, client, store
}

// extractCSRFToken scrapes the hidden csrf input out of a rendered form. The
// token is required by gorilla/csrf on every POST.
var csrfFormRE = regexp.MustCompile(`name="gorilla\.csrf\.Token"\s+value="([^"]+)"`)

func extractCSRFToken(t *testing.T, body string) string {
	t.Helper()
	m := csrfFormRE.FindStringSubmatch(body)
	if len(m) < 2 {
		t.Fatalf("csrf token not found in form body; got:\n%s", body)
	}
	// html/template escapes the value attribute (e.g. + -> &#43;); a real
	// browser decodes those entities before submitting, so the test must too.
	return html.UnescapeString(m[1])
}

func getBody(t *testing.T, client *http.Client, url string) (int, string) {
	t.Helper()
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// postForm POSTs url.Values with a same-origin Referer header. gorilla/csrf's
// default POST/PUT/DELETE/PATCH policy requires Origin or Referer to match the
// request host; real browsers set this automatically but Go's http.Client
// doesn't. Not setting it would turn every CSRF check into a 403 here.
func postForm(t *testing.T, client *http.Client, u string, form url.Values) (int, string, *http.Response) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, u, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build POST %s: %v", u, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", u)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", u, err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, string(b), resp
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

func TestRootRedirectsToLogin(t *testing.T) {
	ts, client, _ := startServer(t)
	resp, err := client.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status: got %d, want 303", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/auth/login" {
		t.Fatalf("Location: got %q, want /auth/login", loc)
	}
}

func TestBrowseRedirectsWhenUnauthenticated(t *testing.T) {
	ts, client, _ := startServer(t)
	resp, err := client.Get(ts.URL + "/browse")
	if err != nil {
		t.Fatalf("GET /browse: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/auth/login" {
		t.Fatalf("expected 303 -> /auth/login, got %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestLoginFirstLaunchBootstrapAndLogin(t *testing.T) {
	ts, client, store := startServer(t)

	// 1. GET /auth/login — should render the first-launch bootstrap form.
	code, body := getBody(t, client, ts.URL+"/auth/login")
	if code != 200 {
		t.Fatalf("GET /auth/login: got %d", code)
	}
	if !strings.Contains(body, "Create the initial admin") {
		t.Fatalf("expected first-launch copy, got:\n%s", body)
	}
	token := extractCSRFToken(t, body)

	// 2. POST /auth/bootstrap — creates admin and logs in.
	code, body, resp := postForm(t, client, ts.URL+"/auth/bootstrap", url.Values{
		"gorilla.csrf.Token": {token},
		"email":              {"admin@example.com"},
		"password":           {"correcthorse"},
	})
	if code != http.StatusSeeOther || resp.Header.Get("Location") != "/browse" {
		t.Fatalf("bootstrap: expected 303 -> /browse; got %d loc=%q body=%s", code, resp.Header.Get("Location"), body)
	}

	// 3. GET /browse — session cookie carries us past RequireAuth.
	code, body = getBody(t, client, ts.URL+"/browse")
	if code != 200 {
		t.Fatalf("GET /browse after login: got %d, body:\n%s", code, body)
	}
	if !strings.Contains(body, "admin@example.com") {
		t.Fatalf("browse should show logged-in email; body:\n%s", body)
	}

	// 4. Verify the user actually landed in the DB as admin.
	u, err := store.UserGetByEmail(context.Background(), "admin@example.com")
	if err != nil {
		t.Fatalf("UserGetByEmail: %v", err)
	}
	if !u.IsAdmin || !u.IsActive {
		t.Fatalf("bootstrap user missing flags: %+v", u)
	}

	// 5. A second bootstrap POST with fresh token must 409 now that a user exists.
	code, body = getBody(t, client, ts.URL+"/auth/login")
	token = extractCSRFToken(t, body)
	code, _, _ = postForm(t, client, ts.URL+"/auth/bootstrap", url.Values{
		"gorilla.csrf.Token": {token},
		"email":              {"x@example.com"},
		"password":           {"longenoughpwd"},
	})
	if code != http.StatusConflict {
		t.Fatalf("second bootstrap: got %d, want 409", code)
	}
}

func TestAdminScopeCreateReloadsScope(t *testing.T) {
	ts, client, _ := startServer(t)

	// Bootstrap an admin to get in.
	_, body := getBody(t, client, ts.URL+"/auth/login")
	token := extractCSRFToken(t, body)
	_, _, _ = postForm(t, client, ts.URL+"/auth/bootstrap", url.Values{
		"gorilla.csrf.Token": {token},
		"email":              {"admin@example.com"},
		"password":           {"correcthorse"},
	})

	// GET /admin/scope — should list zero items and expose a CSRF token.
	_, body = getBody(t, client, ts.URL+"/admin/scope")
	if !strings.Contains(body, "No scope items yet") {
		t.Fatalf("expected empty state, got:\n%s", body)
	}
	token = extractCSRFToken(t, body)

	// POST a scope item.
	code, _, resp := postForm(t, client, ts.URL+"/admin/scope", url.Values{
		"gorilla.csrf.Token": {token},
		"cidr":               {"10.0.0.0/30"},
	})
	if code != http.StatusSeeOther || resp.Header.Get("Location") != "/admin/scope" {
		t.Fatalf("POST /admin/scope: got %d %q", code, resp.Header.Get("Location"))
	}

	// Follow redirect; row should be listed.
	_, body = getBody(t, client, ts.URL+"/admin/scope")
	if !strings.Contains(body, "10.0.0.0/30") {
		t.Fatalf("expected new row in list, got:\n%s", body)
	}
}

func TestLogoutClearsSession(t *testing.T) {
	ts, client, _ := startServer(t)

	// Bootstrap admin, ensure logged in.
	_, body := getBody(t, client, ts.URL+"/auth/login")
	token := extractCSRFToken(t, body)
	_, _, _ = postForm(t, client, ts.URL+"/auth/bootstrap", url.Values{
		"gorilla.csrf.Token": {token},
		"email":              {"admin@example.com"},
		"password":           {"correcthorse"},
	})
	code, body := getBody(t, client, ts.URL+"/browse")
	if code != 200 {
		t.Fatalf("should be logged in; got %d", code)
	}
	token = extractCSRFToken(t, body)

	// Logout.
	code, _, resp := postForm(t, client, ts.URL+"/auth/logout", url.Values{
		"gorilla.csrf.Token": {token},
	})
	if code != http.StatusSeeOther || resp.Header.Get("Location") != "/auth/login" {
		t.Fatalf("logout: got %d %q", code, resp.Header.Get("Location"))
	}

	// Browse should now require auth again.
	resp2, _ := client.Get(ts.URL + "/browse")
	if resp2.StatusCode != http.StatusSeeOther {
		t.Fatalf("GET /browse after logout: got %d", resp2.StatusCode)
	}
	_ = resp2.Body.Close()
}
