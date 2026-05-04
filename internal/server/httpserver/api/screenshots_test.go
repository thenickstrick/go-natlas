package api_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/thenickstrick/go-natlas/internal/server/data"
	"github.com/thenickstrick/go-natlas/internal/server/httpserver/api"
	"github.com/thenickstrick/go-natlas/internal/server/objectstore"
	"github.com/thenickstrick/go-natlas/internal/server/scope"
)

// uploadServer stands up the API handlers with an in-memory object store.
func uploadServer(t *testing.T) (*httptest.Server, *objectstore.Memory) {
	t.Helper()
	store, err := data.NewSQLiteStore(context.Background(), filepath.Join(t.TempDir(), "uploads.sqlite"))
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(store.Close)

	sm, _ := scope.NewScopeManager([]byte("upload-seed"))
	_ = sm.Load(nil)

	objs := objectstore.NewMemory()
	h := &api.Handlers{Store: store, Scope: sm, Objects: objs}
	r := chi.NewRouter()
	r.Post("/api/v1/screenshots/{scan_id}", h.PostScreenshots)

	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)
	return ts, objs
}

// buildMultipart writes one screenshot part with the natlas custom headers.
// Returns the body, the content-type, and the sha256 hex of body.
func buildMultipart(t *testing.T, port int, service string, body []byte, includeHash bool) (*bytes.Buffer, string, string) {
	t.Helper()
	buf := &bytes.Buffer{}
	mw := multipart.NewWriter(buf)
	hdr := textproto.MIMEHeader{}
	hdr.Set("Content-Disposition", `form-data; name="screenshot"; filename="`+strconv.Itoa(port)+"-"+service+".png\"")
	hdr.Set("Content-Type", "image/png")
	hdr.Set("X-Natlas-Port", strconv.Itoa(port))
	hdr.Set("X-Natlas-Service", service)
	sum := sha256.Sum256(body)
	hash := hex.EncodeToString(sum[:])
	if includeHash {
		hdr.Set("X-Natlas-Hash", hash)
	}
	part, err := mw.CreatePart(hdr)
	if err != nil {
		t.Fatalf("CreatePart: %v", err)
	}
	if _, err := part.Write(body); err != nil {
		t.Fatalf("part.Write: %v", err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return buf, mw.FormDataContentType(), hash
}

func TestPostScreenshotsSuccess(t *testing.T) {
	ts, objs := uploadServer(t)
	body := []byte("\x89PNG\r\n\x1a\nfake-png-bytes")
	mp, ct, hash := buildMultipart(t, 80, "HTTP", body, true)

	resp, err := http.Post(ts.URL+"/api/v1/screenshots/scan-123", ct, mp)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: %d body=%s", resp.StatusCode, raw)
	}

	var env map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&env)
	if env["scan_id"] != "scan-123" {
		t.Errorf("scan_id echo wrong: %v", env)
	}

	// The PNG should now be in the object store at screenshots/<hash>.png.
	exists, err := objs.Exists(context.Background(), "screenshots/"+hash+".png")
	if err != nil || !exists {
		t.Fatalf("expected object stored at hash key; exists=%v err=%v", exists, err)
	}
}

func TestPostScreenshotsHashMismatch(t *testing.T) {
	ts, _ := uploadServer(t)
	body := []byte("real bytes")
	mp, ct, _ := buildMultipart(t, 80, "HTTP", body, false)

	// Inject a wrong hash by re-building the multipart with a custom value.
	buf := &bytes.Buffer{}
	mw := multipart.NewWriter(buf)
	hdr := textproto.MIMEHeader{}
	hdr.Set("Content-Disposition", `form-data; name="screenshot"; filename="80-HTTP.png"`)
	hdr.Set("Content-Type", "image/png")
	hdr.Set("X-Natlas-Port", "80")
	hdr.Set("X-Natlas-Service", "HTTP")
	hdr.Set("X-Natlas-Hash", "deadbeef") // intentionally wrong
	part, _ := mw.CreatePart(hdr)
	_, _ = part.Write(body)
	_ = mw.Close()
	mp = buf
	ct = mw.FormDataContentType()

	resp, err := http.Post(ts.URL+"/api/v1/screenshots/s", ct, mp)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 hash mismatch; got %d", resp.StatusCode)
	}
}

func TestPostScreenshotsDeduplicates(t *testing.T) {
	ts, objs := uploadServer(t)
	body := []byte("identical bytes")

	mp, ct, _ := buildMultipart(t, 80, "HTTP", body, true)
	if r, _ := http.Post(ts.URL+"/api/v1/screenshots/s1", ct, mp); r != nil {
		_ = r.Body.Close()
	}
	mp, ct, _ = buildMultipart(t, 80, "HTTP", body, true)
	if r, _ := http.Post(ts.URL+"/api/v1/screenshots/s2", ct, mp); r != nil {
		_ = r.Body.Close()
	}
	if got := objs.Len(); got != 1 {
		t.Fatalf("expected 1 stored object after two identical uploads; got %d", got)
	}
}
