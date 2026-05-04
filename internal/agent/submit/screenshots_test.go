package submit_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/thenickstrick/go-natlas/internal/agent/submit"
	"github.com/thenickstrick/go-natlas/internal/protocol"
)

// fakeUploadServer parses the incoming multipart and records what it saw,
// then echoes a UploadScreenshotsResponse so we exercise the client decoder.
func fakeUploadServer(t *testing.T) (*httptest.Server, *uploadCapture) {
	t.Helper()
	cap := &uploadCapture{}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/screenshots/", func(w http.ResponseWriter, r *http.Request) {
		_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil {
			http.Error(w, "bad content-type: "+err.Error(), http.StatusBadRequest)
			return
		}
		mr := multipart.NewReader(r.Body, params["boundary"])
		var saved []protocol.Screenshot
		for {
			part, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			body, _ := io.ReadAll(part)
			port, _ := strconv.Atoi(part.Header.Get("X-Natlas-Port"))
			service := part.Header.Get("X-Natlas-Service")
			hash := part.Header.Get("X-Natlas-Hash")
			cap.add(observed{port: port, service: service, hash: hash, len: len(body)})
			saved = append(saved, protocol.Screenshot{Port: port, Service: service, Hash: hash})
		}
		_ = json.NewEncoder(w).Encode(submit.UploadScreenshotsResponse{ScanID: "x", Saved: saved})
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts, cap
}

type observed struct {
	port    int
	service string
	hash    string
	len     int
}

type uploadCapture struct {
	mu    sync.Mutex
	parts []observed
}

func (u *uploadCapture) add(o observed) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.parts = append(u.parts, o)
}

func TestUploadScreenshotsRoundTrip(t *testing.T) {
	ts, cap := fakeUploadServer(t)
	c, err := submit.New(submit.Config{ServerURL: ts.URL, RequestTimeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("submit.New: %v", err)
	}
	body80 := []byte("png-80")
	body443 := []byte("png-443-bigger")
	h80 := sha256.Sum256(body80)
	h443 := sha256.Sum256(body443)

	parts := []submit.ScreenshotPart{
		{Port: 80, Service: "HTTP", Hash: hex.EncodeToString(h80[:]), Data: body80},
		{Port: 443, Service: "HTTPS", Hash: hex.EncodeToString(h443[:]), Data: body443},
	}
	resp, err := c.UploadScreenshots(context.Background(), "scan-A", parts)
	if err != nil {
		t.Fatalf("UploadScreenshots: %v", err)
	}
	if len(resp.Saved) != 2 {
		t.Fatalf("Saved: got %d, want 2", len(resp.Saved))
	}

	cap.mu.Lock()
	defer cap.mu.Unlock()
	if len(cap.parts) != 2 {
		t.Fatalf("server saw %d parts, want 2", len(cap.parts))
	}
	for _, p := range cap.parts {
		if p.hash == "" || p.service == "" || p.len == 0 {
			t.Errorf("missing metadata on %+v", p)
		}
	}
}

func TestUploadScreenshotsEmptyIsNoop(t *testing.T) {
	c, err := submit.New(submit.Config{ServerURL: "http://127.0.0.1:1", RequestTimeout: time.Second})
	if err != nil {
		t.Fatalf("submit.New: %v", err)
	}
	resp, err := c.UploadScreenshots(context.Background(), "x", nil)
	if err != nil {
		t.Fatalf("empty upload should not error: %v", err)
	}
	if resp == nil || resp.ScanID != "x" {
		t.Fatalf("empty upload response shape wrong: %+v", resp)
	}
}
