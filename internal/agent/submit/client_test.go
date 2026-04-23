package submit_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/thenickstrick/go-natlas/internal/agent/submit"
	"github.com/thenickstrick/go-natlas/internal/protocol"
)

func TestGetWorkSuccess(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer a.b" {
			t.Errorf("Authorization header: got %q", r.Header.Get("Authorization"))
		}
		_ = json.NewEncoder(w).Encode(protocol.WorkItem{
			ScanID: "abc", Target: "10.0.0.1", ScanReason: protocol.ScanReasonAutomatic, Type: "nmap",
		})
	}))
	defer ts.Close()

	c, err := submit.New(submit.Config{ServerURL: ts.URL, AgentID: "a", Token: "b", RequestTimeout: time.Second})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	w, err := c.GetWork(context.Background(), "")
	if err != nil {
		t.Fatalf("GetWork: %v", err)
	}
	if w.ScanID != "abc" || w.Target != "10.0.0.1" {
		t.Fatalf("decoded wrong: %+v", w)
	}
}

func TestGetWorkNonRetryableDoesNotRetry(t *testing.T) {
	var hits int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(protocol.ErrorResponse{Error: "nope", Retry: false})
	}))
	defer ts.Close()

	c, err := submit.New(submit.Config{
		ServerURL: ts.URL, RequestTimeout: time.Second,
		MaxRetries:  5,
		BackoffBase: time.Millisecond, BackoffCap: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = c.GetWork(context.Background(), "")
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("hits: got %d, want 1 (non-retryable 400 must not retry)", got)
	}
}

func TestGetWorkRetryableRetriesUntilSuccess(t *testing.T) {
	var hits int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		if n < 3 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(protocol.ErrorResponse{Error: "no scope", Retry: true})
			return
		}
		_ = json.NewEncoder(w).Encode(protocol.WorkItem{ScanID: "z", Target: "10.0.0.5"})
	}))
	defer ts.Close()

	c, err := submit.New(submit.Config{
		ServerURL: ts.URL, RequestTimeout: time.Second,
		MaxRetries:  10,
		BackoffBase: time.Millisecond, BackoffCap: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	w, err := c.GetWork(context.Background(), "")
	if err != nil {
		t.Fatalf("GetWork: %v", err)
	}
	if w.ScanID != "z" {
		t.Fatalf("wrong body: %+v", w)
	}
	if got := atomic.LoadInt32(&hits); got != 3 {
		t.Fatalf("hits: got %d, want 3", got)
	}
}

func TestSubmitResultSendsJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("content-type: %q", r.Header.Get("Content-Type"))
		}
		var got protocol.Result
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode: %v", err)
		}
		if got.ScanID != "ss" || got.Target != "10.0.0.9" {
			t.Errorf("decoded %+v", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "accepted"})
	}))
	defer ts.Close()

	c, err := submit.New(submit.Config{ServerURL: ts.URL, RequestTimeout: time.Second})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := c.SubmitResult(context.Background(), &protocol.Result{ScanID: "ss", Target: "10.0.0.9"}); err != nil {
		t.Fatalf("SubmitResult: %v", err)
	}
}
