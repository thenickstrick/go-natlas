package objectstore_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/thenickstrick/go-natlas/internal/server/objectstore"
)

func TestMemoryRoundTrip(t *testing.T) {
	m := objectstore.NewMemory()
	ctx := context.Background()
	body := []byte("png-bytes")

	if err := m.Put(ctx, "screenshots/abc.png", bytes.NewReader(body), "image/png", int64(len(body))); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if m.Len() != 1 {
		t.Fatalf("Len: got %d, want 1", m.Len())
	}

	r, ct, size, err := m.Get(ctx, "screenshots/abc.png")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer r.Close()
	got, _ := io.ReadAll(r)
	if !bytes.Equal(got, body) {
		t.Fatalf("Get body: got %q, want %q", got, body)
	}
	if ct != "image/png" || size != int64(len(body)) {
		t.Fatalf("Get metadata: ct=%q size=%d", ct, size)
	}

	exists, err := m.Exists(ctx, "screenshots/abc.png")
	if err != nil || !exists {
		t.Fatalf("Exists: got %v, %v", exists, err)
	}
	exists, err = m.Exists(ctx, "missing")
	if err != nil || exists {
		t.Fatalf("Exists(missing): got %v, %v", exists, err)
	}

	if _, _, _, err := m.Get(ctx, "missing"); !errors.Is(err, objectstore.ErrNotFound) {
		t.Fatalf("Get(missing): got %v, want ErrNotFound", err)
	}
}

func TestMemorySizeMismatchRejected(t *testing.T) {
	m := objectstore.NewMemory()
	err := m.Put(context.Background(), "k", bytes.NewReader([]byte("abc")), "text/plain", 99)
	if err == nil {
		t.Fatalf("expected size mismatch error")
	}
}
