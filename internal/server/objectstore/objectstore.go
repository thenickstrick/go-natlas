// Package objectstore is a backend-agnostic façade over the bytes-by-key
// blob store the server uses for screenshots. Two implementations live here:
//
//   - MinIO: production. Wraps minio-go/v7 against any S3-compatible backend
//     (Garage in dev compose, AWS S3 / SeaweedFS / MinIO elsewhere).
//   - Memory: tests + local-dev. In-process map of key -> bytes.
//
// Handlers depend only on the Client interface so swapping storage backends
// (or unit-testing) requires no plumbing changes upstream.
package objectstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/minio/minio-go/v7"
)

// ErrNotFound is returned by Get / Exists for missing keys. Implementations
// translate backend-specific 404 / NoSuchKey errors into this sentinel so
// callers can switch on errors.Is uniformly.
var ErrNotFound = errors.New("objectstore: not found")

// Client is the contract every handler depends on. Keys are opaque strings
// (use a leading "directory" prefix for organization, e.g. "screenshots/").
type Client interface {
	// Put uploads size bytes from r under key. ContentType becomes the stored
	// object's metadata. Existing objects with the same key are overwritten.
	Put(ctx context.Context, key string, r io.Reader, contentType string, size int64) error

	// Get returns the object body, its content-type, and its byte size.
	// Caller MUST close the body.
	Get(ctx context.Context, key string) (body io.ReadCloser, contentType string, size int64, err error)

	// Exists is a cheap HEAD-style check.
	Exists(ctx context.Context, key string) (bool, error)
}

// -----------------------------------------------------------------------------
// MinIO / S3 implementation
// -----------------------------------------------------------------------------

// MinIO wraps a minio-go client + bucket name. The bucket is presumed to
// exist (app.New verifies this on startup).
type MinIO struct {
	client *minio.Client
	bucket string
}

// NewMinIO returns a Client backed by minio-go.
func NewMinIO(client *minio.Client, bucket string) *MinIO {
	return &MinIO{client: client, bucket: bucket}
}

func (m *MinIO) Put(ctx context.Context, key string, r io.Reader, contentType string, size int64) error {
	_, err := m.client.PutObject(ctx, m.bucket, key, r, size, minio.PutObjectOptions{
		ContentType: contentType,
	})
	return err
}

func (m *MinIO) Get(ctx context.Context, key string) (io.ReadCloser, string, int64, error) {
	obj, err := m.client.GetObject(ctx, m.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, "", 0, err
	}
	stat, err := obj.Stat()
	if err != nil {
		_ = obj.Close()
		var er minio.ErrorResponse
		if errors.As(err, &er) && er.Code == "NoSuchKey" {
			return nil, "", 0, ErrNotFound
		}
		return nil, "", 0, fmt.Errorf("objectstore: stat %q: %w", key, err)
	}
	return obj, stat.ContentType, stat.Size, nil
}

func (m *MinIO) Exists(ctx context.Context, key string) (bool, error) {
	_, err := m.client.StatObject(ctx, m.bucket, key, minio.StatObjectOptions{})
	if err != nil {
		var er minio.ErrorResponse
		if errors.As(err, &er) && er.Code == "NoSuchKey" {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// -----------------------------------------------------------------------------
// In-memory implementation (tests, local dev)
// -----------------------------------------------------------------------------

type memEntry struct {
	body        []byte
	contentType string
}

// Memory is an in-process Client backed by a map. Safe for concurrent use.
// Suitable for tests and ephemeral local dev only.
type Memory struct {
	mu      sync.RWMutex
	objects map[string]memEntry
}

// NewMemory returns an empty Memory store.
func NewMemory() *Memory { return &Memory{objects: map[string]memEntry{}} }

func (m *Memory) Put(_ context.Context, key string, r io.Reader, contentType string, size int64) error {
	body, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	if size > 0 && int64(len(body)) != size {
		return fmt.Errorf("objectstore.Memory: declared size %d != actual %d", size, len(body))
	}
	m.mu.Lock()
	m.objects[key] = memEntry{body: body, contentType: contentType}
	m.mu.Unlock()
	return nil
}

func (m *Memory) Get(_ context.Context, key string) (io.ReadCloser, string, int64, error) {
	m.mu.RLock()
	e, ok := m.objects[key]
	m.mu.RUnlock()
	if !ok {
		return nil, "", 0, ErrNotFound
	}
	return io.NopCloser(bytes.NewReader(e.body)), e.contentType, int64(len(e.body)), nil
}

func (m *Memory) Exists(_ context.Context, key string) (bool, error) {
	m.mu.RLock()
	_, ok := m.objects[key]
	m.mu.RUnlock()
	return ok, nil
}

// Len reports the number of stored objects. Test-only convenience.
func (m *Memory) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.objects)
}
