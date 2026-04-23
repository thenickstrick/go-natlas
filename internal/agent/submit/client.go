// Package submit is the agent's HTTP client to the natlas-server control
// plane. It wraps GET /api/v1/work, POST /api/v1/results, and GET
// /api/v1/services with typed signatures, a shared bearer-token Authorization
// header, and exponential-backoff-with-jitter retry logic that respects
// context cancellation.
package submit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/thenickstrick/go-natlas/internal/protocol"
)

// Config is the minimum the client needs to run. Supply via natlas-agent's
// config package.
type Config struct {
	ServerURL      string        // e.g. "http://server:5001"
	AgentID        string        // empty => no Authorization header
	Token          string        // empty => no Authorization header
	UserAgent      string        // e.g. "natlas-agent/dev"
	RequestTimeout time.Duration // per-attempt timeout (enforced via per-req ctx)
	MaxRetries     int           // 0 => no retry; <0 => unlimited
	BackoffBase    time.Duration // initial backoff
	BackoffCap     time.Duration // maximum backoff
}

// Client is the typed HTTP wrapper. All methods honor the caller's context.
// On transient failure (network error, 5xx, or explicit retry=true body) the
// client retries with exponential backoff + jitter.
type Client struct {
	cfg  Config
	http *http.Client
	base *url.URL
}

// New returns a Client. The underlying *http.Transport is wrapped by
// otelhttp so every outbound request produces a client span.
func New(cfg Config) (*Client, error) {
	if cfg.ServerURL == "" {
		return nil, errors.New("submit: ServerURL is required")
	}
	u, err := url.Parse(cfg.ServerURL)
	if err != nil {
		return nil, fmt.Errorf("submit: parse ServerURL: %w", err)
	}
	if cfg.RequestTimeout <= 0 {
		cfg.RequestTimeout = 15 * time.Second
	}
	if cfg.BackoffBase <= 0 {
		cfg.BackoffBase = 500 * time.Millisecond
	}
	if cfg.BackoffCap <= 0 {
		cfg.BackoffCap = 30 * time.Second
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = "natlas-agent/dev"
	}
	return &Client{
		cfg: cfg,
		http: &http.Client{
			Timeout:   0, // per-attempt timeout enforced via context
			Transport: otelhttp.NewTransport(http.DefaultTransport),
		},
		base: u,
	}, nil
}

// GetWork calls GET /api/v1/work. Pass a non-empty manualTarget to request a
// specific IP; empty means "let the server decide" (auto + rescan queue).
func (c *Client) GetWork(ctx context.Context, manualTarget string) (*protocol.WorkItem, error) {
	path := "/api/v1/work"
	if manualTarget != "" {
		path += "?target=" + url.QueryEscape(manualTarget)
	}
	var work protocol.WorkItem
	if err := c.do(ctx, http.MethodGet, path, nil, &work); err != nil {
		return nil, err
	}
	return &work, nil
}

// SubmitResult POSTs a scan result. Server-side scope re-validation failures
// are returned as non-retryable errors.
func (c *Client) SubmitResult(ctx context.Context, result *protocol.Result) error {
	body, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("submit: marshal result: %w", err)
	}
	return c.do(ctx, http.MethodPost, "/api/v1/results", body, nil)
}

// GetServices fetches the custom nmap service DB + sha256.
func (c *Client) GetServices(ctx context.Context) (*protocol.Services, error) {
	var s protocol.Services
	if err := c.do(ctx, http.MethodGet, "/api/v1/services", nil, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// APIError carries the server's ErrorResponse envelope plus the HTTP status.
type APIError struct {
	Status int
	Msg    string
	Retry  bool
}

func (e *APIError) Error() string { return fmt.Sprintf("server %d: %s", e.Status, e.Msg) }

// do is the shared request helper. It serializes the request, applies retry
// policy, and unmarshals the JSON response body into out (nil to discard).
func (c *Client) do(ctx context.Context, method, path string, body []byte, out any) error {
	target := *c.base
	// Path may carry a query string.
	if i := strings.Index(path, "?"); i >= 0 {
		target.Path = path[:i]
		target.RawQuery = path[i+1:]
	} else {
		target.Path = path
	}

	attempt := 0
	for {
		attempt++
		err := c.once(ctx, method, target.String(), body, out)
		if err == nil {
			return nil
		}
		// Fatal errors don't retry.
		var apiErr *APIError
		if errors.As(err, &apiErr) && !apiErr.Retry {
			return err
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		if c.cfg.MaxRetries >= 0 && attempt > c.cfg.MaxRetries {
			return fmt.Errorf("submit: retries exhausted: %w", err)
		}
		// Backoff with full-jitter: sleep in [0, min(cap, base*2^attempt)).
		sleep := c.cfg.BackoffBase * time.Duration(1<<min(attempt-1, 30))
		if sleep <= 0 || sleep > c.cfg.BackoffCap {
			sleep = c.cfg.BackoffCap
		}
		sleep = time.Duration(rand.Int64N(int64(sleep) + 1))
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(sleep):
		}
	}
}

// once runs a single attempt subject to RequestTimeout.
func (c *Client) once(ctx context.Context, method, urlStr string, body []byte, out any) error {
	attemptCtx, cancel := context.WithTimeout(ctx, c.cfg.RequestTimeout)
	defer cancel()

	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(attemptCtx, method, urlStr, reader)
	if err != nil {
		return fmt.Errorf("submit: build request: %w", err)
	}
	req.Header.Set("User-Agent", c.cfg.UserAgent)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.cfg.AgentID != "" && c.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.AgentID+"."+c.cfg.Token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("submit: transport: %w", err)
	}
	defer resp.Body.Close()

	// Limit response reads to guard against runaway payloads.
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return fmt.Errorf("submit: read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		// Try to decode the standard ErrorResponse envelope; fall back to raw
		// body for servers that don't follow it.
		var env protocol.ErrorResponse
		_ = json.Unmarshal(respBody, &env)
		if env.Error == "" {
			env.Error = strings.TrimSpace(string(respBody))
			if env.Error == "" {
				env.Error = resp.Status
			}
		}
		return &APIError{
			Status: resp.StatusCode,
			Msg:    env.Error,
			// Retry ONLY if the server explicitly says so; default false.
			Retry: env.Retry,
		}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(respBody, out); err != nil {
		return fmt.Errorf("submit: decode response: %w", err)
	}
	return nil
}
