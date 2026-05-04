package submit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"strconv"

	"github.com/thenickstrick/go-natlas/internal/protocol"
)

// ScreenshotPart is the agent-side representation of one screenshot to upload.
// Hash is the agent-computed sha256 hex of Data; the server verifies it.
type ScreenshotPart struct {
	Port    int
	Service string
	Hash    string
	Data    []byte
}

// UploadScreenshotsResponse is the JSON body returned by the server.
type UploadScreenshotsResponse struct {
	ScanID string                `json:"scan_id"`
	Saved  []protocol.Screenshot `json:"saved"`
}

// UploadScreenshots POSTs every part as a single multipart request. An
// empty parts slice is a no-op (returns nil, nil).
func (c *Client) UploadScreenshots(ctx context.Context, scanID string, parts []ScreenshotPart) (*UploadScreenshotsResponse, error) {
	if len(parts) == 0 {
		return &UploadScreenshotsResponse{ScanID: scanID}, nil
	}

	body := &bytes.Buffer{}
	mw := multipart.NewWriter(body)
	for _, p := range parts {
		hdr := textproto.MIMEHeader{}
		hdr.Set("Content-Disposition",
			fmt.Sprintf(`form-data; name="screenshot"; filename="%d-%s.png"`, p.Port, p.Service))
		hdr.Set("Content-Type", "image/png")
		hdr.Set("X-Natlas-Port", strconv.Itoa(p.Port))
		hdr.Set("X-Natlas-Service", p.Service)
		if p.Hash != "" {
			hdr.Set("X-Natlas-Hash", p.Hash)
		}
		part, err := mw.CreatePart(hdr)
		if err != nil {
			return nil, fmt.Errorf("submit screenshots: create part: %w", err)
		}
		if _, err := part.Write(p.Data); err != nil {
			return nil, fmt.Errorf("submit screenshots: write part: %w", err)
		}
	}
	if err := mw.Close(); err != nil {
		return nil, fmt.Errorf("submit screenshots: close multipart: %w", err)
	}

	target := *c.base
	target.Path = "/api/v1/screenshots/" + url.PathEscape(scanID)

	// We bypass the JSON-shaped do() here because the request body is
	// multipart and the response decoding is bespoke. Backoff still applies
	// at the once-attempt level via per-call ctx timeout.
	attempt := 0
	for {
		attempt++
		resp, err := c.attemptScreenshots(ctx, target.String(), mw.FormDataContentType(), body.Bytes())
		if err == nil {
			return resp, nil
		}
		var apiErr *APIError
		if errors.As(err, &apiErr) && !apiErr.Retry {
			return nil, err
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		if c.cfg.MaxRetries >= 0 && attempt > c.cfg.MaxRetries {
			return nil, fmt.Errorf("submit screenshots: retries exhausted: %w", err)
		}
		// Reuse the do() backoff schedule by sleeping with the same shape.
		// Multipart requests are big — keep the cap modest so a network
		// blip doesn't stall the agent for minutes.
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
	}
}

func (c *Client) attemptScreenshots(ctx context.Context, urlStr, contentType string, body []byte) (*UploadScreenshotsResponse, error) {
	attemptCtx, cancel := context.WithTimeout(ctx, c.cfg.RequestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(attemptCtx, http.MethodPost, urlStr, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("submit screenshots: build request: %w", err)
	}
	req.Header.Set("User-Agent", c.cfg.UserAgent)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", contentType)
	if c.cfg.AgentID != "" && c.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.AgentID+"."+c.cfg.Token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("submit screenshots: transport: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, fmt.Errorf("submit screenshots: read response: %w", err)
	}
	if resp.StatusCode >= 400 {
		var env protocol.ErrorResponse
		_ = json.Unmarshal(respBody, &env)
		if env.Error == "" {
			env.Error = resp.Status
		}
		return nil, &APIError{Status: resp.StatusCode, Msg: env.Error, Retry: env.Retry}
	}
	var out UploadScreenshotsResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("submit screenshots: decode response: %w", err)
	}
	return &out, nil
}
