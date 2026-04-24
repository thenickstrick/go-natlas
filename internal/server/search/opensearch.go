package search

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/opensearch-project/opensearch-go/v4"
)

// osClient is the Searcher implementation backed by OpenSearch.
//
// We deliberately use the low-level *opensearch.Client.Perform path rather
// than the typed opensearchapi v4 surface. Two reasons:
//   - The typed surface is still stabilizing across v4 patch releases; raw
//     HTTP keeps us insulated from churn.
//   - Every call we make is one of: index a document, get a document by id,
//     delete a document, or run a search query — small enough that hand-rolled
//     request building is shorter than wiring through a generated client.
type osClient struct {
	c *opensearch.Client
}

// New returns a Searcher backed by the given OpenSearch client. Callers must
// have already invoked Bootstrap to ensure the indices exist.
func New(c *opensearch.Client) Searcher {
	return &osClient{c: c}
}

// -----------------------------------------------------------------------------
// IndexResult: write to both indices
// -----------------------------------------------------------------------------

// IndexResult writes the document to history (auto-id append) and the latest
// index (overwrite by IP). The history write happens first; if it fails we
// don't touch latest, so a retried submission won't leave the latest pointing
// at a doc that no longer exists in history.
func (s *osClient) IndexResult(ctx context.Context, doc Document) error {
	if doc.IP == "" {
		return errors.New("search: document IP is required")
	}
	if doc.ScanID == "" {
		return errors.New("search: document ScanID is required")
	}
	if doc.Ctime.IsZero() {
		doc.Ctime = time.Now().UTC()
	}
	body, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("search: marshal: %w", err)
	}

	// 1. Append to history.
	if _, err := s.indexAuto(ctx, IndexHistory, body); err != nil {
		return fmt.Errorf("search: index history: %w", err)
	}
	// 2. Overwrite latest by IP.
	if err := s.indexByID(ctx, IndexLatest, doc.IP, body); err != nil {
		return fmt.Errorf("search: index latest: %w", err)
	}
	return nil
}

func (s *osClient) indexByID(ctx context.Context, index, id string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut,
		"/"+index+"/_doc/"+url.PathEscape(id), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.c.Perform(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("PUT /%s/_doc/%s: status %d: %s", index, id, resp.StatusCode, string(raw))
	}
	return nil
}

func (s *osClient) indexAuto(ctx context.Context, index string, body []byte) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"/"+index+"/_doc", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.c.Perform(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("POST /%s/_doc: status %d: %s", index, resp.StatusCode, string(raw))
	}
	var out struct {
		ID string `json:"_id"`
	}
	_ = json.Unmarshal(raw, &out)
	return out.ID, nil
}

// -----------------------------------------------------------------------------
// Reads
// -----------------------------------------------------------------------------

// GetLatest returns the latest scan for ip. ErrNotFound if the host has never
// been scanned.
func (s *osClient) GetLatest(ctx context.Context, ip netip.Addr) (Document, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"/"+IndexLatest+"/_doc/"+url.PathEscape(ip.String()), nil)
	if err != nil {
		return Document{}, err
	}
	resp, err := s.c.Perform(req)
	if err != nil {
		return Document{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return Document{}, ErrNotFound
	}
	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(resp.Body)
		return Document{}, fmt.Errorf("GET %s/_doc/%s: status %d: %s",
			IndexLatest, ip, resp.StatusCode, string(raw))
	}
	var out struct {
		Found  bool     `json:"found"`
		Source Document `json:"_source"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return Document{}, fmt.Errorf("decode get response: %w", err)
	}
	if !out.Found {
		return Document{}, ErrNotFound
	}
	return out.Source, nil
}

// GetHistory returns up to limit history entries for ip, sorted by ctime desc.
func (s *osClient) GetHistory(ctx context.Context, ip netip.Addr, limit, offset int) (Page, error) {
	if limit <= 0 {
		limit = 20
	}
	body, _ := json.Marshal(map[string]any{
		"size": limit,
		"from": offset,
		"sort": []any{map[string]any{"ctime": map[string]string{"order": "desc"}}},
		"track_total_hits": true,
		"query": map[string]any{
			"term": map[string]any{"ip": ip.String()},
		},
	})
	return s.searchRaw(ctx, []string{IndexHistory}, body)
}

// GetScanByID returns the single history doc with the given scan_id.
func (s *osClient) GetScanByID(ctx context.Context, scanID string) (Document, error) {
	body, _ := json.Marshal(map[string]any{
		"size":  1,
		"query": map[string]any{"term": map[string]any{"scan_id": scanID}},
	})
	page, err := s.searchRaw(ctx, []string{IndexHistory}, body)
	if err != nil {
		return Document{}, err
	}
	if len(page.Hits) == 0 {
		return Document{}, ErrNotFound
	}
	return page.Hits[0], nil
}

// Search runs a query_string query against nmap_data with is_up=true and
// port_count>0 filters baked in. Empty Query matches everything in scope.
func (s *osClient) Search(ctx context.Context, opts SearchOpts) (Page, error) {
	if opts.Limit <= 0 {
		opts.Limit = 20
	}
	must := []any{
		map[string]any{"term": map[string]any{"is_up": true}},
		map[string]any{"range": map[string]any{"port_count": map[string]any{"gt": 0}}},
	}
	if q := opts.Query; q != "" {
		must = append(must, map[string]any{
			"query_string": map[string]any{
				"query":            q,
				"default_field":    "nmap_data",
				"default_operator": "AND",
			},
		})
	}
	body, _ := json.Marshal(map[string]any{
		"size": opts.Limit,
		"from": opts.Offset,
		"sort": []any{map[string]any{"ctime": map[string]string{"order": "desc"}}},
		"track_total_hits": true,
		"query": map[string]any{
			"bool": map[string]any{"must": must},
		},
	})
	idx := IndexLatest
	if opts.History {
		idx = IndexHistory
	}
	return s.searchRaw(ctx, []string{idx}, body)
}

// CountSince returns the number of history entries with scan_start >= since.
func (s *osClient) CountSince(ctx context.Context, since time.Time) (int64, error) {
	body, _ := json.Marshal(map[string]any{
		"query": map[string]any{
			"range": map[string]any{
				"scan_start": map[string]any{"gte": since.UTC().Format(time.RFC3339)},
			},
		},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"/"+IndexHistory+"/_count", bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.c.Perform(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return 0, fmt.Errorf("POST /%s/_count: status %d: %s", IndexHistory, resp.StatusCode, string(raw))
	}
	var out struct {
		Count int64 `json:"count"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return 0, fmt.Errorf("decode _count response: %w", err)
	}
	return out.Count, nil
}

// RandomHost returns a random up host from the latest index. Implementation
// uses function_score with random_score, which is O(N) on the segment but
// trivially fast at any reasonable scope size.
func (s *osClient) RandomHost(ctx context.Context) (Document, error) {
	body, _ := json.Marshal(map[string]any{
		"size": 1,
		"query": map[string]any{
			"function_score": map[string]any{
				"query": map[string]any{
					"bool": map[string]any{
						"must": []any{
							map[string]any{"term": map[string]any{"is_up": true}},
							map[string]any{"range": map[string]any{"port_count": map[string]any{"gt": 0}}},
						},
					},
				},
				"random_score": map[string]any{"seed": time.Now().UnixNano(), "field": "_seq_no"},
			},
		},
	})
	page, err := s.searchRaw(ctx, []string{IndexLatest}, body)
	if err != nil {
		return Document{}, err
	}
	if len(page.Hits) == 0 {
		return Document{}, ErrNotFound
	}
	return page.Hits[0], nil
}

// -----------------------------------------------------------------------------
// Delete-with-promotion
// -----------------------------------------------------------------------------

// DeleteScan removes the given scan_id from history; if it was the document
// currently in the latest index for that IP, the next-most-recent history
// entry is promoted into latest. If no other history exists, latest is
// deleted too. ErrNotFound if scan_id doesn't exist.
func (s *osClient) DeleteScan(ctx context.Context, scanID string) error {
	doc, err := s.GetScanByID(ctx, scanID)
	if err != nil {
		return err
	}

	// Step 1: delete from history. We use delete_by_query because we don't
	// store the history doc's _id alongside its scan_id (auto-id index).
	{
		body, _ := json.Marshal(map[string]any{
			"query": map[string]any{"term": map[string]any{"scan_id": scanID}},
		})
		req, err := http.NewRequestWithContext(ctx, http.MethodPost,
			"/"+IndexHistory+"/_delete_by_query?refresh=true", bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := s.c.Perform(req)
		if err != nil {
			return fmt.Errorf("delete history: %w", err)
		}
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode >= 400 {
			return fmt.Errorf("delete history: status %d: %s", resp.StatusCode, string(raw))
		}
	}

	// Step 2: check whether the doc in latest had this scan_id.
	latest, err := s.GetLatest(ctx, mustParseAddr(doc.IP))
	switch {
	case errors.Is(err, ErrNotFound):
		return nil // Nothing to promote, latest is already gone.
	case err != nil:
		return fmt.Errorf("delete: probe latest: %w", err)
	}
	if latest.ScanID != scanID {
		// Latest was a different scan; nothing to do.
		return nil
	}

	// Step 3: find the next-most-recent history entry for this IP.
	page, err := s.GetHistory(ctx, mustParseAddr(doc.IP), 1, 0)
	if err != nil {
		return fmt.Errorf("delete: probe history for promotion: %w", err)
	}
	if len(page.Hits) == 0 {
		// No other history; remove latest.
		return s.deleteLatestByIP(ctx, doc.IP)
	}
	// Promote: re-index the next-most-recent into the latest slot.
	body, _ := json.Marshal(page.Hits[0])
	if err := s.indexByID(ctx, IndexLatest, doc.IP, body); err != nil {
		return fmt.Errorf("delete: promote: %w", err)
	}
	return nil
}

func (s *osClient) deleteLatestByIP(ctx context.Context, ip string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete,
		"/"+IndexLatest+"/_doc/"+url.PathEscape(ip), nil)
	if err != nil {
		return err
	}
	resp, err := s.c.Perform(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("DELETE /%s/_doc/%s: status %d: %s", IndexLatest, ip, resp.StatusCode, string(raw))
	}
	return nil
}

// Refresh forces a refresh on both natlas indices. Used by tests; production
// code should rely on the default 1s refresh interval.
func (s *osClient) Refresh(ctx context.Context) error {
	for _, name := range []string{IndexLatest, IndexHistory} {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "/"+name+"/_refresh", nil)
		if err != nil {
			return err
		}
		resp, err := s.c.Perform(req)
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
	}
	return nil
}

// -----------------------------------------------------------------------------
// Internals
// -----------------------------------------------------------------------------

// searchRaw is the shared body of every read query: POSTs the JSON body to
// the right index's _search endpoint and decodes hits + total.
func (s *osClient) searchRaw(ctx context.Context, indices []string, body []byte) (Page, error) {
	path := "/" + strings.Join(indices, ",") + "/_search"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, path, bytes.NewReader(body))
	if err != nil {
		return Page{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.c.Perform(req)
	if err != nil {
		return Page{}, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return Page{}, fmt.Errorf("POST %s: status %d: %s", path, resp.StatusCode, string(raw))
	}
	var out struct {
		Hits struct {
			Total struct {
				Value int64 `json:"value"`
			} `json:"total"`
			Hits []struct {
				Source Document `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return Page{}, fmt.Errorf("decode search response: %w", err)
	}
	page := Page{Total: out.Hits.Total.Value, Hits: make([]Document, len(out.Hits.Hits))}
	for i, h := range out.Hits.Hits {
		page.Hits[i] = h.Source
	}
	return page, nil
}

// mustParseAddr is internal-only; the only callers feed it values that came
// out of OpenSearch's `ip` field, which OpenSearch already validated.
func mustParseAddr(s string) netip.Addr {
	a, _ := netip.ParseAddr(s)
	return a
}
