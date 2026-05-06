package migrate

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/opensearch-project/opensearch-go/v4"
)

// SearchReport summarizes the doc counts produced by MigrateSearch.
type SearchReport struct {
	Latest  int64
	History int64
}

// SearchOptions wraps Elasticsearch source + OpenSearch destination
// connection details. When BatchSize is 0 we default to 500.
type SearchOptions struct {
	SourceURL      string
	SourceUser     string
	SourcePassword string
	SourceInsecure bool

	DestURL      string
	DestUser     string
	DestPassword string
	DestInsecure bool

	BatchSize int
}

// MigrateSearch streams every document from the Python natlas Elasticsearch
// indices (nmap + nmap_history) into the destination OpenSearch indices.
// It scrolls the source in batches of opts.BatchSize and bulk-indexes each
// batch into the destination.
//
// Idempotency: latest docs PUT by IP (source's doc_id is already the IP);
// history docs PUT by scan_id when the doc carries one (covers ~all real
// natlas data) and fall back to the source _id otherwise.
//
// dryRun=true scrolls the source but skips any writes.
func MigrateSearch(ctx context.Context, opts SearchOptions, dryRun bool) (SearchReport, error) {
	if opts.BatchSize <= 0 {
		opts.BatchSize = 500
	}
	src, err := newSearchClient(opts.SourceURL, opts.SourceUser, opts.SourcePassword, opts.SourceInsecure)
	if err != nil {
		return SearchReport{}, fmt.Errorf("source client: %w", err)
	}
	dst, err := newSearchClient(opts.DestURL, opts.DestUser, opts.DestPassword, opts.DestInsecure)
	if err != nil {
		return SearchReport{}, fmt.Errorf("dest client: %w", err)
	}

	var rep SearchReport

	latest, err := reindexOne(ctx, src, dst, "nmap", "nmap", opts.BatchSize, dryRun, func(_ string, src map[string]any) (string, map[string]any) {
		// Source doc_id is already the IP for the latest index, so use the
		// scrolled doc's _id verbatim.
		return src["__id__"].(string), TransformESDocument(src)
	})
	if err != nil {
		return rep, fmt.Errorf("nmap latest: %w", err)
	}
	rep.Latest = latest

	hist, err := reindexOne(ctx, src, dst, "nmap_history", "nmap_history", opts.BatchSize, dryRun, func(srcID string, src map[string]any) (string, map[string]any) {
		// Prefer scan_id as the dest doc_id so re-running migration is
		// idempotent and Searcher.GetScanByID lookups stay O(1) on a known
		// key.  Fall back to the source _id when scan_id is missing.
		if v, ok := src["scan_id"].(string); ok && v != "" {
			return v, TransformESDocument(src)
		}
		return srcID, TransformESDocument(src)
	})
	if err != nil {
		return rep, fmt.Errorf("nmap_history: %w", err)
	}
	rep.History = hist

	return rep, nil
}

// -----------------------------------------------------------------------------
// Internals
// -----------------------------------------------------------------------------

func newSearchClient(addr, user, pass string, insecure bool) (*opensearch.Client, error) {
	cfg := opensearch.Config{
		Addresses: []string{addr},
		Username:  user,
		Password:  pass,
	}
	if insecure {
		cfg.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // #nosec G402 — operator opt-in
		}
	}
	return opensearch.NewClient(cfg)
}

// reindexOne scrolls a single source index and bulk-indexes each batch into
// the destination index. The transform callback receives the source doc_id
// and the parsed _source; it returns the dest doc_id + transformed body.
func reindexOne(
	ctx context.Context,
	src, dst *opensearch.Client,
	srcIndex, dstIndex string,
	batchSize int,
	dryRun bool,
	transform func(srcID string, source map[string]any) (string, map[string]any),
) (int64, error) {
	scrollBody, _ := json.Marshal(map[string]any{
		"size": batchSize,
		"sort": []any{map[string]any{"_doc": map[string]string{"order": "asc"}}},
		"query": map[string]any{"match_all": map[string]any{}},
	})

	scrollID := ""
	defer func() {
		if scrollID != "" {
			body, _ := json.Marshal(map[string]string{"scroll_id": scrollID})
			req, _ := http.NewRequestWithContext(context.Background(), http.MethodDelete, "/_search/scroll", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			if resp, err := src.Perform(req); err == nil {
				_ = resp.Body.Close()
			}
		}
	}()

	var total int64
	first := true

	for {
		var (
			urlPath string
			body    []byte
		)
		if first {
			first = false
			urlPath = "/" + url.PathEscape(srcIndex) + "/_search?scroll=2m"
			body = scrollBody
		} else {
			urlPath = "/_search/scroll"
			b, _ := json.Marshal(map[string]any{
				"scroll":    "2m",
				"scroll_id": scrollID,
			})
			body = b
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, urlPath, bytes.NewReader(body))
		if err != nil {
			return total, err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := src.Perform(req)
		if err != nil {
			return total, fmt.Errorf("scroll: %w", err)
		}
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound {
			// Index doesn't exist on the source — treat as empty + return.
			slog.WarnContext(ctx, "migrate: source index missing, skipping", "index", srcIndex)
			return total, nil
		}
		if resp.StatusCode >= 400 {
			return total, fmt.Errorf("scroll: status %d: %s", resp.StatusCode, string(raw))
		}

		var parsed scrollResponse
		if err := json.Unmarshal(raw, &parsed); err != nil {
			return total, fmt.Errorf("scroll decode: %w", err)
		}
		scrollID = parsed.ScrollID
		if len(parsed.Hits.Hits) == 0 {
			return total, nil
		}

		// Build a single bulk body for the batch.
		var bulk bytes.Buffer
		for _, h := range parsed.Hits.Hits {
			doc := map[string]any{}
			if h.Source != nil {
				if err := json.Unmarshal(h.Source, &doc); err != nil {
					return total, fmt.Errorf("decode hit %s: %w", h.ID, err)
				}
			}
			// Pass the source ID through to the transform via a sentinel key.
			doc["__id__"] = h.ID
			destID, transformed := transform(h.ID, doc)
			delete(transformed, "__id__")

			meta := map[string]any{
				"index": map[string]any{
					"_index": dstIndex,
					"_id":    destID,
				},
			}
			if err := writeBulkLine(&bulk, meta, transformed); err != nil {
				return total, err
			}
			total++
		}

		if !dryRun {
			if err := bulkPost(ctx, dst, bulk.Bytes()); err != nil {
				return total, fmt.Errorf("bulk index: %w", err)
			}
		}
	}
}

type scrollResponse struct {
	ScrollID string `json:"_scroll_id"`
	Hits     struct {
		Total struct {
			Value int64 `json:"value"`
		} `json:"total"`
		Hits []scrollHit `json:"hits"`
	} `json:"hits"`
}

type scrollHit struct {
	ID     string          `json:"_id"`
	Source json.RawMessage `json:"_source"`
}

func writeBulkLine(buf *bytes.Buffer, meta, doc map[string]any) error {
	if err := json.NewEncoder(buf).Encode(meta); err != nil {
		return err
	}
	if err := json.NewEncoder(buf).Encode(doc); err != nil {
		return err
	}
	return nil
}

func bulkPost(ctx context.Context, dst *opensearch.Client, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "/_bulk", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	resp, err := dst.Perform(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return fmt.Errorf("bulk status %d: %s", resp.StatusCode, string(raw))
	}
	// _bulk returns 200 even on per-item failures; surface those individually.
	var parsed struct {
		Errors bool `json:"errors"`
		Items  []map[string]map[string]any `json:"items"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return fmt.Errorf("bulk decode: %w", err)
	}
	if parsed.Errors {
		var failures []string
		for _, item := range parsed.Items {
			for op, body := range item {
				if errObj, ok := body["error"]; ok {
					failures = append(failures, fmt.Sprintf("%s: %v", op, errObj))
				}
			}
			if len(failures) >= 5 {
				break
			}
		}
		return errors.New("bulk had per-item errors: " + joinSample(failures))
	}
	return nil
}

func joinSample(items []string) string {
	if len(items) == 0 {
		return "(none)"
	}
	out := items[0]
	for _, s := range items[1:] {
		out += " | " + s
	}
	return out
}
