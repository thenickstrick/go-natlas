package search

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/opensearch-project/opensearch-go/v4"
)

// mappingFS embeds the canonical index spec. Both indices (latest + history)
// share the same mapping; only their write semantics differ.
//
//go:embed mapping/nmap.json
var mappingFS embed.FS

// MappingJSON returns the embedded mapping document as a byte slice. Useful
// for tests and out-of-band tooling.
func MappingJSON() ([]byte, error) {
	return mappingFS.ReadFile("mapping/nmap.json")
}

// Bootstrap creates IndexLatest and IndexHistory if they don't already exist.
// Existing indices are left in place (mapping drift is logged at WARN; an
// upgrade tool will land alongside the migration story in Phase 10).
func Bootstrap(ctx context.Context, client *opensearch.Client) error {
	body, err := MappingJSON()
	if err != nil {
		return fmt.Errorf("search: read embedded mapping: %w", err)
	}
	for _, name := range []string{IndexLatest, IndexHistory} {
		if err := ensureIndex(ctx, client, name, body); err != nil {
			return fmt.Errorf("search: ensure %s: %w", name, err)
		}
	}
	return nil
}

// ensureIndex creates the index iff it doesn't yet exist. The "exists" probe
// is a HEAD request, which OpenSearch answers in O(ms).
func ensureIndex(ctx context.Context, client *opensearch.Client, name string, mapping []byte) error {
	headReq, err := http.NewRequestWithContext(ctx, http.MethodHead, "/"+name, nil)
	if err != nil {
		return err
	}
	headResp, err := client.Perform(headReq)
	if err != nil {
		return fmt.Errorf("HEAD /%s: %w", name, err)
	}
	_ = headResp.Body.Close()
	switch headResp.StatusCode {
	case http.StatusOK:
		// Already there. Quick mapping-drift sanity check.
		checkMappingDrift(ctx, client, name, mapping)
		return nil
	case http.StatusNotFound:
		// Fall through to create.
	default:
		return fmt.Errorf("HEAD /%s: unexpected status %d", name, headResp.StatusCode)
	}

	putReq, err := http.NewRequestWithContext(ctx, http.MethodPut, "/"+name, bytes.NewReader(mapping))
	if err != nil {
		return err
	}
	putReq.Header.Set("Content-Type", "application/json")
	putResp, err := client.Perform(putReq)
	if err != nil {
		return fmt.Errorf("PUT /%s: %w", name, err)
	}
	defer putResp.Body.Close()
	if putResp.StatusCode >= 400 {
		raw, _ := io.ReadAll(putResp.Body)
		return fmt.Errorf("PUT /%s: status %d: %s", name, putResp.StatusCode, string(raw))
	}
	slog.InfoContext(ctx, "search: created index", "name", name)
	return nil
}

// checkMappingDrift compares the deployed mapping's _meta.natlas_mapping_version
// against the embedded one. Mismatch => log WARN; we don't auto-migrate yet.
func checkMappingDrift(ctx context.Context, client *opensearch.Client, name string, embedded []byte) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "/"+name+"/_mapping", nil)
	if err != nil {
		return
	}
	resp, err := client.Perform(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return
	}
	body, _ := io.ReadAll(resp.Body)
	live := mappingMetaVersion(body, name)
	want := mappingMetaVersion(embedded, "")
	if live == "" || want == "" {
		return
	}
	if live != want {
		slog.WarnContext(ctx, "search: mapping drift detected",
			"index", name, "deployed_version", live, "embedded_version", want,
		)
	}
}

// mappingMetaVersion picks the natlas_mapping_version out of either the
// embedded mapping body (where it sits at mappings._meta.natlas_mapping_version)
// or a GET /<index>/_mapping body (where it's nested under the index name).
func mappingMetaVersion(body []byte, indexName string) string {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return ""
	}
	if indexName != "" {
		// GET /<index>/_mapping wraps everything under the index name.
		inner, ok := raw[indexName]
		if !ok {
			return ""
		}
		var indexBody struct {
			Mappings struct {
				Meta map[string]string `json:"_meta"`
			} `json:"mappings"`
		}
		if err := json.Unmarshal(inner, &indexBody); err != nil {
			return ""
		}
		return indexBody.Mappings.Meta["natlas_mapping_version"]
	}
	var top struct {
		Mappings struct {
			Meta map[string]string `json:"_meta"`
		} `json:"mappings"`
	}
	if err := json.Unmarshal(body, &top); err != nil {
		return ""
	}
	return top.Mappings.Meta["natlas_mapping_version"]
}
