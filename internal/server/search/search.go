// Package search owns the OpenSearch interaction: index bootstrap, the
// indexable Document type, the protocol.Result -> Document transform, and
// the Searcher interface used by HTTP handlers.
//
// The package exposes only domain-shaped types; nothing depending on it
// imports the OpenSearch SDK. That keeps handler code dialect-agnostic and
// lets us swap the backend in tests with a fake.
package search

import (
	"context"
	"errors"
	"net/netip"
	"time"
)

// Index names. Two indices are kept:
//
//   - IndexLatest holds at most one document per IP (doc_id = IP). Overwriting
//     by IP gives O(1) "current state" lookups for the host detail page.
//
//   - IndexHistory is append-only with auto-generated doc IDs. Every scan
//     result lands here for the timeline view + audit trail.
const (
	IndexLatest  = "nmap"
	IndexHistory = "nmap_history"
)

// ErrNotFound is returned when a single-document Get finds nothing matching.
var ErrNotFound = errors.New("search: not found")

// Document is the indexable shape. It mirrors the schema in
// opensearch/mappings/nmap.json field-for-field; tests assert that.
type Document struct {
	// Time the result was indexed (used as @timestamp).
	Ctime time.Time `json:"ctime"`

	// Agent identity + version string.
	Agent        string `json:"agent,omitempty"`
	AgentID      string `json:"agent_id,omitempty"`
	AgentVersion string `json:"agent_version,omitempty"`

	// Per-scan identity.
	ScanID     string    `json:"scan_id"`
	ScanReason string    `json:"scan_reason"`
	ScanStart  time.Time `json:"scan_start"`
	ScanStop   time.Time `json:"scan_stop"`
	ElapsedS   int       `json:"elapsed_s"`
	Tags       []string  `json:"tags,omitempty"`

	// Target identity + status.
	IP       string `json:"ip"`
	Hostname string `json:"hostname,omitempty"`
	IsUp     bool   `json:"is_up"`
	TimedOut bool   `json:"timed_out,omitempty"`

	// Port summary.
	PortCount int    `json:"port_count"`
	PortStr   string `json:"port_str,omitempty"`
	Ports     []Port `json:"ports,omitempty"`

	// Raw nmap blobs.
	NmapData  string `json:"nmap_data,omitempty"`
	XMLData   string `json:"xml_data,omitempty"`
	GNmapData string `json:"gnmap_data,omitempty"`

	// Screenshots are populated in Phase 8.
	Screenshots []Screenshot `json:"screenshots,omitempty"`
}

// Port is the indexed shape of one open port. Keep field names aligned with
// mapping.properties.ports.properties.
type Port struct {
	ID       string   `json:"id"`
	Number   int      `json:"number"`
	Protocol string   `json:"protocol"`
	State    string   `json:"state"`
	Reason   string   `json:"reason,omitempty"`
	Banner   string   `json:"banner,omitempty"`
	Service  Service  `json:"service,omitzero"`
	Scripts  []Script `json:"scripts,omitempty"`
}

// Service mirrors the indexed service block. Empty fields are omitted.
type Service struct {
	Name      string `json:"name,omitempty"`
	Product   string `json:"product,omitempty"`
	Version   string `json:"version,omitempty"`
	OSType    string `json:"ostype,omitempty"`
	Conf      int    `json:"conf,omitempty"`
	CPEList   string `json:"cpelist,omitempty"`
	Method    string `json:"method,omitempty"`
	ExtraInfo string `json:"extrainfo,omitempty"`
	Tunnel    string `json:"tunnel,omitempty"`
}

// Script is a single NSE script's id + output.
type Script struct {
	ID     string `json:"id"`
	Output string `json:"output"`
}

// Screenshot is the metadata for a screenshot stored in the object store.
type Screenshot struct {
	Host      string `json:"host,omitempty"`
	Port      int    `json:"port,omitempty"`
	Service   string `json:"service,omitempty"`
	Hash      string `json:"hash,omitempty"`
	ThumbHash string `json:"thumb_hash,omitempty"`
}

// Page is a paginated list of Documents plus the matching total.
type Page struct {
	Total int64
	Hits  []Document
}

// Searcher is the backend-agnostic contract HTTP handlers use.
//
// IndexResult writes to both the latest (overwrite by IP) and history (append)
// indices. DeleteScan removes one history entry by scan_id; if it was the
// latest copy of that IP, the next-most-recent history entry is promoted into
// the latest index — that's the "delete-with-promotion" behavior natlas has
// always had.
type Searcher interface {
	IndexResult(ctx context.Context, doc Document) error
	GetLatest(ctx context.Context, ip netip.Addr) (Document, error)
	GetHistory(ctx context.Context, ip netip.Addr, limit, offset int) (Page, error)
	GetScanByID(ctx context.Context, scanID string) (Document, error)
	Search(ctx context.Context, opts SearchOpts) (Page, error)
	CountSince(ctx context.Context, since time.Time) (int64, error)
	RandomHost(ctx context.Context) (Document, error)
	DeleteScan(ctx context.Context, scanID string) error

	// Refresh forces a refresh on both indices. Tests use it to make writes
	// immediately searchable; production code should not call this on the
	// hot path.
	Refresh(ctx context.Context) error
}

// SearchOpts controls a query against either the latest or history index.
// Query is interpreted with OpenSearch's query_string syntax against the
// nmap_data field; an empty Query matches every host that's up with at
// least one open port.
type SearchOpts struct {
	Query   string
	History bool // false => latest only; true => full history
	Limit   int
	Offset  int
}
