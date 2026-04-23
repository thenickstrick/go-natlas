// Package protocol defines the wire types shared between the natlas-server
// and natlas-agent. Every field carries its canonical JSON tag; both sides
// depend only on this package, which keeps the wire format isolated from any
// backend-specific storage representation.
//
// Versioning: the HTTP routes are already versioned (/api/v1/...), so the
// types here can evolve by adding new optional fields without breaking older
// peers. Removing or renaming a field requires a /v2 bump.
package protocol

import "time"

// -----------------------------------------------------------------------------
// Work dispatch
// -----------------------------------------------------------------------------

// Scan-reason constants used in WorkItem.ScanReason and Result.ScanReason.
const (
	ScanReasonAutomatic = "automatic"
	ScanReasonRequested = "requested"
	ScanReasonManual    = "manual"
)

// WorkItem is what GET /api/v1/work returns: a single target to scan plus the
// configuration the agent should apply while scanning it.
type WorkItem struct {
	ScanID       string      `json:"scan_id"`
	ScanReason   string      `json:"scan_reason"`
	Target       string      `json:"target"` // IPv4 or IPv6 address, canonical form
	Tags         []string    `json:"tags"`
	Type         string      `json:"type"` // always "nmap" for now
	AgentConfig  AgentConfig `json:"agent_config"`
	ServicesHash string      `json:"services_hash"`
}

// AgentConfig is the dispatcher-controlled subset of nmap flags. Field names
// mirror internal/server/data.AgentConfig but use JSON snake_case.
type AgentConfig struct {
	VersionDetection      bool     `json:"version_detection"`
	OsDetection           bool     `json:"os_detection"`
	EnableScripts         bool     `json:"enable_scripts"`
	OnlyOpens             bool     `json:"only_opens"`
	ScanTimeoutS          int      `json:"scan_timeout_s"`
	WebScreenshots        bool     `json:"web_screenshots"`
	VncScreenshots        bool     `json:"vnc_screenshots"`
	WebScreenshotTimeoutS int      `json:"web_screenshot_timeout_s"`
	VncScreenshotTimeoutS int      `json:"vnc_screenshot_timeout_s"`
	ScriptTimeoutS        int      `json:"script_timeout_s"`
	HostTimeoutS          int      `json:"host_timeout_s"`
	OsScanLimit           bool     `json:"os_scan_limit"`
	NoPing                bool     `json:"no_ping"`
	UdpScan               bool     `json:"udp_scan"`
	Scripts               []string `json:"scripts"`
}

// -----------------------------------------------------------------------------
// Results
// -----------------------------------------------------------------------------

// Result is what POST /api/v1/results carries. Screenshots are uploaded in a
// separate multipart request (Phase 8) and are not part of this JSON body.
type Result struct {
	ScanID       string    `json:"scan_id"`
	Target       string    `json:"target"`
	ScanReason   string    `json:"scan_reason"`
	Tags         []string  `json:"tags,omitempty"`
	Agent        string    `json:"agent"`         // agent_id
	AgentVersion string    `json:"agent_version"` // version of the agent binary
	ScanStart    time.Time `json:"scan_start"`
	ScanStop     time.Time `json:"scan_stop"`
	ElapsedS     int       `json:"elapsed_s"`
	IsUp         bool      `json:"is_up"`
	TimedOut     bool      `json:"timed_out,omitempty"`
	Hostname     string    `json:"hostname,omitempty"`
	PortCount    int       `json:"port_count"`
	PortStr      string    `json:"port_str,omitempty"` // "22, 80, 443"
	Ports        []Port    `json:"ports,omitempty"`
	NmapData     string    `json:"nmap_data,omitempty"`
	XMLData      string    `json:"xml_data,omitempty"`
	GNmapData    string    `json:"gnmap_data,omitempty"`
}

// Port describes a single port's scan outcome.
type Port struct {
	ID       string   `json:"id"` // "22/tcp"
	Number   int      `json:"number"`
	Protocol string   `json:"protocol"` // "tcp" | "udp"
	State    string   `json:"state"`    // "open" | "closed" | "filtered" | etc.
	Reason   string   `json:"reason,omitempty"`
	Banner   string   `json:"banner,omitempty"`
	Service  Service  `json:"service,omitzero"`
	Scripts  []Script `json:"scripts,omitempty"`
}

// Service is nmap's service-detection output for a port.
type Service struct {
	Name      string `json:"name,omitempty"`
	Product   string `json:"product,omitempty"`
	Version   string `json:"version,omitempty"`
	OSType    string `json:"ostype,omitempty"`
	Conf      int    `json:"conf,omitempty"`
	CPEList   string `json:"cpelist,omitempty"` // space-joined
	Method    string `json:"method,omitempty"`
	ExtraInfo string `json:"extrainfo,omitempty"`
	Tunnel    string `json:"tunnel,omitempty"`
}

// Script is a single NSE script's output, attached to either a port or a host.
type Script struct {
	ID     string `json:"id"`
	Output string `json:"output"`
}

// -----------------------------------------------------------------------------
// Services distribution
// -----------------------------------------------------------------------------

// Services is the response to GET /api/v1/services: the nmap custom service
// database blob plus its SHA-256. Agents re-fetch when the hash they see in a
// WorkItem differs from what they've cached.
type Services struct {
	SHA256   string `json:"sha256"`
	Services string `json:"services"`
}

// -----------------------------------------------------------------------------
// Error envelope
// -----------------------------------------------------------------------------

// ErrorResponse is the shape of every non-2xx JSON body the agent endpoints
// return. Retry tells the client whether the error is transient.
type ErrorResponse struct {
	Error string `json:"error"`
	Retry bool   `json:"retry"`
}
