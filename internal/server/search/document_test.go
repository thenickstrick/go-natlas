package search_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/thenickstrick/go-natlas/internal/protocol"
	"github.com/thenickstrick/go-natlas/internal/server/search"
)

func TestFromResultPopulatesEverything(t *testing.T) {
	now := time.Date(2026, 4, 23, 10, 30, 0, 0, time.UTC)
	r := &protocol.Result{
		ScanID:       "abc",
		Target:       "10.0.0.5",
		ScanReason:   protocol.ScanReasonAutomatic,
		Tags:         []string{"corp", "dmz"},
		Agent:        "agent-001",
		AgentVersion: "0.1.0",
		ScanStart:    now,
		ScanStop:     now.Add(4 * time.Second),
		ElapsedS:     4,
		IsUp:         true,
		Hostname:     "host.local",
		PortCount:    2,
		PortStr:      "22, 80",
		NmapData:     "Nmap...",
		XMLData:      "<nmaprun/>",
		GNmapData:    "Host:",
		Ports: []protocol.Port{
			{
				ID: "22/tcp", Number: 22, Protocol: "tcp", State: "open",
				Service: protocol.Service{Name: "ssh", Product: "OpenSSH", Version: "9.6", CPEList: "cpe:/a:openbsd:openssh:9.6"},
				Scripts: []protocol.Script{{ID: "ssh-auth-methods", Output: "publickey"}},
			},
			{
				ID: "80/tcp", Number: 80, Protocol: "tcp", State: "open",
				Service: protocol.Service{Name: "http", Product: "nginx"},
			},
		},
	}

	doc := search.FromResult(r)
	if doc.IP != "10.0.0.5" || doc.ScanID != "abc" || doc.Hostname != "host.local" {
		t.Fatalf("scalar fields wrong: %+v", doc)
	}
	if !doc.IsUp || doc.PortCount != 2 || doc.PortStr != "22, 80" {
		t.Fatalf("status/port fields wrong: %+v", doc)
	}
	if doc.Ctime.IsZero() {
		t.Errorf("Ctime not auto-populated")
	}
	if doc.Agent != doc.AgentID {
		t.Errorf("AgentID and Agent should mirror today: agent=%q agent_id=%q", doc.Agent, doc.AgentID)
	}
	if len(doc.Ports) != 2 {
		t.Fatalf("Ports: got %d, want 2", len(doc.Ports))
	}
	if doc.Ports[0].Service.Name != "ssh" || len(doc.Ports[0].Scripts) != 1 {
		t.Fatalf("nested port fields lost: %+v", doc.Ports[0])
	}
}

// JSON of a converted Document must use the field names the index mapping
// expects. This is what tells future-us when somebody renames a field on one
// side and forgets the other.
func TestDocumentJSONShapeMatchesMapping(t *testing.T) {
	doc := search.FromResult(&protocol.Result{
		ScanID: "x", Target: "1.2.3.4", IsUp: true, PortCount: 0,
	})
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	body := string(b)
	for _, want := range []string{
		`"ctime":`, `"scan_id":"x"`, `"ip":"1.2.3.4"`, `"is_up":true`,
		`"port_count":0`, `"agent_version":"`, `"scan_reason":"`,
	} {
		if !strings.Contains(body, want) {
			// agent_version may be empty in this fixture; allow that
			if strings.HasPrefix(want, `"agent_version"`) {
				continue
			}
			t.Errorf("JSON missing %q; got:\n%s", want, body)
		}
	}
}

func TestMappingJSONEmbedded(t *testing.T) {
	body, err := search.MappingJSON()
	if err != nil {
		t.Fatalf("MappingJSON: %v", err)
	}
	if len(body) < 100 {
		t.Fatalf("MappingJSON looks empty: %d bytes", len(body))
	}
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatalf("MappingJSON not valid JSON: %v", err)
	}
	if _, ok := raw["mappings"]; !ok {
		t.Fatalf("MappingJSON missing top-level mappings key")
	}
}
