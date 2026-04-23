package scanner

import (
	"strings"
	"testing"

	"github.com/thenickstrick/go-natlas/internal/protocol"
)

// Representative nmap 7.9x output for a /32 with one open port. Trimmed to
// just the elements we parse; unknown elements are silently ignored.
const fixtureHostUp = `<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -oX - 127.0.0.1" start="1714070000" version="7.94" xmloutputversion="1.05">
  <host starttime="1714070001" endtime="1714070005">
    <status state="up" reason="syn-ack" reason_ttl="0"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <hostnames>
      <hostname name="localhost" type="PTR"/>
    </hostnames>
    <ports>
      <extraports state="closed" count="999"/>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack" reason_ttl="64"/>
        <service name="ssh" product="OpenSSH" version="9.6" ostype="Linux" method="probed" conf="10" extrainfo="protocol 2.0">
          <cpe>cpe:/a:openbsd:openssh:9.6</cpe>
          <cpe>cpe:/o:linux:linux_kernel</cpe>
        </service>
        <script id="ssh-auth-methods" output="  Supported authentication methods:&#10;    publickey"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack" reason_ttl="64"/>
        <service name="http" product="nginx" version="1.26.0" method="probed" conf="10"/>
      </port>
      <port protocol="tcp" portid="3306">
        <state state="filtered" reason="no-response" reason_ttl="0"/>
      </port>
    </ports>
  </host>
  <runstats>
    <finished time="1714070005" timestr="Wed Apr 23 10:30:05 2026" elapsed="4.23" summary="Nmap done" exit="success"/>
    <hosts up="1" down="0" total="1"/>
  </runstats>
</nmaprun>`

const fixtureHostDown = `<?xml version="1.0"?>
<nmaprun>
  <host starttime="1" endtime="2">
    <status state="down" reason="no-response"/>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports/>
  </host>
  <runstats>
    <finished time="2" elapsed="1.0"/>
    <hosts up="0" down="1" total="1"/>
  </runstats>
</nmaprun>`

func TestParseXMLHostUp(t *testing.T) {
	r, err := ParseXML([]byte(fixtureHostUp), "127.0.0.1")
	if err != nil {
		t.Fatalf("ParseXML: %v", err)
	}
	if r.Target != "127.0.0.1" {
		t.Fatalf("Target: got %q, want 127.0.0.1", r.Target)
	}
	if !r.IsUp {
		t.Fatalf("IsUp: expected true")
	}
	if r.Hostname != "localhost" {
		t.Fatalf("Hostname: got %q, want localhost", r.Hostname)
	}
	// Only "open" ports survive the filter.
	if r.PortCount != 2 {
		t.Fatalf("PortCount: got %d, want 2 (filtered 3306 should be dropped)", r.PortCount)
	}
	if r.PortStr != "22, 80" {
		t.Fatalf("PortStr: got %q, want \"22, 80\"", r.PortStr)
	}
	if r.ElapsedS != 4 {
		t.Fatalf("ElapsedS: got %d, want 4", r.ElapsedS)
	}

	// Spot-check the first port's service detail + scripts.
	p := r.Ports[0]
	if p.ID != "22/tcp" || p.Number != 22 || p.Protocol != "tcp" || p.State != "open" {
		t.Fatalf("port 22 shape: %+v", p)
	}
	if p.Service.Name != "ssh" || p.Service.Product != "OpenSSH" || p.Service.Version != "9.6" {
		t.Fatalf("port 22 service: %+v", p.Service)
	}
	if !strings.Contains(p.Service.CPEList, "cpe:/a:openbsd:openssh:9.6") {
		t.Fatalf("CPEs missing: %q", p.Service.CPEList)
	}
	if len(p.Scripts) != 1 || p.Scripts[0].ID != "ssh-auth-methods" {
		t.Fatalf("port 22 scripts: %+v", p.Scripts)
	}
}

func TestParseXMLHostDown(t *testing.T) {
	r, err := ParseXML([]byte(fixtureHostDown), "10.0.0.1")
	if err != nil {
		t.Fatalf("ParseXML: %v", err)
	}
	if r.IsUp {
		t.Fatalf("IsUp: expected false")
	}
	if r.PortCount != 0 || len(r.Ports) != 0 {
		t.Fatalf("expected no ports, got %+v", r.Ports)
	}
	if r.ElapsedS != 1 {
		t.Fatalf("ElapsedS: got %d, want 1", r.ElapsedS)
	}
}

func TestParseXMLEmptyHosts(t *testing.T) {
	r, err := ParseXML([]byte(`<?xml version="1.0"?><nmaprun><runstats/></nmaprun>`), "1.2.3.4")
	if err != nil {
		t.Fatalf("ParseXML: %v", err)
	}
	if r.Target != "1.2.3.4" {
		t.Fatalf("Target fallback: got %q, want 1.2.3.4", r.Target)
	}
	if r.IsUp || r.PortCount != 0 {
		t.Fatalf("expected host-down zero result, got %+v", r)
	}
}

func TestCommandArgsBuilds(t *testing.T) {
	cfg := &protocol.AgentConfig{
		VersionDetection: true,
		OsDetection:      true,
		OsScanLimit:      true,
		NoPing:           false,
		OnlyOpens:        true,
		EnableScripts:    true,
		ScriptTimeoutS:   30,
		HostTimeoutS:     300,
		ScanTimeoutS:     600,
		Scripts:          []string{"default", "ssl-cert"},
	}
	args := CommandArgs(cfg, "/etc/natlas/services", "/tmp/scan/out", "192.0.2.1")

	joined := strings.Join(args, " ")
	for _, want := range []string{
		"-oA /tmp/scan/out",
		"--servicedb /etc/natlas/services",
		"-sV",
		"-O",
		"--osscan-limit",
		"--open",
		"--script=default,ssl-cert",
		"--script-timeout=30s",
		"--host-timeout=300s",
		"192.0.2.1",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("args missing %q; got:\n  %s", want, joined)
		}
	}
	if strings.Contains(joined, "-Pn") {
		t.Errorf("NoPing=false should not produce -Pn; got: %s", joined)
	}
	if strings.Contains(joined, "-6") {
		t.Errorf("IPv4 target should not produce -6; got: %s", joined)
	}
	// Target must be last (nmap positional).
	if args[len(args)-1] != "192.0.2.1" {
		t.Errorf("target should be last arg; got: %v", args)
	}
}

func TestCommandArgsIPv6(t *testing.T) {
	cfg := &protocol.AgentConfig{}
	args := CommandArgs(cfg, "", "/tmp/out", "2001:db8::1")
	if !strings.Contains(strings.Join(args, " "), "-6") {
		t.Errorf("IPv6 target should add -6; got: %v", args)
	}
}
