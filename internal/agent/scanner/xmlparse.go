package scanner

import (
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/thenickstrick/go-natlas/internal/protocol"
)

// The XML types below model the subset of nmap's -oX output we actually index.
// Schema reference: https://nmap.org/book/nmap-dtd.html
//
// Anything we don't care about yet (os fingerprints, traceroute, uptime, times)
// is elided — encoding/xml silently ignores unmapped elements, which is exactly
// what we want.

type nmapRun struct {
	XMLName  xml.Name   `xml:"nmaprun"`
	Args     string     `xml:"args,attr"`
	Start    int64      `xml:"start,attr"`
	Version  string     `xml:"version,attr"`
	Hosts    []xmlHost  `xml:"host"`
	RunStats xmlRunStat `xml:"runstats"`
}

type xmlRunStat struct {
	Finished xmlFinished `xml:"finished"`
	Hosts    xmlHostStat `xml:"hosts"`
}

type xmlFinished struct {
	Time    int64  `xml:"time,attr"`
	Elapsed string `xml:"elapsed,attr"` // string because nmap emits a float
	Summary string `xml:"summary,attr"`
	Exit    string `xml:"exit,attr"`
}

type xmlHostStat struct {
	Up    int `xml:"up,attr"`
	Down  int `xml:"down,attr"`
	Total int `xml:"total,attr"`
}

type xmlHost struct {
	Starttime  int64         `xml:"starttime,attr"`
	Endtime    int64         `xml:"endtime,attr"`
	Status     xmlStatus     `xml:"status"`
	Addresses  []xmlAddress  `xml:"address"`
	Hostnames  xmlHostnames  `xml:"hostnames"`
	Ports      xmlPorts      `xml:"ports"`
	HostScript xmlHostScript `xml:"hostscript"`
}

type xmlStatus struct {
	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr"`
}

type xmlAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type xmlHostnames struct {
	Names []xmlHostname `xml:"hostname"`
}

type xmlHostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

type xmlPorts struct {
	Ports []xmlPort `xml:"port"`
}

type xmlPort struct {
	Protocol string       `xml:"protocol,attr"`
	PortID   int          `xml:"portid,attr"`
	State    xmlPortState `xml:"state"`
	Service  xmlService   `xml:"service"`
	Scripts  []xmlScript  `xml:"script"`
}

type xmlPortState struct {
	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr"`
}

type xmlService struct {
	Name      string   `xml:"name,attr"`
	Product   string   `xml:"product,attr"`
	Version   string   `xml:"version,attr"`
	ExtraInfo string   `xml:"extrainfo,attr"`
	OSType    string   `xml:"ostype,attr"`
	Method    string   `xml:"method,attr"`
	Conf      int      `xml:"conf,attr"`
	Tunnel    string   `xml:"tunnel,attr"`
	CPEs      []string `xml:"cpe"`
}

type xmlScript struct {
	ID     string `xml:"id,attr"`
	Output string `xml:"output,attr"`
}

type xmlHostScript struct {
	Scripts []xmlScript `xml:"script"`
}

// ParseXML parses nmap -oX output and returns a partially-populated
// protocol.Result: target, status, ports, services, scripts, and timing.
// The caller fills in ScanID, Agent, AgentVersion, Tags, ScanReason, and the
// raw .nmap/.gnmap/.xml blobs before submission.
//
// fallbackTarget is used as Target when the XML contains no <address>
// (shouldn't happen for valid nmap runs, but worth a guard).
func ParseXML(data []byte, fallbackTarget string) (*protocol.Result, error) {
	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil, fmt.Errorf("nmap: unmarshal xml: %w", err)
	}

	result := &protocol.Result{
		Target: fallbackTarget,
	}

	if len(run.Hosts) == 0 {
		// Host-down or nmap-level error with no <host> element.
		return result, nil
	}
	if len(run.Hosts) > 1 {
		return nil, fmt.Errorf("nmap: expected single host, got %d", len(run.Hosts))
	}
	h := run.Hosts[0]

	if h.Starttime != 0 {
		result.ScanStart = time.Unix(h.Starttime, 0).UTC()
	}
	if h.Endtime != 0 {
		result.ScanStop = time.Unix(h.Endtime, 0).UTC()
	}
	if !result.ScanStart.IsZero() && !result.ScanStop.IsZero() {
		result.ElapsedS = int(result.ScanStop.Sub(result.ScanStart).Seconds())
	} else if s := run.RunStats.Finished.Elapsed; s != "" {
		if f, err := strconv.ParseFloat(s, 64); err == nil {
			result.ElapsedS = int(f)
		}
	}

	for _, a := range h.Addresses {
		switch a.AddrType {
		case "ipv4", "ipv6":
			result.Target = a.Addr
		}
		// "mac" entries are ignored for now; we may surface them later.
	}
	if len(h.Hostnames.Names) > 0 {
		result.Hostname = h.Hostnames.Names[0].Name
	}
	result.IsUp = h.Status.State == "up"

	if result.IsUp {
		for _, p := range h.Ports.Ports {
			// We deliberately keep only "open" ports — matching the natlas
			// Python behavior + the AgentConfig.OnlyOpens dispatcher default.
			// Callers that want filtered/closed visibility can revisit once
			// the indexer has a use for them.
			if p.State.State != "open" {
				continue
			}
			result.Ports = append(result.Ports, convertPort(p))
		}
	}
	result.PortCount = len(result.Ports)
	result.PortStr = joinPortStr(result.Ports)
	return result, nil
}

func convertPort(p xmlPort) protocol.Port {
	port := protocol.Port{
		ID:       fmt.Sprintf("%d/%s", p.PortID, p.Protocol),
		Number:   p.PortID,
		Protocol: p.Protocol,
		State:    p.State.State,
		Reason:   p.State.Reason,
		Service: protocol.Service{
			Name:      p.Service.Name,
			Product:   p.Service.Product,
			Version:   p.Service.Version,
			OSType:    p.Service.OSType,
			Conf:      p.Service.Conf,
			CPEList:   strings.Join(p.Service.CPEs, " "),
			Method:    p.Service.Method,
			ExtraInfo: p.Service.ExtraInfo,
			Tunnel:    p.Service.Tunnel,
		},
	}
	for _, s := range p.Scripts {
		port.Scripts = append(port.Scripts, protocol.Script{ID: s.ID, Output: s.Output})
	}
	return port
}

// joinPortStr formats a human-readable "22, 80, 443" list, preserving the
// order the ports were seen in (nmap emits them in ascending order).
func joinPortStr(ports []protocol.Port) string {
	if len(ports) == 0 {
		return ""
	}
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = strconv.Itoa(p.Number)
	}
	return strings.Join(parts, ", ")
}
