package search

import (
	"time"

	"github.com/thenickstrick/go-natlas/internal/protocol"
)

// FromResult converts a wire-format protocol.Result into the indexable
// Document. Ctime defaults to "now" if not set on the result; we want the
// indexer to always have a timestamp for sort/order.
func FromResult(r *protocol.Result) Document {
	if r == nil {
		return Document{}
	}
	doc := Document{
		Ctime:        time.Now().UTC(),
		Agent:        r.Agent,
		AgentID:      r.Agent,
		AgentVersion: r.AgentVersion,
		ScanID:       r.ScanID,
		ScanReason:   r.ScanReason,
		ScanStart:    r.ScanStart,
		ScanStop:     r.ScanStop,
		ElapsedS:     r.ElapsedS,
		Tags:         append([]string(nil), r.Tags...),
		IP:           r.Target,
		Hostname:     r.Hostname,
		IsUp:         r.IsUp,
		TimedOut:     r.TimedOut,
		PortCount:    r.PortCount,
		PortStr:      r.PortStr,
		NmapData:     r.NmapData,
		XMLData:      r.XMLData,
		GNmapData:    r.GNmapData,
	}
	if len(r.Ports) > 0 {
		doc.Ports = make([]Port, len(r.Ports))
		for i, p := range r.Ports {
			doc.Ports[i] = Port{
				ID:       p.ID,
				Number:   p.Number,
				Protocol: p.Protocol,
				State:    p.State,
				Reason:   p.Reason,
				Banner:   p.Banner,
				Service: Service{
					Name:      p.Service.Name,
					Product:   p.Service.Product,
					Version:   p.Service.Version,
					OSType:    p.Service.OSType,
					Conf:      p.Service.Conf,
					CPEList:   p.Service.CPEList,
					Method:    p.Service.Method,
					ExtraInfo: p.Service.ExtraInfo,
					Tunnel:    p.Service.Tunnel,
				},
			}
			if len(p.Scripts) > 0 {
				doc.Ports[i].Scripts = make([]Script, len(p.Scripts))
				for j, s := range p.Scripts {
					doc.Ports[i].Scripts[j] = Script{ID: s.ID, Output: s.Output}
				}
			}
		}
	}
	return doc
}
