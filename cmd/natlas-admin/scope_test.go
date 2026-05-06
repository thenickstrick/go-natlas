package main

import (
	"net/netip"
	"strings"
	"testing"
)

func TestParseScopeCSV(t *testing.T) {
	body := `# top-of-file comment
10.0.0.0/24
192.0.2.0/30,1
172.16.0.0/16,0,corp,production
   # indented comment skipped
2001:db8::/120,false,ipv6

`
	rows, err := parseScopeCSV(strings.NewReader(body))
	if err != nil {
		t.Fatalf("parseScopeCSV: %v", err)
	}
	if len(rows) != 4 {
		t.Fatalf("rows: got %d, want 4", len(rows))
	}
	if rows[0].CIDR != "10.0.0.0/24" || rows[0].Blacklist || len(rows[0].Tags) != 0 {
		t.Errorf("row 0 wrong: %+v", rows[0])
	}
	if rows[1].CIDR != "192.0.2.0/30" || !rows[1].Blacklist {
		t.Errorf("row 1 wrong: %+v", rows[1])
	}
	if rows[2].CIDR != "172.16.0.0/16" || rows[2].Blacklist {
		t.Errorf("row 2 cidr/blacklist wrong: %+v", rows[2])
	}
	if len(rows[2].Tags) != 2 || rows[2].Tags[0] != "corp" || rows[2].Tags[1] != "production" {
		t.Errorf("row 2 tags wrong: %+v", rows[2].Tags)
	}
	if rows[3].CIDR != "2001:db8::/120" || rows[3].Blacklist {
		t.Errorf("row 3 wrong: %+v", rows[3])
	}
}

func TestParseScopeCSVErrors(t *testing.T) {
	cases := []struct {
		name, body string
	}{
		{"empty input", ""},
		{"non-bool blacklist", "10.0.0.0/8,maybe"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := parseScopeCSV(strings.NewReader(c.body)); err == nil {
				t.Fatalf("expected error for %q", c.body)
			}
		})
	}
}

func TestLastAddrInPrefix(t *testing.T) {
	cases := []struct {
		prefix, last string
	}{
		{"10.0.0.0/24", "10.0.0.255"},
		{"192.0.2.0/30", "192.0.2.3"},
		{"10.1.2.3/32", "10.1.2.3"},
		{"0.0.0.0/0", "255.255.255.255"},
		{"2001:db8::/120", "2001:db8::ff"},
		{"2001:db8::/127", "2001:db8::1"},
	}
	for _, c := range cases {
		got := lastAddrInPrefix(netip.MustParsePrefix(c.prefix))
		if got.String() != c.last {
			t.Errorf("lastAddrInPrefix(%s): got %s, want %s", c.prefix, got, c.last)
		}
	}
}
