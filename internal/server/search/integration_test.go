//go:build integration

package search_test

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/opensearch-project/opensearch-go/v4"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/thenickstrick/go-natlas/internal/protocol"
	"github.com/thenickstrick/go-natlas/internal/server/search"
)

// startOpenSearch boots a single-node OpenSearch container with security
// disabled (dev-only) and waits for it to answer /_cluster/health.
//
// The container is shared across test functions in this file via t.Cleanup —
// each test gets its own *opensearch.Client but the container lifecycle is
// tied to the first caller. Cheap enough for a small test set.
func startOpenSearch(t *testing.T) *opensearch.Client {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "opensearchproject/opensearch:3.6.0",
			ExposedPorts: []string{"9200/tcp"},
			Env: map[string]string{
				"discovery.type":                "single-node",
				"plugins.security.disabled":     "true",
				"OPENSEARCH_INITIAL_ADMIN_PASSWORD": "Natlas-Dev-Password-1!",
				"OPENSEARCH_JAVA_OPTS":          "-Xms512m -Xmx512m",
				"bootstrap.memory_lock":         "false",
			},
			WaitingFor: wait.ForHTTP("/_cluster/health").
				WithPort("9200/tcp").
				WithStartupTimeout(2 * time.Minute),
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("start OpenSearch container: %v", err)
	}
	t.Cleanup(func() {
		_ = container.Terminate(context.Background())
	})

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("container host: %v", err)
	}
	port, err := container.MappedPort(ctx, "9200/tcp")
	if err != nil {
		t.Fatalf("container port: %v", err)
	}
	url := fmt.Sprintf("http://%s:%s", host, port.Port())
	t.Logf("OpenSearch URL: %s", url)

	client, err := opensearch.NewClient(opensearch.Config{
		Addresses: []string{url},
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, // #nosec G402
	})
	if err != nil {
		t.Fatalf("opensearch client: %v", err)
	}
	return client
}

func TestIntegrationIndexAndGetLatest(t *testing.T) {
	if os.Getenv("DOCKER_HOST") == "" && os.Getenv("CI") == "" {
		// Best-effort heuristic: skip on machines without docker; testcontainers
		// will give a louder error if docker is missing, but skipping early
		// keeps `go test ./... -tags=integration` clean for laptops.
	}
	client := startOpenSearch(t)
	ctx := context.Background()
	if err := search.Bootstrap(ctx, client); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	s := search.New(client)

	doc := search.FromResult(&protocol.Result{
		ScanID: "scan-1", Target: "10.0.0.1", IsUp: true, PortCount: 1, PortStr: "22",
		ScanReason: protocol.ScanReasonAutomatic, ScanStart: time.Now().Add(-5 * time.Second),
		ScanStop: time.Now(), ElapsedS: 5,
		Ports: []protocol.Port{{ID: "22/tcp", Number: 22, Protocol: "tcp", State: "open",
			Service: protocol.Service{Name: "ssh"}}},
	})
	if err := s.IndexResult(ctx, doc); err != nil {
		t.Fatalf("IndexResult: %v", err)
	}
	if err := s.Refresh(ctx); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	got, err := s.GetLatest(ctx, netip.MustParseAddr("10.0.0.1"))
	if err != nil {
		t.Fatalf("GetLatest: %v", err)
	}
	if got.ScanID != "scan-1" || got.IP != "10.0.0.1" || got.PortCount != 1 {
		t.Fatalf("GetLatest mismatch: %+v", got)
	}
	if len(got.Ports) != 1 || got.Ports[0].Service.Name != "ssh" {
		t.Fatalf("nested ports lost: %+v", got.Ports)
	}

	if _, err := s.GetLatest(ctx, netip.MustParseAddr("10.0.0.99")); !errors.Is(err, search.ErrNotFound) {
		t.Fatalf("GetLatest(missing): got %v, want ErrNotFound", err)
	}
}

func TestIntegrationSearchAndCount(t *testing.T) {
	client := startOpenSearch(t)
	ctx := context.Background()
	if err := search.Bootstrap(ctx, client); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	s := search.New(client)

	for i := 0; i < 3; i++ {
		doc := search.FromResult(&protocol.Result{
			ScanID:     fmt.Sprintf("scan-%d", i),
			Target:     fmt.Sprintf("10.0.0.%d", i+1),
			IsUp:       true,
			PortCount:  1,
			PortStr:    "22",
			ScanReason: protocol.ScanReasonAutomatic,
			ScanStart:  time.Now().Add(-time.Minute),
			ScanStop:   time.Now(),
			ElapsedS:   60,
			NmapData:   "ssh OpenSSH 9.6",
			Ports:      []protocol.Port{{ID: "22/tcp", Number: 22, Protocol: "tcp", State: "open"}},
		})
		if err := s.IndexResult(ctx, doc); err != nil {
			t.Fatalf("IndexResult: %v", err)
		}
	}
	_ = s.Refresh(ctx)

	page, err := s.Search(ctx, search.SearchOpts{Query: "OpenSSH", Limit: 10})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if page.Total != 3 || len(page.Hits) != 3 {
		t.Fatalf("Search hits: got total=%d hits=%d, want 3/3", page.Total, len(page.Hits))
	}

	page, err = s.Search(ctx, search.SearchOpts{Query: "no-such-thing", Limit: 10})
	if err != nil {
		t.Fatalf("Search empty: %v", err)
	}
	if page.Total != 0 {
		t.Fatalf("expected zero hits for nonsense query; got %d", page.Total)
	}

	n, err := s.CountSince(ctx, time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("CountSince: %v", err)
	}
	if n != 3 {
		t.Fatalf("CountSince: got %d, want 3", n)
	}
}

func TestIntegrationDeleteWithPromotion(t *testing.T) {
	client := startOpenSearch(t)
	ctx := context.Background()
	if err := search.Bootstrap(ctx, client); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	s := search.New(client)

	ip := "10.0.0.42"

	// Three sequential scans of the same IP. After all three, latest holds
	// scan-3 (most recent) and history holds 1, 2, 3.
	for i, scanID := range []string{"scan-1", "scan-2", "scan-3"} {
		doc := search.FromResult(&protocol.Result{
			ScanID: scanID, Target: ip, IsUp: true, PortCount: 1, PortStr: "22",
			ScanStart: time.Now().Add(time.Duration(i) * time.Second),
			ScanStop:  time.Now().Add(time.Duration(i)*time.Second + time.Second),
		})
		if err := s.IndexResult(ctx, doc); err != nil {
			t.Fatalf("IndexResult: %v", err)
		}
		// Force a refresh between writes so ctime ordering is stable.
		_ = s.Refresh(ctx)
		time.Sleep(10 * time.Millisecond)
	}

	latest, err := s.GetLatest(ctx, netip.MustParseAddr(ip))
	if err != nil {
		t.Fatalf("GetLatest after 3 scans: %v", err)
	}
	if latest.ScanID != "scan-3" {
		t.Fatalf("latest should be scan-3, got %q", latest.ScanID)
	}

	// Delete the latest. Promotion should bring scan-2 forward.
	if err := s.DeleteScan(ctx, "scan-3"); err != nil {
		t.Fatalf("DeleteScan(scan-3): %v", err)
	}
	_ = s.Refresh(ctx)
	latest, err = s.GetLatest(ctx, netip.MustParseAddr(ip))
	if err != nil {
		t.Fatalf("GetLatest after delete-with-promotion: %v", err)
	}
	if latest.ScanID != "scan-2" {
		t.Fatalf("after delete, latest should be scan-2; got %q", latest.ScanID)
	}

	// Delete a non-latest scan: latest should be unchanged.
	if err := s.DeleteScan(ctx, "scan-1"); err != nil {
		t.Fatalf("DeleteScan(scan-1): %v", err)
	}
	_ = s.Refresh(ctx)
	latest, err = s.GetLatest(ctx, netip.MustParseAddr(ip))
	if err != nil {
		t.Fatalf("GetLatest after deleting non-latest: %v", err)
	}
	if latest.ScanID != "scan-2" {
		t.Fatalf("latest should still be scan-2; got %q", latest.ScanID)
	}

	// Delete the last remaining scan; latest should disappear.
	if err := s.DeleteScan(ctx, "scan-2"); err != nil {
		t.Fatalf("DeleteScan(scan-2): %v", err)
	}
	_ = s.Refresh(ctx)
	if _, err := s.GetLatest(ctx, netip.MustParseAddr(ip)); !errors.Is(err, search.ErrNotFound) {
		t.Fatalf("after final delete, GetLatest should be ErrNotFound; got %v", err)
	}

	// Deleting a missing scan is ErrNotFound.
	if err := s.DeleteScan(ctx, "scan-1"); !errors.Is(err, search.ErrNotFound) {
		t.Fatalf("delete missing scan: got %v, want ErrNotFound", err)
	}
}

// silence unused-import false positive when test code is conditionally compiled.
var _ = strings.Contains
