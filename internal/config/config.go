// Package config loads and validates runtime configuration for the natlas
// server, agent, and admin binaries. Configuration is environment-driven via
// envconfig; callers should invoke LoadServer or LoadAgent at process start
// and treat the returned struct as immutable for the lifetime of the process.
package config

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kelseyhightower/envconfig"
)

// OTel holds OpenTelemetry export settings shared by all binaries.
type OTel struct {
	Enabled  bool   `envconfig:"OTEL_ENABLED" default:"true"`
	Endpoint string `envconfig:"OTEL_EXPORTER_OTLP_ENDPOINT" default:"otel:4317"`
	Insecure bool   `envconfig:"OTEL_EXPORTER_OTLP_INSECURE" default:"true"`
}

// Postgres groups Postgres connection settings. An empty URL means the
// server should fall back to SQLite.
type Postgres struct {
	URL string `envconfig:"POSTGRES_URL"`
}

// SQLite is the single-node fallback for development or small deployments.
type SQLite struct {
	Path string `envconfig:"SQLITE_PATH"`
}

// OpenSearch configures the search/index backend.
type OpenSearch struct {
	URL      string `envconfig:"OPENSEARCH_URL" default:"http://opensearch:9200"`
	Username string `envconfig:"OPENSEARCH_USERNAME" default:"admin"`
	Password string `envconfig:"OPENSEARCH_PASSWORD"`
	Insecure bool   `envconfig:"OPENSEARCH_INSECURE_TLS" default:"false"`
}

// ObjectStore configures an S3-compatible backend (Garage by default).
type ObjectStore struct {
	Endpoint  string `envconfig:"S3_ENDPOINT" default:"garage:3900"`
	Bucket    string `envconfig:"S3_BUCKET" default:"natlas-screenshots"`
	AccessKey string `envconfig:"S3_ACCESS_KEY"`
	SecretKey string `envconfig:"S3_SECRET_KEY"`
	Region    string `envconfig:"S3_REGION" default:"garage"`
	UseTLS    bool   `envconfig:"S3_USE_TLS" default:"false"`
}

// SMTP configures outbound mail for user workflows (invites, password resets).
type SMTP struct {
	Host     string `envconfig:"SMTP_HOST"`
	Port     int    `envconfig:"SMTP_PORT" default:"587"`
	Username string `envconfig:"SMTP_USERNAME"`
	Password string `envconfig:"SMTP_PASSWORD"`
	From     string `envconfig:"SMTP_FROM" default:"noreply@natlas.local"`
	UseTLS   bool   `envconfig:"SMTP_USE_TLS" default:"true"`
}

// Server is the full runtime configuration for the natlas-server binary.
type Server struct {
	HTTPAddr  string `envconfig:"HTTP_ADDR" default:":5001"`
	PublicURL string `envconfig:"PUBLIC_URL" default:"http://localhost:5001"`
	SecretKey string `envconfig:"SECRET_KEY"`
	LogLevel  string `envconfig:"LOG_LEVEL" default:"info"`
	LogFormat string `envconfig:"LOG_FORMAT" default:"json"`

	Postgres    Postgres
	SQLite      SQLite
	OpenSearch  OpenSearch
	ObjectStore ObjectStore
	SMTP        SMTP
	OTel        OTel
}

// Agent is the full runtime configuration for the natlas-agent binary.
type Agent struct {
	ServerURL      string        `envconfig:"NATLAS_SERVER_URL" default:"http://server:5001"`
	AgentID        string        `envconfig:"NATLAS_AGENT_ID"`
	Token          string        `envconfig:"NATLAS_AGENT_TOKEN"`
	MaxWorkers     int           `envconfig:"NATLAS_MAX_WORKERS" default:"3"`
	PollInterval   time.Duration `envconfig:"NATLAS_POLL_INTERVAL" default:"10s"`
	RequestTimeout time.Duration `envconfig:"NATLAS_REQUEST_TIMEOUT" default:"15s"`
	DataDir        string        `envconfig:"NATLAS_DATA_DIR" default:"/data"`
	LogLevel       string        `envconfig:"LOG_LEVEL" default:"info"`
	LogFormat      string        `envconfig:"LOG_FORMAT" default:"json"`

	OTel OTel
}

// LoadServer reads the environment, applies defaults, and validates.
func LoadServer() (*Server, error) {
	var s Server
	if err := envconfig.Process("", &s); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if err := s.validate(); err != nil {
		return nil, err
	}
	return &s, nil
}

// LoadAgent reads the environment, applies defaults, and validates.
func LoadAgent() (*Agent, error) {
	var a Agent
	if err := envconfig.Process("", &a); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if err := a.validate(); err != nil {
		return nil, err
	}
	return &a, nil
}

// Dialect reports the configured relational dialect.
func (s *Server) Dialect() string {
	if s.Postgres.URL != "" {
		return "postgres"
	}
	return "sqlite"
}

func (s *Server) validate() error {
	var problems []string
	if s.Postgres.URL == "" && s.SQLite.Path == "" {
		problems = append(problems, "one of POSTGRES_URL or SQLITE_PATH must be set")
	}
	if s.Postgres.URL != "" && s.SQLite.Path != "" {
		problems = append(problems, "POSTGRES_URL and SQLITE_PATH are mutually exclusive")
	}
	if s.SecretKey == "" {
		problems = append(problems, "SECRET_KEY must be set (use a long, randomly generated value)")
	}
	if s.ObjectStore.AccessKey == "" || s.ObjectStore.SecretKey == "" {
		problems = append(problems, "S3_ACCESS_KEY and S3_SECRET_KEY must both be set")
	}
	if s.OpenSearch.Password == "" {
		problems = append(problems, "OPENSEARCH_PASSWORD must be set")
	}
	return joinProblems(problems)
}

func (a *Agent) validate() error {
	var problems []string
	if a.ServerURL == "" {
		problems = append(problems, "NATLAS_SERVER_URL must be set")
	}
	if a.MaxWorkers < 1 {
		problems = append(problems, "NATLAS_MAX_WORKERS must be >= 1")
	}
	if a.RequestTimeout <= 0 {
		problems = append(problems, "NATLAS_REQUEST_TIMEOUT must be positive")
	}
	return joinProblems(problems)
}

func joinProblems(problems []string) error {
	if len(problems) == 0 {
		return nil
	}
	return errors.New("invalid configuration:\n  - " + strings.Join(problems, "\n  - "))
}
