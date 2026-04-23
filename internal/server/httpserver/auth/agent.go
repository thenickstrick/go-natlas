// Package auth holds authentication middleware for natlas-server. Agent
// authentication is covered here; user session handling comes in Phase 6.
package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/thenickstrick/go-natlas/internal/protocol"
	"github.com/thenickstrick/go-natlas/internal/server/data"
)

type agentCtxKey struct{}

// AgentFromContext returns the authenticated agent attached by AgentAuth, or
// (zero, false) if none.
func AgentFromContext(ctx context.Context) (data.Agent, bool) {
	a, ok := ctx.Value(agentCtxKey{}).(data.Agent)
	return a, ok
}

// AgentAuth returns middleware that authenticates agents via
//
//	Authorization: Bearer <agent_id>.<token>
//
// The token is checked against the bcrypt hash stored on the agent row. When
// required is false the middleware is a pass-through; this matches the
// Python server's AGENT_AUTHENTICATION=false dev mode.
func AgentAuth(store data.Store, required bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !required {
				next.ServeHTTP(w, r)
				return
			}
			agent, err := authenticate(r, store)
			if err != nil {
				writeErr(w, http.StatusUnauthorized, err.Error(), false)
				return
			}
			// Best-effort last-seen update; don't block the request on DB lag.
			go func() {
				// Detached context so a cancelled request still records the
				// last-seen touch. A short-lived agent's identity shouldn't
				// churn the DB here — caller bears the cost.
				_ = store.AgentTouchLastSeen(context.Background(), agent.ID)
			}()
			ctx := context.WithValue(r.Context(), agentCtxKey{}, agent)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func authenticate(r *http.Request, store data.Store) (data.Agent, error) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return data.Agent{}, errors.New("missing Authorization header")
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return data.Agent{}, errors.New("Authorization must start with 'Bearer '")
	}
	tok := strings.TrimPrefix(header, prefix)
	// Bearer <agent_id>.<token>. A single dot separates the two halves; the
	// token itself must not contain a dot (tokens are base32/hex-encoded
	// random bytes, so that's enforced by the generator).
	agentID, secret, ok := strings.Cut(tok, ".")
	if !ok || agentID == "" || secret == "" {
		return data.Agent{}, errors.New("malformed bearer token; expected 'agent_id.token'")
	}
	agent, err := store.AgentGetByAgentID(r.Context(), agentID)
	if err != nil {
		// Uniform error for unknown-agent and bad-token to avoid agent-id
		// enumeration.
		return data.Agent{}, errors.New("invalid agent credentials")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(agent.TokenHash), []byte(secret)); err != nil {
		return data.Agent{}, errors.New("invalid agent credentials")
	}
	return agent, nil
}

func writeErr(w http.ResponseWriter, code int, msg string, retry bool) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(protocol.ErrorResponse{Error: msg, Retry: retry})
}
