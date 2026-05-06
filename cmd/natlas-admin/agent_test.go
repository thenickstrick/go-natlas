package main

import (
	"strings"
	"testing"
)

func TestGenerateAgentCredentialsShape(t *testing.T) {
	id, token, err := generateAgentCredentials()
	if err != nil {
		t.Fatalf("generateAgentCredentials: %v", err)
	}
	if len(id) != 16 {
		t.Errorf("agent id len: got %d, want 16 (hex of 8 random bytes)", len(id))
	}
	for _, c := range id {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("agent id non-hex char %q", c)
		}
	}
	if len(token) != 39 {
		t.Errorf("token len: got %d, want 39 (base32 no-pad of 24 random bytes)", len(token))
	}
	if strings.ContainsRune(token, '.') {
		t.Errorf("token must not contain '.', got %q", token)
	}

	// Two consecutive calls produce different values — vanishingly unlikely
	// to collide if crypto/rand is sane, so this is a smoke test for "did
	// we accidentally hardcode a constant somewhere".
	id2, tok2, err := generateAgentCredentials()
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if id == id2 || token == tok2 {
		t.Fatal("two consecutive credential generations returned identical values")
	}
}
