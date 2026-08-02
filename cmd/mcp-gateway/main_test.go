package main

import (
	"crypto/sha256"
	"testing"

	"github.com/apraba05/mcp-gateway/internal/config"
)

func TestGatewayAPIKeysPreservesIdentifiersAndHashes(t *testing.T) {
	t.Parallel()

	digest := sha256.Sum256([]byte("fixture-key"))
	got := gatewayAPIKeys([]config.APIKey{{ID: "client-a", SHA256: digest}})
	if len(got) != 1 || got[0].ID != "client-a" || got[0].SHA256 != digest {
		t.Fatalf("gateway keys = %#v", got)
	}
}
