package main

import (
	"crypto/sha256"
	"testing"
	"time"

	"github.com/apraba05/mcp-gateway/internal/config"
)

func TestGatewayToolPoliciesPreservesClientToolAndEffect(t *testing.T) {
	t.Parallel()

	got := gatewayToolPolicies([]config.ToolPolicy{{ClientID: "client-a", Tool: "search", Allow: true}})
	if len(got) != 1 || got[0].ClientID != "client-a" || got[0].Tool != "search" || !got[0].Allow {
		t.Fatalf("gateway tool policies = %#v", got)
	}
}

func TestGatewayAPIKeysPreservesIdentifiersAndHashes(t *testing.T) {
	t.Parallel()

	digest := sha256.Sum256([]byte("fixture-key"))
	got := gatewayAPIKeys([]config.APIKey{{ID: "client-a", SHA256: digest}})
	if len(got) != 1 || got[0].ID != "client-a" || got[0].SHA256 != digest {
		t.Fatalf("gateway keys = %#v", got)
	}
}

func TestGatewayRateLimitsPreservesClientToolCapacityAndInterval(t *testing.T) {
	t.Parallel()

	got := gatewayRateLimits([]config.RateLimit{{ClientID: "client-a", Tool: "search", Capacity: 7, RefillInterval: 250 * time.Millisecond}})
	if len(got) != 1 || got[0].ClientID != "client-a" || got[0].Tool != "search" || got[0].Capacity != 7 || got[0].RefillInterval != 250*time.Millisecond {
		t.Fatalf("gateway rate limits = %#v", got)
	}
}
