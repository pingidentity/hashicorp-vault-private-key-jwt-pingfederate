// These tests cover ping/servers/{name}/jwks: that the response is public
// material only (verified at byte level), that unknown servers return 404,
// that the key set grows from two to three across the first rotation, and
// that the path is registered as unauthenticated.
package pingfederate

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/hashicorp/vault/sdk/logical"
)

// TestJWKS_ReturnsOnlyPublicKeys verifies the JWKS contains only public keys
// via both the parsed jose check and a raw byte scan for private field markers.
func TestJWKS_ReturnsOnlyPublicKeys(t *testing.T) {
	b, s := testBackend(t)
	b.req(t, s, logical.CreateOperation, "servers/prod", map[string]interface{}{
		"ping_url": "https://pingfed.example.com:9031",
	})

	resp := b.req(t, s, logical.ReadOperation, "servers/prod/jwks", nil)
	if resp == nil {
		t.Fatal("expected jwks response")
	}

	raw, ok := resp.Data[logical.HTTPRawBody].([]byte)
	if !ok {
		t.Fatalf("expected raw body []byte, got %T", resp.Data[logical.HTTPRawBody])
	}
	if ct := resp.Data[logical.HTTPContentType]; ct != "application/json" {
		t.Errorf("content type = %v, want application/json", ct)
	}

	var set jose.JSONWebKeySet
	if err := json.Unmarshal(raw, &set); err != nil {
		t.Fatalf("unmarshal jwks: %v", err)
	}
	if len(set.Keys) < 2 {
		t.Fatalf("expected at least current+next keys, got %d", len(set.Keys))
	}
	for i, k := range set.Keys {
		if !k.IsPublic() {
			t.Errorf("jwks key %d is not public", i)
		}
	}

	body := string(raw)
	for _, forbidden := range []string{`"d":`, `"p":`, `"q":`, `"dp":`, `"dq":`, "PRIVATE KEY", "private_key_pkcs8"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("jwks body leaked private material (%q)", forbidden)
		}
	}
}

func TestJWKS_UnknownServer404(t *testing.T) {
	b, s := testBackend(t)
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "servers/ghost/jwks",
		Storage:   s,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected a response")
	}
	if code, _ := resp.Data[logical.HTTPStatusCode].(int); code != 404 {
		if !resp.IsError() {
			t.Errorf("expected error/404 for unknown server, got %v", resp.Data)
		}
	}
}

// TestJWKS_Lifecycle_TwoKeysBeforeRotation_ThreeAfter pins the JWKS shape
// before and after the first rotation.
func TestJWKS_Lifecycle_TwoKeysBeforeRotation_ThreeAfter(t *testing.T) {
	t0 := time.Unix(1700000000, 0)
	b, s := testBackend(t)
	b.now = fixedNow(t0)

	b.req(t, s, logical.CreateOperation, "servers/prod", map[string]interface{}{
		"ping_url": "https://pingfed.example.com:9031",
	})

	readJWKS := func() jose.JSONWebKeySet {
		t.Helper()
		resp := b.req(t, s, logical.ReadOperation, "servers/prod/jwks", nil)
		raw := resp.Data[logical.HTTPRawBody].([]byte)
		var set jose.JSONWebKeySet
		if err := json.Unmarshal(raw, &set); err != nil {
			t.Fatalf("unmarshal jwks: %v", err)
		}
		return set
	}

	before := readJWKS()
	if len(before.Keys) != 2 {
		t.Fatalf("initial JWKS should have 2 keys (current+next), got %d", len(before.Keys))
	}
	initialKids := map[string]bool{}
	for _, k := range before.Keys {
		initialKids[k.KeyID] = true
	}

	b.now = fixedNow(t0.Add(25 * time.Hour))
	if err := b.periodicRotate(context.Background(), &logical.Request{Storage: s}); err != nil {
		t.Fatalf("periodicRotate: %v", err)
	}

	after := readJWKS()
	if len(after.Keys) != 3 {
		t.Fatalf("post-rotation JWKS should have 3 keys, got %d", len(after.Keys))
	}
	carriedOver := 0
	for _, k := range after.Keys {
		if initialKids[k.KeyID] {
			carriedOver++
		}
	}
	if carriedOver != 2 {
		t.Errorf("expected both initial keys to survive rotation as previous+current, got %d", carriedOver)
	}
}

// TestJWKS_IsDeclaredUnauthenticated verifies the JWKS path is registered as
// public while server config paths remain authenticated.
func TestJWKS_IsDeclaredUnauthenticated(t *testing.T) {
	b := newBackend()
	special := b.Backend.PathsSpecial
	if special == nil {
		t.Fatal("no PathsSpecial declared")
	}

	found := false
	for _, p := range special.Unauthenticated {
		if p == "servers/+/jwks" {
			found = true
		}
		if p == "servers/+" || strings.HasPrefix(p, "clients/") {
			t.Errorf("unexpected unauthenticated path %q", p)
		}
	}
	if !found {
		t.Errorf("servers/+/jwks not declared unauthenticated; got %v", special.Unauthenticated)
	}
}
