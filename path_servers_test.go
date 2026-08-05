// These tests cover ping/servers/{name}: store/retrieve, validation,
// trailing-slash normalization, listing, deletion, and the guarantee that
// reading a server never exposes private key material.
package pingfederate

import (
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestServerConfig_StoreAndRetrieve(t *testing.T) {
	b, s := testBackend(t)

	b.req(t, s, logical.CreateOperation, "servers/prod", map[string]interface{}{
		"ping_url": "https://pingfed.example.com:9031",
	})

	resp := b.req(t, s, logical.ReadOperation, "servers/prod", nil)
	if resp == nil {
		t.Fatal("expected read response, got nil")
	}
	if got := resp.Data["ping_url"]; got != "https://pingfed.example.com:9031" {
		t.Errorf("ping_url = %v", got)
	}
	if got := resp.Data["disable_tls_validation"]; got != false {
		t.Errorf("disable_tls_validation = %v, want false", got)
	}
	if got := resp.Data["rotation_period"]; got != int64(86400) {
		t.Errorf("rotation_period = %v, want 86400", got)
	}
	if got := resp.Data["token_endpoint"]; got != "https://pingfed.example.com:9031/as/token.oauth2" {
		t.Errorf("token_endpoint = %v", got)
	}
	if resp.Data["current_key_id"] == "" || resp.Data["current_key_id"] == nil {
		t.Error("expected current_key_id to be set")
	}
}

// TestServerConfig_ReadNeverExposesPrivateKeys verifies the read response
// never leaks the key ring or private-key fields.
func TestServerConfig_ReadNeverExposesPrivateKeys(t *testing.T) {
	b, s := testBackend(t)
	b.req(t, s, logical.CreateOperation, "servers/prod", map[string]interface{}{
		"ping_url": "https://pingfed.example.com:9031",
	})

	resp := b.req(t, s, logical.ReadOperation, "servers/prod", nil)
	for _, k := range []string{"keys", "private_key_pkcs8", "current", "next", "previous"} {
		if _, ok := resp.Data[k]; ok {
			t.Errorf("server read response leaked sensitive field %q", k)
		}
	}
}

func TestServerConfig_DisableTLSValidationSandbox(t *testing.T) {
	b, s := testBackend(t)
	b.req(t, s, logical.CreateOperation, "servers/sandbox", map[string]interface{}{
		"ping_url":               "https://pingfed-sandbox.example.com:9031",
		"disable_tls_validation": true,
	})
	resp := b.req(t, s, logical.ReadOperation, "servers/sandbox", nil)
	if got := resp.Data["disable_tls_validation"]; got != true {
		t.Errorf("disable_tls_validation = %v, want true", got)
	}
}

func TestServerConfig_RequiresPingURL(t *testing.T) {
	b, s := testBackend(t)
	resp := b.req(t, s, logical.CreateOperation, "servers/prod", map[string]interface{}{})
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected error response for missing ping_url, got %v", resp)
	}
}

func TestServerConfig_RejectsLowRotationPeriod(t *testing.T) {
	b, s := testBackend(t)
	resp := b.req(t, s, logical.CreateOperation, "servers/prod", map[string]interface{}{
		"ping_url":        "https://pingfed.example.com:9031",
		"rotation_period": 60,
	})
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected error response for low rotation_period, got %v", resp)
	}
}

func TestServerConfig_RejectsInvalidURL(t *testing.T) {
	b, s := testBackend(t)
	resp := b.req(t, s, logical.CreateOperation, "servers/prod", map[string]interface{}{
		"ping_url": "not-a-url",
	})
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected error response for invalid ping_url, got %v", resp)
	}
}

func TestServerConfig_List(t *testing.T) {
	b, s := testBackend(t)
	for _, name := range []string{"prod", "dev", "sandbox"} {
		b.req(t, s, logical.CreateOperation, "servers/"+name, map[string]interface{}{
			"ping_url": "https://pingfed.example.com:9031",
		})
	}
	resp := b.req(t, s, logical.ListOperation, "servers/", nil)
	keys, _ := resp.Data["keys"].([]string)
	if len(keys) != 3 {
		t.Fatalf("expected 3 servers, got %v", keys)
	}
}

// TestServerConfig_KeysPreservedAcrossUpdate ensures Update does not regenerate keys.
func TestServerConfig_KeysPreservedAcrossUpdate(t *testing.T) {
	b, s := testBackend(t)
	b.req(t, s, logical.CreateOperation, "servers/prod", map[string]interface{}{
		"ping_url": "https://pingfed.example.com:9031",
	})
	before := b.req(t, s, logical.ReadOperation, "servers/prod", nil).Data["current_key_id"]

	b.req(t, s, logical.UpdateOperation, "servers/prod", map[string]interface{}{
		"ping_url": "https://pingfed2.example.com:9031",
	})
	after := b.req(t, s, logical.ReadOperation, "servers/prod", nil).Data["current_key_id"]

	if before != after {
		t.Errorf("current_key_id changed across update: before=%v after=%v", before, after)
	}
}

// TestServerConfig_TrimsTrailingSlash verifies ping_url is canonicalized at
// write time so aud and the token endpoint cannot disagree.
func TestServerConfig_TrimsTrailingSlash(t *testing.T) {
	b, s := testBackend(t)
	b.req(t, s, logical.CreateOperation, "servers/prod", map[string]interface{}{
		"ping_url": "https://pingfed.example.com:9031/",
	})
	resp := b.req(t, s, logical.ReadOperation, "servers/prod", nil)
	if got := resp.Data["ping_url"]; got != "https://pingfed.example.com:9031" {
		t.Errorf("ping_url not trimmed: got %q", got)
	}
	if got := resp.Data["token_endpoint"]; got != "https://pingfed.example.com:9031/as/token.oauth2" {
		t.Errorf("token_endpoint = %q", got)
	}
}

func TestServerConfig_Delete(t *testing.T) {
	b, s := testBackend(t)
	b.req(t, s, logical.CreateOperation, "servers/prod", map[string]interface{}{
		"ping_url": "https://pingfed.example.com:9031",
	})
	b.req(t, s, logical.DeleteOperation, "servers/prod", nil)
	resp := b.req(t, s, logical.ReadOperation, "servers/prod", nil)
	if resp != nil {
		t.Errorf("expected nil response after delete, got %v", resp)
	}
}
