// These tests cover ping/clients/{server}/{name}: store/retrieve, the
// requirement that the parent server must already exist, and that listing
// clients is scoped to a single server.
package pingfederate

import (
	"reflect"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func mustServer(t *testing.T, b *backend, s logical.Storage, name string) {
	t.Helper()
	b.req(t, s, logical.CreateOperation, "servers/"+name, map[string]interface{}{
		"ping_url": "https://pingfed.example.com:9031",
	})
}

// TestClientConfig_StoreAndRetrieve covers the create-then-read round trip
// and pins TypeKVPairs metadata semantics.
func TestClientConfig_StoreAndRetrieve(t *testing.T) {
	b, s := testBackend(t)
	mustServer(t, b, s, "prod")

	b.req(t, s, logical.CreateOperation, "clients/prod/billing", map[string]interface{}{
		"client_id": "vault-secret-engine",
		"metadata":  []string{"compliance=internal", "usage=billing"},
	})

	resp := b.req(t, s, logical.ReadOperation, "clients/prod/billing", nil)
	if resp == nil {
		t.Fatal("expected client read response")
	}
	if got := resp.Data["client_id"]; got != "vault-secret-engine" {
		t.Errorf("client_id = %v", got)
	}
	md, _ := resp.Data["metadata"].(map[string]string)
	want := map[string]string{"compliance": "internal", "usage": "billing"}
	if !reflect.DeepEqual(md, want) {
		t.Errorf("metadata = %v, want %v", md, want)
	}
}

func TestClientConfig_RequiresExistingServer(t *testing.T) {
	b, s := testBackend(t)
	resp := b.req(t, s, logical.CreateOperation, "clients/ghost/billing", map[string]interface{}{
		"client_id": "vault-secret-engine",
	})
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected error for client on missing server, got %v", resp)
	}
}

func TestClientConfig_RequiresClientID(t *testing.T) {
	b, s := testBackend(t)
	mustServer(t, b, s, "prod")
	resp := b.req(t, s, logical.CreateOperation, "clients/prod/billing", map[string]interface{}{})
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected error for missing client_id, got %v", resp)
	}
}

// TestClientConfig_ListScopedToServer confirms the list is scoped to one
// server and does not expose clients belonging to another.
func TestClientConfig_ListScopedToServer(t *testing.T) {
	b, s := testBackend(t)
	mustServer(t, b, s, "prod")
	mustServer(t, b, s, "dev")

	b.req(t, s, logical.CreateOperation, "clients/prod/billing", map[string]interface{}{"client_id": "a"})
	b.req(t, s, logical.CreateOperation, "clients/prod/pci", map[string]interface{}{"client_id": "b"})
	b.req(t, s, logical.CreateOperation, "clients/dev/test", map[string]interface{}{"client_id": "c"})

	resp := b.req(t, s, logical.ListOperation, "clients/prod/", nil)
	keys, _ := resp.Data["keys"].([]string)
	if len(keys) != 2 {
		t.Fatalf("expected 2 prod clients, got %v", keys)
	}
}

func TestClientConfig_Delete(t *testing.T) {
	b, s := testBackend(t)
	mustServer(t, b, s, "prod")
	b.req(t, s, logical.CreateOperation, "clients/prod/billing", map[string]interface{}{"client_id": "a"})
	b.req(t, s, logical.DeleteOperation, "clients/prod/billing", nil)
	resp := b.req(t, s, logical.ReadOperation, "clients/prod/billing", nil)
	if resp != nil {
		t.Errorf("expected nil after delete, got %v", resp)
	}
}
