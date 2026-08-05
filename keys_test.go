// These tests cover signing-key generation, the previous/current/next ring,
// the JWKS shape it produces, and the periodic rotator that advances each
// server's keys on schedule.
package pingfederate

import (
	"context"
	"crypto/rsa"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/hashicorp/vault/sdk/logical"
)

func TestKeyRing_InitialHasCurrentAndNext(t *testing.T) {
	ring, err := newKeyRing(time.Unix(1700000000, 0), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if ring.Current == nil || ring.Next == nil {
		t.Fatal("expected current and next keys on creation")
	}
	if ring.Previous != nil {
		t.Error("expected previous to be nil on creation")
	}
	if ring.Current.KeyID == ring.Next.KeyID {
		t.Error("current and next must be distinct keys")
	}
}

// TestKeyRing_PublicKeySet_OnlyPublicMaterial walks every published key and
// verifies it carries only public material with the correct metadata.
func TestKeyRing_PublicKeySet_OnlyPublicMaterial(t *testing.T) {
	ring, _ := newKeyRing(time.Unix(1700000000, 0), 24*time.Hour)
	_ = ring.rotate(time.Unix(1700000000, 0))

	set, err := ring.publicKeySet()
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Keys) != 3 {
		t.Fatalf("expected 3 keys (prev, current, next), got %d", len(set.Keys))
	}
	for i, k := range set.Keys {
		if !k.IsPublic() {
			t.Errorf("key %d is not public", i)
		}
		if _, ok := k.Key.(*rsa.PrivateKey); ok {
			t.Errorf("key %d exposes an *rsa.PrivateKey", i)
		}
		if _, ok := k.Key.(*rsa.PublicKey); !ok {
			t.Errorf("key %d is not *rsa.PublicKey (got %T)", i, k.Key)
		}
		if k.KeyID == "" {
			t.Errorf("key %d missing kid", i)
		}
		if k.Algorithm != string(jose.RS256) {
			t.Errorf("key %d alg = %q, want RS256", i, k.Algorithm)
		}
		if k.Use != "sig" {
			t.Errorf("key %d use = %q, want sig", i, k.Use)
		}
	}
}

func TestKeyRing_Rotate(t *testing.T) {
	t0 := time.Unix(1700000000, 0)
	ring, _ := newKeyRing(t0, 24*time.Hour)

	origCurrent := ring.Current.KeyID
	origNext := ring.Next.KeyID

	t1 := t0.Add(24 * time.Hour)
	if err := ring.rotate(t1); err != nil {
		t.Fatal(err)
	}

	if ring.Previous.KeyID != origCurrent {
		t.Errorf("previous = %q, want old current %q", ring.Previous.KeyID, origCurrent)
	}
	if ring.Current.KeyID != origNext {
		t.Errorf("current = %q, want old next %q", ring.Current.KeyID, origNext)
	}
	if ring.Next.KeyID == origNext || ring.Next.KeyID == origCurrent {
		t.Errorf("next %q should be a brand new key", ring.Next.KeyID)
	}
	if !ring.LastRotated.Equal(t1) {
		t.Errorf("LastRotated = %v, want %v", ring.LastRotated, t1)
	}
}

func TestKeyRing_DueForRotation(t *testing.T) {
	t0 := time.Unix(1700000000, 0)
	ring, _ := newKeyRing(t0, 24*time.Hour)

	if ring.dueForRotation(t0.Add(23 * time.Hour)) {
		t.Error("should not be due before the period elapses")
	}
	if !ring.dueForRotation(t0.Add(24 * time.Hour)) {
		t.Error("should be due once the period elapses")
	}
}

func TestPeriodicRotate_RotatesDueServers(t *testing.T) {
	t0 := time.Unix(1700000000, 0)
	b, s := testBackend(t)
	b.now = fixedNow(t0)

	b.req(t, s, logical.CreateOperation, "servers/prod", map[string]interface{}{
		"ping_url": "https://pingfed.example.com:9031",
	})

	before := b.req(t, s, logical.ReadOperation, "servers/prod", nil).Data["current_key_id"]

	b.now = fixedNow(t0.Add(25 * time.Hour))
	if err := b.periodicRotate(context.Background(), &logical.Request{Storage: s}); err != nil {
		t.Fatalf("periodicRotate: %v", err)
	}

	after := b.req(t, s, logical.ReadOperation, "servers/prod", nil).Data["current_key_id"]
	if before == after {
		t.Error("expected current_key_id to change after rotation")
	}
}
