// These tests cover assertion building and signing: required standard claims,
// reserved-claim protection against operator metadata, signature verification
// against the engine's public key, and a unique jti per call.
package pingfederate

import (
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func testKey(t *testing.T) *keyEntry {
	t.Helper()
	k, err := newKeyEntry(time.Unix(1700000000, 0))
	if err != nil {
		t.Fatalf("newKeyEntry: %v", err)
	}
	return k
}

func TestBuildClaims_RequiredStandardClaims(t *testing.T) {
	now := time.Unix(1700000000, 0)
	std, _ := buildClaims(assertionParams{
		clientID: "vault-secret-engine",
		audience: "https://pingfed.example.com:9031",
		ttl:      60 * time.Second,
	}, now, "fixed-jti")

	if std.Issuer != "vault-secret-engine" {
		t.Errorf("iss = %q, want client_id", std.Issuer)
	}
	if std.Subject != "vault-secret-engine" {
		t.Errorf("sub = %q, want client_id", std.Subject)
	}
	if len(std.Audience) != 1 || std.Audience[0] != "https://pingfed.example.com:9031" {
		t.Errorf("aud = %v, want ping base URL", std.Audience)
	}
	if std.ID != "fixed-jti" {
		t.Errorf("jti = %q", std.ID)
	}
	wantExp := now.Add(60 * time.Second)
	if !std.Expiry.Time().Equal(wantExp) {
		t.Errorf("exp = %v, want %v", std.Expiry.Time(), wantExp)
	}
	if std.IssuedAt.Time().After(std.Expiry.Time()) {
		t.Error("iat after exp")
	}
}

// TestBuildClaims_MetadataCannotOverwriteReservedClaims throws every reserved
// name at the metadata channel and verifies none survive into extra claims.
func TestBuildClaims_MetadataCannotOverwriteReservedClaims(t *testing.T) {
	now := time.Unix(1700000000, 0)
	_, extra := buildClaims(assertionParams{
		clientID: "real-client",
		audience: "https://pingfed.example.com:9031",
		ttl:      60 * time.Second,
		extraClaims: map[string]interface{}{
			"iss":         "attacker",
			"sub":         "attacker",
			"aud":         "https://evil.example.com",
			"exp":         1,
			"iat":         1,
			"nbf":         1,
			"jti":         "static",
			"department":  "billing",
			"environment": "prod",
		},
	}, now, "fixed-jti")

	for _, reserved := range []string{"iss", "sub", "aud", "exp", "iat", "nbf", "jti"} {
		if _, present := extra[reserved]; present {
			t.Errorf("reserved claim %q was not stripped from metadata", reserved)
		}
	}
	if extra["department"] != "billing" {
		t.Errorf("department metadata claim missing: %v", extra)
	}
	if extra["environment"] != "prod" {
		t.Errorf("environment metadata claim missing: %v", extra)
	}
}

// TestSignAssertion_VerifiesAndCarriesClaims signs a real assertion and
// verifies it round-trips against the matching public key.
func TestSignAssertion_VerifiesAndCarriesClaims(t *testing.T) {
	key := testKey(t)
	now := time.Unix(1700000000, 0)

	token, err := signAssertion(key, assertionParams{
		clientID: "vault-secret-engine",
		audience: "https://pingfed.example.com:9031",
		ttl:      60 * time.Second,
		extraClaims: map[string]interface{}{
			"department": "billing",
			"iss":        "should-be-ignored",
		},
	}, now)
	if err != nil {
		t.Fatalf("signAssertion: %v", err)
	}

	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatalf("ParseSigned: %v", err)
	}

	priv, _ := key.privateKey()
	var std jwt.Claims
	extra := map[string]interface{}{}
	if err := parsed.Claims(&priv.PublicKey, &std, &extra); err != nil {
		t.Fatalf("Claims verify: %v", err)
	}

	if std.Issuer != "vault-secret-engine" || std.Subject != "vault-secret-engine" {
		t.Errorf("iss/sub wrong: iss=%q sub=%q", std.Issuer, std.Subject)
	}
	if std.Audience[0] != "https://pingfed.example.com:9031" {
		t.Errorf("aud wrong: %v", std.Audience)
	}
	if std.ID == "" {
		t.Error("jti empty")
	}
	if extra["department"] != "billing" {
		t.Errorf("department claim missing in signed token: %v", extra)
	}
	if std.Issuer == "should-be-ignored" {
		t.Error("metadata overwrote iss")
	}
}

func TestSignAssertion_HeaderHasKidAndType(t *testing.T) {
	key := testKey(t)
	token, err := signAssertion(key, assertionParams{
		clientID: "c", audience: "https://p.example.com", ttl: time.Minute,
	}, time.Unix(1700000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Headers) == 0 {
		t.Fatal("no JWS headers")
	}
	h := parsed.Headers[0]
	if h.KeyID != key.KeyID {
		t.Errorf("kid = %q, want %q", h.KeyID, key.KeyID)
	}
	if got := h.ExtraHeaders[jose.HeaderType]; got != "JWT" {
		t.Errorf("typ = %v, want JWT", got)
	}
}

func TestSignAssertion_UniqueJTIPerCall(t *testing.T) {
	key := testKey(t)
	now := time.Unix(1700000000, 0)
	p := assertionParams{clientID: "c", audience: "https://p.example.com", ttl: time.Minute}

	seen := map[string]bool{}
	for i := 0; i < 5; i++ {
		token, err := signAssertion(key, p, now)
		if err != nil {
			t.Fatal(err)
		}
		parsed, _ := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
		var std jwt.Claims
		priv, _ := key.privateKey()
		_ = parsed.Claims(&priv.PublicKey, &std)
		if seen[std.ID] {
			t.Fatalf("duplicate jti %q on iteration %d", std.ID, i)
		}
		seen[std.ID] = true
	}
}
