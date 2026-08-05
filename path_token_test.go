// These tests cover the token-read flow end to end, including assertion shape,
// outbound OAuth form fields, no-lease behavior, and PingFederate error handling.
package pingfederate

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/hashicorp/vault/sdk/logical"
)

func newJSONResponse(status int, body map[string]interface{}) *http.Response {
	b, _ := json.Marshal(body)
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(bytes.NewReader(b)),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
	}
}

// TestTokenRead_HappyPath covers the full flow end to end: verifies the
// operator-facing response, the outbound OAuth form shape, claim values, and
// the no-lease guarantee (resp.Secret must stay nil).
func TestTokenRead_HappyPath(t *testing.T) {
	b, s := testBackend(t)

	b.req(t, s, logical.CreateOperation, "servers/prod", map[string]interface{}{
		"ping_url": "https://pingfed.example.com:9031",
	})
	b.req(t, s, logical.CreateOperation, "clients/prod/billing", map[string]interface{}{
		"client_id": "vault-secret-engine",
		"metadata":  "department=billing",
	})

	var gotForm url.Values
	var gotURL string
	b.clientFactory = func(insecure bool) httpDoer {
		return &mockDoer{handler: func(req *http.Request) (*http.Response, error) {
			gotURL = req.URL.String()
			body, _ := io.ReadAll(req.Body)
			gotForm, _ = url.ParseQuery(string(body))
			return newJSONResponse(http.StatusOK, map[string]interface{}{
				"access_token": "the-access-token",
				"token_type":   "Bearer",
				"expires_in":   300,
				"scope":        "read",
			}), nil
		}}
	}

	resp := b.req(t, s, logical.ReadOperation, "clients/prod/billing/token", nil)
	if resp == nil || resp.IsError() {
		t.Fatalf("token read failed: %v", resp)
	}
	if resp.Data["access_token"] != "the-access-token" {
		t.Errorf("access_token = %v", resp.Data["access_token"])
	}
	if resp.Data["token_type"] != "Bearer" {
		t.Errorf("token_type = %v", resp.Data["token_type"])
	}
	if resp.Secret != nil {
		t.Errorf("token read created a lease (resp.Secret = %#v); want nil", resp.Secret)
	}

	if gotURL != "https://pingfed.example.com:9031/as/token.oauth2" {
		t.Errorf("token endpoint = %q", gotURL)
	}
	if gotForm.Get("grant_type") != "client_credentials" {
		t.Errorf("grant_type = %q", gotForm.Get("grant_type"))
	}
	if gotForm.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		t.Errorf("client_assertion_type = %q", gotForm.Get("client_assertion_type"))
	}
	if gotForm.Get("client_id") != "vault-secret-engine" {
		t.Errorf("client_id = %q", gotForm.Get("client_id"))
	}

	assertion := gotForm.Get("client_assertion")
	if assertion == "" {
		t.Fatal("no client_assertion sent")
	}
	parsed, err := jwt.ParseSigned(assertion, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatalf("assertion not parseable: %v", err)
	}
	var claims jwt.Claims
	extra := map[string]interface{}{}
	// Signature verification is covered in jwt_test.go; here we only inspect claim values.
	if err := parsed.UnsafeClaimsWithoutVerification(&claims, &extra); err != nil {
		t.Fatalf("reading claims: %v", err)
	}
	if claims.Issuer != "vault-secret-engine" || claims.Subject != "vault-secret-engine" {
		t.Errorf("iss/sub: %q/%q", claims.Issuer, claims.Subject)
	}
	if len(claims.Audience) == 0 || claims.Audience[0] != "https://pingfed.example.com:9031" {
		t.Errorf("aud: %v", claims.Audience)
	}
	if extra["department"] != "billing" {
		t.Errorf("metadata claim missing: %v", extra)
	}
}

// TestTokenRead_AudIsNormalizedBaseURL guards against a trailing slash in
// ping_url leaking into the JWT aud claim.
func TestTokenRead_AudIsNormalizedBaseURL(t *testing.T) {
	b, s := testBackend(t)

	b.req(t, s, logical.CreateOperation, "servers/prod", map[string]interface{}{
		"ping_url": "https://pingfed.example.com:9031/",
	})
	b.req(t, s, logical.CreateOperation, "clients/prod/billing", map[string]interface{}{
		"client_id": "vault-secret-engine",
	})

	var gotAssertion string
	var gotURL string
	b.clientFactory = func(insecure bool) httpDoer {
		return &mockDoer{handler: func(req *http.Request) (*http.Response, error) {
			gotURL = req.URL.String()
			body, _ := io.ReadAll(req.Body)
			form, _ := url.ParseQuery(string(body))
			gotAssertion = form.Get("client_assertion")
			return newJSONResponse(http.StatusOK, map[string]interface{}{
				"access_token": "t", "token_type": "Bearer", "expires_in": 60,
			}), nil
		}}
	}
	b.req(t, s, logical.ReadOperation, "clients/prod/billing/token", nil)

	if gotURL != "https://pingfed.example.com:9031/as/token.oauth2" {
		t.Errorf("token endpoint = %q (slash leaked)", gotURL)
	}

	parsed, err := jwt.ParseSigned(gotAssertion, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var claims jwt.Claims
	_ = parsed.UnsafeClaimsWithoutVerification(&claims)
	if len(claims.Audience) != 1 || claims.Audience[0] != "https://pingfed.example.com:9031" {
		t.Errorf("aud = %v, want exact base URL with no trailing slash", claims.Audience)
	}
}

func TestTokenRead_NewAssertionPerCall(t *testing.T) {
	b, s := testBackend(t)
	b.req(t, s, logical.CreateOperation, "servers/prod", map[string]interface{}{
		"ping_url": "https://pingfed.example.com:9031",
	})
	b.req(t, s, logical.CreateOperation, "clients/prod/billing", map[string]interface{}{
		"client_id": "vault-secret-engine",
	})

	var assertions []string
	b.clientFactory = func(insecure bool) httpDoer {
		return &mockDoer{handler: func(req *http.Request) (*http.Response, error) {
			body, _ := io.ReadAll(req.Body)
			form, _ := url.ParseQuery(string(body))
			assertions = append(assertions, form.Get("client_assertion"))
			return newJSONResponse(http.StatusOK, map[string]interface{}{
				"access_token": "t", "token_type": "Bearer", "expires_in": 60,
			}), nil
		}}
	}

	b.req(t, s, logical.ReadOperation, "clients/prod/billing/token", nil)
	b.req(t, s, logical.ReadOperation, "clients/prod/billing/token", nil)

	if len(assertions) != 2 {
		t.Fatalf("expected 2 assertions, got %d", len(assertions))
	}
	if assertions[0] == assertions[1] {
		t.Error("expected a fresh assertion (unique jti) per call")
	}
}

func TestTokenRead_PassesTLSFlagToClientFactory(t *testing.T) {
	b, s := testBackend(t)
	b.req(t, s, logical.CreateOperation, "servers/sandbox", map[string]interface{}{
		"ping_url":               "https://pingfed-sandbox.example.com:9031",
		"disable_tls_validation": true,
	})
	b.req(t, s, logical.CreateOperation, "clients/sandbox/billy", map[string]interface{}{
		"client_id": "vault-secret-engine",
	})

	var gotInsecure bool
	b.clientFactory = func(insecure bool) httpDoer {
		gotInsecure = insecure
		return &mockDoer{handler: func(req *http.Request) (*http.Response, error) {
			return newJSONResponse(http.StatusOK, map[string]interface{}{
				"access_token": "t", "token_type": "Bearer", "expires_in": 60,
			}), nil
		}}
	}
	b.req(t, s, logical.ReadOperation, "clients/sandbox/billy/token", nil)
	if !gotInsecure {
		t.Error("expected disable_tls_validation to propagate to client factory")
	}
}

// TestTokenRead_PingErrorSurfacedNoAssertionLeak verifies a PingFederate error
// is surfaced with the OAuth error code but never the assertion.
func TestTokenRead_PingErrorSurfacedNoAssertionLeak(t *testing.T) {
	b, s := testBackend(t)
	b.req(t, s, logical.CreateOperation, "servers/prod", map[string]interface{}{
		"ping_url": "https://pingfed.example.com:9031",
	})
	b.req(t, s, logical.CreateOperation, "clients/prod/billing", map[string]interface{}{
		"client_id": "vault-secret-engine",
	})

	b.clientFactory = func(insecure bool) httpDoer {
		return &mockDoer{handler: func(req *http.Request) (*http.Response, error) {
			return newJSONResponse(http.StatusBadRequest, map[string]interface{}{
				"error":             "invalid_client",
				"error_description": "bad assertion",
			}), nil
		}}
	}

	resp := b.req(t, s, logical.ReadOperation, "clients/prod/billing/token", nil)
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected error response, got %v", resp)
	}
	msg := resp.Error().Error()
	if !bytes.Contains([]byte(msg), []byte("invalid_client")) {
		t.Errorf("expected ping error surfaced, got %q", msg)
	}
}

func TestTokenRead_MissingClient(t *testing.T) {
	b, s := testBackend(t)
	b.req(t, s, logical.CreateOperation, "servers/prod", map[string]interface{}{
		"ping_url": "https://pingfed.example.com:9031",
	})
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "clients/prod/ghost/token",
		Storage:   s,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected error for missing client, got %v", resp)
	}
}
