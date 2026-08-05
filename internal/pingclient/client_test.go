// These tests exercise the token-endpoint client against an httptest server:
// the happy-path form shape, error-status mapping to *TokenError, the
// reserved-form-key guard, and the missing-access_token failure mode.
package pingclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// TestFetchToken_AgainstMockServer covers the happy-path round trip and
// pins the form shape sent to the token endpoint.
func TestFetchToken_AgainstMockServer(t *testing.T) {
	var gotForm url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotForm = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"abc","token_type":"Bearer","expires_in":300,"scope":"read write"}`))
	}))
	defer srv.Close()

	resp, err := FetchToken(context.Background(), srv.Client(), TokenRequest{
		TokenEndpoint: srv.URL,
		ClientID:      "vault-secret-engine",
		Assertion:     "signed.jwt.assertion",
		Scopes:        []string{"read", "write"},
	})
	if err != nil {
		t.Fatalf("FetchToken: %v", err)
	}
	if resp.AccessToken != "abc" {
		t.Errorf("access_token = %q", resp.AccessToken)
	}
	if resp.ExpiresIn != 300 {
		t.Errorf("expires_in = %d", resp.ExpiresIn)
	}

	if gotForm.Get("grant_type") != "client_credentials" {
		t.Errorf("grant_type = %q", gotForm.Get("grant_type"))
	}
	if gotForm.Get("client_assertion") != "signed.jwt.assertion" {
		t.Errorf("client_assertion = %q", gotForm.Get("client_assertion"))
	}
	if gotForm.Get("scope") != "read write" {
		t.Errorf("scope = %q", gotForm.Get("scope"))
	}
}

func TestFetchToken_ErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
	}))
	defer srv.Close()

	_, err := FetchToken(context.Background(), srv.Client(), TokenRequest{
		TokenEndpoint: srv.URL,
		ClientID:      "c",
		Assertion:     "a",
	})
	if err == nil {
		t.Fatal("expected error for 401")
	}
	var tokErr *TokenError
	if !errorsAs(err, &tokErr) {
		t.Fatalf("expected *TokenError, got %T", err)
	}
	if tokErr.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d", tokErr.StatusCode)
	}
}

// TestFetchToken_ExtraFormCannotOverrideReserved verifies ExtraForm cannot
// replace reserved OAuth parameters.
func TestFetchToken_ExtraFormCannotOverrideReserved(t *testing.T) {
	var gotForm url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotForm = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"abc","token_type":"Bearer","expires_in":1}`))
	}))
	defer srv.Close()

	_, err := FetchToken(context.Background(), srv.Client(), TokenRequest{
		TokenEndpoint: srv.URL,
		ClientID:      "real",
		Assertion:     "real-assertion",
		ExtraForm: map[string]string{
			"client_assertion": "attacker-assertion",
			"client_id":        "attacker",
			"custom":           "ok",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotForm.Get("client_assertion") != "real-assertion" {
		t.Errorf("ExtraForm overrode client_assertion: %q", gotForm.Get("client_assertion"))
	}
	if gotForm.Get("client_id") != "real" {
		t.Errorf("ExtraForm overrode client_id: %q", gotForm.Get("client_id"))
	}
	if gotForm.Get("custom") != "ok" {
		t.Errorf("custom extra form param missing: %q", gotForm.Get("custom"))
	}
}

func TestFetchToken_MissingAccessToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token_type":"Bearer"}`))
	}))
	defer srv.Close()

	_, err := FetchToken(context.Background(), srv.Client(), TokenRequest{
		TokenEndpoint: srv.URL, ClientID: "c", Assertion: "a",
	})
	if err == nil {
		t.Fatal("expected error when access_token missing")
	}
}

// errorsAs is a local shim for errors.As targeting *TokenError, avoiding an
// import of the errors package just for this one test helper.
func errorsAs(err error, target interface{}) bool {
	te, ok := target.(**TokenError)
	if !ok {
		return false
	}
	for err != nil {
		if t, ok := err.(*TokenError); ok {
			*te = t
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
