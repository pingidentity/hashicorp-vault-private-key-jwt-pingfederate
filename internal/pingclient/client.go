/* Package pingclient: */
// Contains the small HTTP client used to call PingFederate's token endpoint.
//
// Builds the form-encoded OAuth request, protects reserved form fields, parses
// successful responses, and returns safe errors that do not expose assertions.
package pingclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
const maxErrorBodyBytes = 8 << 10

/* TokenRequest: */
// Holds the inputs for one token-endpoint call.
// Assertion is a short-lived secret and must never be logged.
type TokenRequest struct {
	TokenEndpoint string
	ClientID      string
	Assertion     string
	GrantType     string            // defaults to "client_credentials" when empty
	Scopes        []string          // omitted from the request when empty
	ExtraForm     map[string]string // reserved OAuth keys are silently ignored
}

/* TokenResponse: */
// Parsed successful token response.
// RawBody preserves the full decoded body for callers that need provider-specific fields.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`

	RawBody map[string]interface{} `json:"-"`
}

/* reservedFormKeys: */
// OAuth parameters this package always controls.
// ExtraForm entries with these keys are silently dropped.
var reservedFormKeys = map[string]struct{}{
	"grant_type":            {},
	"client_assertion":      {},
	"client_assertion_type": {},
	"client_id":             {},
}

/* Doer: */
// Subset of *http.Client used by FetchToken.
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

/* FetchToken: */
// POSTs the client-credentials grant with a Private Key JWT assertion and returns the parsed response.
// On a non-200 status it returns a *TokenError; the request assertion is never included in the error.
func FetchToken(ctx context.Context, httpClient Doer, tr TokenRequest) (*TokenResponse, error) {
	if tr.TokenEndpoint == "" {
		return nil, fmt.Errorf("token endpoint is required")
	}
	if tr.Assertion == "" {
		return nil, fmt.Errorf("client assertion is required")
	}

	grant := tr.GrantType
	if grant == "" {
		grant = "client_credentials"
	}

	form := url.Values{}
	form.Set("grant_type", grant)
	form.Set("client_id", tr.ClientID)
	form.Set("client_assertion_type", clientAssertionType)
	form.Set("client_assertion", tr.Assertion)
	if len(tr.Scopes) > 0 {
		form.Set("scope", strings.Join(tr.Scopes, " "))
	}
	for k, v := range tr.ExtraForm {
		if _, reserved := reservedFormKeys[k]; !reserved {
			form.Set(k, v)
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tr.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("building token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("calling PingFederate token endpoint: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
		return nil, &TokenError{StatusCode: resp.StatusCode, Body: strings.TrimSpace(string(body))}
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("reading token response: %w", err)
	}

	var out TokenResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decoding token response: %w", err)
	}
	if out.AccessToken == "" {
		return nil, fmt.Errorf("token response did not contain an access_token")
	}
	_ = json.Unmarshal(raw, &out.RawBody)

	return &out, nil
}

/* TokenError: */
// Returned for non-200 responses from the token endpoint.
type TokenError struct {
	StatusCode int
	Body       string
}

/* Error: */
// Returns a human-readable message without exposing the request assertion.
func (e *TokenError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("PingFederate token endpoint returned HTTP %d", e.StatusCode)
	}
	return fmt.Sprintf("PingFederate token endpoint returned HTTP %d: %s", e.StatusCode, e.Body)
}

/* NewHTTPClient: */
// Returns a production *http.Client.
// When insecure is true, TLS verification is disabled - intended for sandbox use only.
func NewHTTPClient(insecure bool) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if insecure {
		transport.TLSClientConfig = newInsecureTLSConfig()
	}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}
}
