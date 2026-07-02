// Implements the token-read endpoint.
//
// A token read loads the server and client config, signs a fresh assertion,
// exchanges it with PingFederate, and returns the access token without creating
// a Vault lease or writing anything back to storage.
package pingfederate

import (
	"context"
	"errors"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"vault-plugin-secrets-pingfederate/internal/pingclient"
)

/* pathToken: */
// Returns the framework path for the token-retrieval endpoint.
func (b *backend) pathToken() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "clients/" + framework.GenericNameRegex("server") + "/" + framework.GenericNameRegex("name") + "/token",
			Fields: map[string]*framework.FieldSchema{
				"server": {
					Type:        framework.TypeString,
					Description: "Name of the configured PingFederate server.",
					Required:    true,
				},
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the configured client.",
					Required:    true,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{Callback: b.handleTokenRead},
			},
			HelpSynopsis:    "Retrieve a short-lived access token from PingFederate.",
			HelpDescription: "Mints a fresh single-use Private Key JWT client assertion and exchanges it at PingFederate's token endpoint. Issues no lease and writes nothing to storage.",
		},
	}
}

/* handleTokenRead: */
// Mints a fresh assertion and exchanges it for an access token.
// No lease is created; resp.Secret stays nil by design.
func (b *backend) handleTokenRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	serverName := data.Get("server").(string)
	clientName := data.Get("name").(string)

	// Snapshot config and signing key under RLock so a concurrent rotation
	// cannot retire the key between lookup and signing.
	b.lock.RLock()
	srv, srvErr := b.getServer(ctx, req.Storage, serverName)
	cli, cliErr := b.getClient(ctx, req.Storage, serverName, clientName)
	var signingKey *keyEntry
	if srv != nil && srv.Keys != nil {
		signingKey = srv.Keys.Current
	}
	b.lock.RUnlock()

	if srvErr != nil {
		return nil, srvErr
	}
	if cliErr != nil {
		return nil, cliErr
	}
	if srv == nil {
		return logical.ErrorResponse("server %q not found", serverName), nil
	}
	if cli == nil {
		return logical.ErrorResponse("client %q not found for server %q", clientName, serverName), nil
	}
	if signingKey == nil {
		return nil, errors.New("server has no signing key configured")
	}

	// Phase 1 merges only client-config metadata. Entity/alias merging is deferred.
	extra := make(map[string]interface{}, len(cli.Metadata))
	for k, v := range cli.Metadata {
		extra[k] = v
	}

	assertion, err := signAssertion(signingKey, assertionParams{
		clientID:    cli.ClientID,
		audience:    srv.PingURL,
		ttl:         cli.ttl(),
		extraClaims: extra,
	}, b.now())
	if err != nil {
		return nil, err
	}

	httpClient := b.clientFactory(srv.DisableTLSValidation)

	tokenResp, err := pingclient.FetchToken(ctx, httpClient, pingclient.TokenRequest{
		TokenEndpoint: srv.tokenEndpoint(),
		ClientID:      cli.ClientID,
		Assertion:     assertion,
		GrantType:     cli.GrantType,
		Scopes:        cli.Scopes,
	})
	if err != nil {
		// Surface the PingFederate error without leaking the assertion.
		var tokErr *pingclient.TokenError
		if errors.As(err, &tokErr) {
			return logical.ErrorResponse("PingFederate rejected the token request: %s", tokErr.Error()), nil
		}
		return nil, err
	}

	respData := map[string]interface{}{
		"access_token": tokenResp.AccessToken,
		"token_type":   tokenResp.TokenType,
		"expires_in":   tokenResp.ExpiresIn,
	}
	if tokenResp.Scope != "" {
		respData["scope"] = tokenResp.Scope
	}

	return &logical.Response{Data: respData}, nil
}
