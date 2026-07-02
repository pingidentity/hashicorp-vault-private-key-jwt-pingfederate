// Implements the public JWKS endpoint at "ping/servers/{name}/jwks".
//
// PingFederate fetches this URL to validate the engine's assertions. The
// response carries only public key material — never the private halves —
// and the path is the only unauthenticated surface in the plugin.
package pingfederate

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

/* pathJWKS: */
// Returns the framework path for the public JWKS endpoint.
// Only read is exposed to keep the unauthenticated surface minimal.
func (b *backend) pathJWKS() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "servers/" + framework.GenericNameRegex("name") + "/jwks",
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Logical name of the PingFederate server.",
					Required:    true,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{Callback: b.handleJWKSRead},
			},
			HelpSynopsis:    "Public JWKS for a PingFederate server (unauthenticated).",
			HelpDescription: "Returns the public signing keys (previous, current, next) as a JWKS document. Configure this URL as the client's jwks_url in PingFederate.",
		},
	}
}

/* handleJWKSRead: */
// Serves the public JWKS. Unknown servers return 404.
func (b *backend) handleJWKSRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)

	b.lock.RLock()
	cfg, err := b.getServer(ctx, req.Storage, name)
	b.lock.RUnlock()
	if err != nil {
		return nil, err
	}
	if cfg == nil || cfg.Keys == nil {
		return logical.RespondWithStatusCode(
			logical.ErrorResponse("server %q not found", name), req, http.StatusNotFound)
	}

	set, err := cfg.Keys.publicKeySet()
	if err != nil {
		return nil, err
	}

	body, err := json.Marshal(set)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			logical.HTTPContentType: "application/json",
			logical.HTTPRawBody:     body,
			logical.HTTPStatusCode:  http.StatusOK,
		},
	}, nil
}
