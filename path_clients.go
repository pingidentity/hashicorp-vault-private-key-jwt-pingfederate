// Implements the "ping/clients/{server}/{name}" endpoints.
//
// It stores per-client configuration: the PingFederate client_id, optional
// metadata that becomes extra claims on issued assertions, and a few OAuth
// knobs (assertion TTL, scopes, grant type). A client always belongs to a
// previously configured server.
package pingfederate

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const defaultAssertionTTL = 60 * time.Second

/* clientConfig: */
// The stored configuration for one PingFederate client.
// Metadata values are merged into the assertion as extra claims; reserved
// standard claim names (iss, sub, aud, etc.) are dropped at signing time.
type clientConfig struct {
	ClientID     string            `json:"client_id"`
	Metadata     map[string]string `json:"metadata"`
	AssertionTTL duration          `json:"assertion_ttl"`
	Scopes       []string          `json:"scopes"`
	GrantType    string            `json:"grant_type"`
}

func (c *clientConfig) ttl() time.Duration {
	if d := time.Duration(c.AssertionTTL); d > 0 {
		return d
	}
	return defaultAssertionTTL
}

/* pathClients: */
// Returns the framework paths for managing client configs.
func (b *backend) pathClients() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "clients/" + framework.GenericNameRegex("server") + "/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"server": {
					Type:        framework.TypeString,
					Description: "Name of the configured PingFederate server this client belongs to.",
					Required:    true,
				},
				"name": {
					Type:        framework.TypeString,
					Description: "Logical name for this client.",
					Required:    true,
				},
				"client_id": {
					Type:        framework.TypeString,
					Description: "PingFederate client_id used as iss and sub in the assertion.",
				},
				"metadata": {
					Type:        framework.TypeKVPairs,
					Description: "Additional claims (key=value) merged into the issued JWT. Cannot override reserved standard claims (iss, sub, aud, exp, iat, nbf, jti).",
				},
				"assertion_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: fmt.Sprintf("Lifetime of the signed client assertion. Defaults to %s.", defaultAssertionTTL),
				},
				"scopes": {
					Type:        framework.TypeCommaStringSlice,
					Description: "Optional OAuth scopes to request at the token endpoint.",
				},
				"grant_type": {
					Type:        framework.TypeString,
					Description: "Optional OAuth grant type. Defaults to client_credentials.",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{Callback: b.handleClientWrite},
				logical.UpdateOperation: &framework.PathOperation{Callback: b.handleClientWrite},
				logical.ReadOperation:   &framework.PathOperation{Callback: b.handleClientRead},
				logical.DeleteOperation: &framework.PathOperation{Callback: b.handleClientDelete},
			},
			ExistenceCheck:  b.clientExistenceCheck,
			HelpSynopsis:    "Configure a PingFederate client tied to a server.",
			HelpDescription: "Stores the client_id and optional metadata used to mint and sign Private Key JWT client assertions.",
		},
		{
			Pattern: "clients/" + framework.GenericNameRegex("server") + "/?$",
			Fields: map[string]*framework.FieldSchema{
				"server": {
					Type:        framework.TypeString,
					Description: "Name of the configured PingFederate server.",
					Required:    true,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{Callback: b.handleClientList},
			},
			HelpSynopsis: "List clients configured for a server.",
		},
	}
}

func (b *backend) clientExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	cfg, err := b.getClient(ctx, req.Storage, data.Get("server").(string), data.Get("name").(string))
	if err != nil {
		return false, err
	}
	return cfg != nil, nil
}

/* handleClientWrite: */
// Creates or updates a client config. The referenced server must exist.
func (b *backend) handleClientWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	server := data.Get("server").(string)
	name := data.Get("name").(string)

	srv, err := b.getServer(ctx, req.Storage, server)
	if err != nil {
		return nil, err
	}
	if srv == nil {
		return logical.ErrorResponse("server %q does not exist; configure it first via servers/%s", server, server), nil
	}

	cfg, err := b.getClient(ctx, req.Storage, server, name)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		cfg = &clientConfig{}
	}

	if raw, ok := data.GetOk("client_id"); ok {
		cfg.ClientID = raw.(string)
	}
	if raw, ok := data.GetOk("metadata"); ok {
		cfg.Metadata = raw.(map[string]string)
	}
	if raw, ok := data.GetOk("assertion_ttl"); ok {
		cfg.AssertionTTL = duration(time.Duration(raw.(int)) * time.Second)
	}
	if raw, ok := data.GetOk("scopes"); ok {
		cfg.Scopes = raw.([]string)
	}
	if raw, ok := data.GetOk("grant_type"); ok {
		cfg.GrantType = raw.(string)
	}

	if cfg.ClientID == "" {
		return logical.ErrorResponse("client_id is required"), nil
	}

	if err := b.putClient(ctx, req.Storage, server, name, cfg); err != nil {
		return nil, err
	}
	return nil, nil
}

/* handleClientRead: */
// Reads a client config. The referenced server must exist.
func (b *backend) handleClientRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	cfg, err := b.getClient(ctx, req.Storage, data.Get("server").(string), data.Get("name").(string))
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, nil
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"client_id":     cfg.ClientID,
			"metadata":      cfg.Metadata,
			"assertion_ttl": int64(cfg.ttl().Seconds()),
			"scopes":        cfg.Scopes,
			"grant_type":    cfg.GrantType,
		},
	}, nil
}

/* handleClientDelete: */
// Deletes a client config. The referenced server must exist.
func (b *backend) handleClientDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return nil, req.Storage.Delete(ctx, clientStorageKey(data.Get("server").(string), data.Get("name").(string)))
}

/* handleClientList: */
// Lists all client configs for a given server.
func (b *backend) handleClientList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	prefix := storageClientPrefix + data.Get("server").(string) + "/"
	names, err := req.Storage.List(ctx, prefix)
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(names), nil
}

/* clientStorageKey: */
// Returns the storage key for a client config.
func clientStorageKey(server, name string) string {
	return storageClientPrefix + server + "/" + name
}

/* getClient: */
// Returns the stored client config, or nil if it doesn't exist.
func (b *backend) getClient(ctx context.Context, s logical.Storage, server, name string) (*clientConfig, error) {
	entry, err := s.Get(ctx, clientStorageKey(server, name))
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	var cfg clientConfig
	if err := entry.DecodeJSON(&cfg); err != nil {
		return nil, fmt.Errorf("decoding client config %s/%s: %w", server, name, err)
	}
	return &cfg, nil
}

/* putClient: */
// Stores the client config.
func (b *backend) putClient(ctx context.Context, s logical.Storage, server, name string, cfg *clientConfig) error {
	entry, err := logical.StorageEntryJSON(clientStorageKey(server, name), cfg)
	if err != nil {
		return err
	}
	return s.Put(ctx, entry)
}
