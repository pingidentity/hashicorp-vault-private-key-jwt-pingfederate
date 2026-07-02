// Implements the "ping/servers/{name}" endpoints.
//
// It stores per-server configuration (base URL, TLS flag, rotation period)
// and owns the lifecycle of the server's signing key ring. The PeriodicFunc
// hook installed in backend.go calls into periodicRotate here to advance
// each ring on schedule.
package pingfederate

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// Rotation bounds.
// PingFederate caches JWKS for ~6 h, so the minimum is kept well above that window to ensure the outgoing key is always trusted.
const (
	defaultRotationPeriod = 24 * time.Hour
	minRotationPeriod     = 12 * time.Hour
)

/* serverConfig: */
// The stored configuration for one PingFederate server.
// The key ring is generated on first create and preserved across updates.
type serverConfig struct {
	PingURL              string   `json:"ping_url"`
	DisableTLSValidation bool     `json:"disable_tls_validation"`
	RotationPeriod       duration `json:"rotation_period"`
	Keys                 *keyRing `json:"keys"`
}

/* tokenEndpoint: */
// Returns the token endpoint for the server.
func (c *serverConfig) tokenEndpoint() string {
	return strings.TrimRight(c.PingURL, "/") + "/as/token.oauth2"
}

/* pathServers: */
// Returns the framework paths for managing server configs.
func (b *backend) pathServers() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "servers/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Logical name for this PingFederate server.",
					Required:    true,
				},
				"ping_url": {
					Type:        framework.TypeString,
					Description: "Base URL of the PingFederate server, e.g. https://pingfed.example.com:9031.",
				},
				"disable_tls_validation": {
					Type:        framework.TypeBool,
					Description: "Disable TLS certificate validation when calling PingFederate. For sandbox/testing only; never enable in production.",
					Default:     false,
				},
				"rotation_period": {
					Type:        framework.TypeDurationSecond,
					Description: fmt.Sprintf("How often signing keys rotate. Defaults to %s; minimum %s (must stay well above PingFederate's JWKS cache window).", defaultRotationPeriod, minRotationPeriod),
					Default:     int(defaultRotationPeriod.Seconds()),
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{Callback: b.handleServerWrite},
				logical.UpdateOperation: &framework.PathOperation{Callback: b.handleServerWrite},
				logical.ReadOperation:   &framework.PathOperation{Callback: b.handleServerRead},
				logical.DeleteOperation: &framework.PathOperation{Callback: b.handleServerDelete},
			},
			ExistenceCheck:  b.serverExistenceCheck,
			HelpSynopsis:    "Configure a PingFederate server.",
			HelpDescription: "Stores the base URL and TLS settings for a PingFederate server and generates the signing keys used to authenticate to it.",
		},
		{
			Pattern: "servers/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{Callback: b.handleServerList},
			},
			HelpSynopsis: "List configured PingFederate servers.",
		},
	}
}

/* serverExistenceCheck: */
// Checks if a server config exists.
func (b *backend) serverExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	cfg, err := b.getServer(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return false, err
	}
	return cfg != nil, nil
}

/* handleServerWrite: */
// Creates or updates a server config.
// The key ring is generated on first create and preserved across updates.
func (b *backend) handleServerWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)

	b.lock.Lock()
	defer b.lock.Unlock()

	cfg, err := b.getServer(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	isCreate := cfg == nil
	if isCreate {
		cfg = &serverConfig{}
	}

	if raw, ok := data.GetOk("ping_url"); ok {
		// Trim trailing slashes at write time so aud and tokenEndpoint always agree
		// PingFederate compares aud as an exact string
		cfg.PingURL = strings.TrimRight(raw.(string), "/")
	}
	if raw, ok := data.GetOk("disable_tls_validation"); ok {
		cfg.DisableTLSValidation = raw.(bool)
	}

	if raw, ok := data.GetOk("rotation_period"); ok {
		cfg.RotationPeriod = duration(time.Duration(raw.(int)) * time.Second)
	} else if isCreate {
		cfg.RotationPeriod = duration(defaultRotationPeriod)
	}

	if err := validateServerConfig(cfg); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	if cfg.Keys == nil {
		ring, err := newKeyRing(b.now(), time.Duration(cfg.RotationPeriod))
		if err != nil {
			return nil, err
		}
		cfg.Keys = ring
	} else {
		cfg.Keys.RotationPeriod = time.Duration(cfg.RotationPeriod)
	}

	if err := b.putServer(ctx, req.Storage, name, cfg); err != nil {
		return nil, err
	}
	return nil, nil
}

/* handleServerRead: */
// Returns the operator-visible view of a server config.
// The key ring's private material is never included.
func (b *backend) handleServerRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	cfg, err := b.getServer(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, nil
	}

	resp := map[string]interface{}{
		"ping_url":               cfg.PingURL,
		"disable_tls_validation": cfg.DisableTLSValidation,
		"rotation_period":        int64(time.Duration(cfg.RotationPeriod).Seconds()),
		"token_endpoint":         cfg.tokenEndpoint(),
	}
	if cfg.Keys != nil {
		resp["current_key_id"] = cfg.Keys.Current.KeyID
		resp["last_rotated"] = cfg.Keys.LastRotated.Format(time.RFC3339)
	}
	return &logical.Response{Data: resp}, nil
}

/* handleServerDelete: */
// Deletes a server config and its key ring.
// Clients referencing this server will fail until the server is re-created.
func (b *backend) handleServerDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.lock.Lock()
	defer b.lock.Unlock()
	return nil, req.Storage.Delete(ctx, storageServerPrefix+data.Get("name").(string))
}

/* handleServerList: */
// Lists all server configs.
func (b *backend) handleServerList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	names, err := req.Storage.List(ctx, storageServerPrefix)
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(names), nil
}

/* validateServerConfig: */
// Validates a server config.
// Returns an error if any required field is missing or invalid.
func validateServerConfig(cfg *serverConfig) error {
	if cfg.PingURL == "" {
		return fmt.Errorf("ping_url is required")
	}
	u, err := url.Parse(cfg.PingURL)
	if err != nil {
		return fmt.Errorf("ping_url is not a valid URL: %w", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("ping_url must be an http(s) URL")
	}
	if u.Host == "" {
		return fmt.Errorf("ping_url must include a host")
	}
	if rp := time.Duration(cfg.RotationPeriod); rp < minRotationPeriod {
		return fmt.Errorf("rotation_period %s is below the minimum %s", rp, minRotationPeriod)
	}
	return nil
}

/* getServer: */
// Returns the stored server config, or nil if it doesn't exist.
func (b *backend) getServer(ctx context.Context, s logical.Storage, name string) (*serverConfig, error) {
	entry, err := s.Get(ctx, storageServerPrefix+name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	var cfg serverConfig
	if err := entry.DecodeJSON(&cfg); err != nil {
		return nil, fmt.Errorf("decoding server config %q: %w", name, err)
	}
	return &cfg, nil
}

/* putServer: */
// Stores the server config.
func (b *backend) putServer(ctx context.Context, s logical.Storage, name string, cfg *serverConfig) error {
	entry, err := logical.StorageEntryJSON(storageServerPrefix+name, cfg)
	if err != nil {
		return err
	}
	return s.Put(ctx, entry)
}

/* periodicRotate: */
// Rotates key rings whose period has elapsed.
// Per-server errors are logged and skipped so one bad record cannot block the rest.
func (b *backend) periodicRotate(ctx context.Context, req *logical.Request) error {
	b.lock.Lock()
	defer b.lock.Unlock()

	names, err := req.Storage.List(ctx, storageServerPrefix)
	if err != nil {
		return err
	}
	now := b.now()
	for _, name := range names {
		cfg, err := b.getServer(ctx, req.Storage, name)
		if err != nil || cfg == nil || cfg.Keys == nil {
			continue
		}
		if !cfg.Keys.dueForRotation(now) {
			continue
		}
		if err := cfg.Keys.rotate(now); err != nil {
			b.Logger().Error("key rotation failed", "server", name, "error", err)
			continue
		}
		if err := b.putServer(ctx, req.Storage, name, cfg); err != nil {
			b.Logger().Error("persisting rotated keys failed", "server", name, "error", err)
			continue
		}
		b.Logger().Info("rotated signing keys", "server", name, "current_key_id", cfg.Keys.Current.KeyID)
	}
	return nil
}
