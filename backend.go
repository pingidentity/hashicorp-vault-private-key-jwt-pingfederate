/* Package pingfederate: */
// A Vault secrets engine that issues short-lived OAuth access tokens from PingFederate using Private Key JWT auth.
//
// The engine manages its own RSA signing keys per server and publishes the
// public keys at an unauthenticated JWKS endpoint that PingFederate fetches
// to validate assertions. Workloads read the token path; the engine mints
// a single-use JWT and exchanges it for an access token. No long-lived
// client_secret ever leaves Vault.
//
// Currently uses a single static client; DCR is out of scope.
//
// Paths (mounted at "ping"):
//
//	ping/servers/{name}                  server config and signing keys
//	ping/servers/{name}/jwks             public JWKS (unauthenticated)
//	ping/clients/{server}/{name}         client config
//	ping/clients/{server}/{name}/token   issue an access token
//
// This file is the engine's entry point: it builds the backend, registers
// every path, declares the unauthenticated surface, and installs the
// periodic key-rotation hook.
package pingfederate

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	storageServerPrefix = "servers/"
	storageClientPrefix = "clients/"
)

/* backend: */
// The PingFederate secrets engine.
// "clientFactory" and "now" are production defaults that tests can override.
type backend struct {
	*framework.Backend

	// lock serializes key-ring mutations; token issuance takes RLock.
	lock          sync.RWMutex
	clientFactory func(insecure bool) httpDoer
	now           func() time.Time
}

/* Factory: */
// The plugin entry point called by Vault to construct the backend.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := newBackend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

/* newBackend: */
// Builds a backend wired with production defaults.
func newBackend() *backend {
	b := &backend{
		clientFactory: defaultHTTPClient,
		now:           time.Now,
	}

	b.Backend = &framework.Backend{
		Help:        strings.TrimSpace(backendHelp),
		BackendType: logical.TypeLogical,
		PathsSpecial: &logical.Paths{
			// "+" matches exactly one path segment, so servers/{name}
			// stays authenticated while only /jwks is public.
			Unauthenticated: []string{
				"servers/+/jwks",
			},
		},
		Paths: framework.PathAppend(
			b.pathServers(),
			b.pathJWKS(),
			b.pathClients(),
			b.pathToken(),
		),
		PeriodicFunc: b.periodicRotate,
	}

	return b
}

const backendHelp = `
The PingFederate secrets engine issues short-lived OAuth access tokens from a
PingFederate server using Private Key JWT client authentication, removing the
need for long-lived client secrets.

Configure a PingFederate server under "servers/<name>", configure one or more
clients under "clients/<server>/<name>", then read
"clients/<server>/<name>/token" to retrieve an access token. The public signing
keys are published at the unauthenticated "servers/<name>/jwks" endpoint for
PingFederate to validate the engine's assertions.
`
