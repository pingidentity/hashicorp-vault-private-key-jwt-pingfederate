// Command vault-plugin-secrets-pingfederate is the plugin binary entry point.
//
// Vault launches this binary as a child process and talks to it over the
// plugin RPC protocol. This file just wires the plugin SDK to the backend
// factory in the parent package; there is no business logic here.
package main

import (
	"os"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/plugin"

	pingfederate "vault-plugin-secrets-pingfederate"
)

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	if err := flags.Parse(os.Args[1:]); err != nil {
		logFatal(err)
	}

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	if err := plugin.ServeMultiplex(&plugin.ServeOpts{
		BackendFactoryFunc: pingfederate.Factory,
		// Required for pre-v5 plugin protocols; v5 multiplexed plugins use
		// AutoMTLS and ignore it.
		TLSProviderFunc: tlsProviderFunc,
	}); err != nil {
		logFatal(err)
	}
}

func logFatal(err error) {
	logger := hclog.New(&hclog.LoggerOptions{})
	logger.Error("plugin shutting down", "error", err)
	os.Exit(1)
}
