// Defines the HTTP client seam used by the token endpoint.
//
// The httpDoer interface lets tests inject a fake transport while the
// production factory delegates to internal/pingclient. This is the only
// place the plugin's path handlers reach the network.
package pingfederate

import (
	"net/http"

	"vault-plugin-secrets-pingfederate/internal/pingclient"
)

/* httpDoer: */
// The minimal HTTP interface used by the token path.
// Tests replace this with a mock to avoid real network calls.
type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

/* defaultHTTPClient: */
// The production clientFactory.
func defaultHTTPClient(insecure bool) httpDoer {
	return pingclient.NewHTTPClient(insecure)
}
