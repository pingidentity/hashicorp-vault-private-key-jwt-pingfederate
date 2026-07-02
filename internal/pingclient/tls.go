// Holds the only place in the plugin where TLS verification can be disabled.
package pingclient

import "crypto/tls"

/* newInsecureTLSConfig: */
// Returns a TLS config that skips verification.
// This is gated behind an explicit sandbox-only opt-in.
func newInsecureTLSConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // gated behind explicit sandbox-only opt-in
	}
}
