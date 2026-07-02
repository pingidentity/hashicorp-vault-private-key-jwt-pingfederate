// Builds the Private Key JWT assertion sent to PingFederate.
//
// The engine owns the standard claims, strips metadata that tries to override
// them, and signs each assertion with a fresh jti so the result is short-lived
// and single-use.
package pingfederate

import (
	"fmt"
	"time"

	"github.com/hashicorp/go-uuid"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

/* reservedClaims: */
// The standard claims the engine sets itself.
// Any metadata key matching one of these is dropped before signing to prevent override.
var reservedClaims = map[string]struct{}{
	"iss": {}, "sub": {}, "aud": {},
	"exp": {}, "iat": {}, "nbf": {}, "jti": {},
}

/* assertionParams: */
// Holds the inputs for one assertion.
type assertionParams struct {
	clientID    string // becomes iss and sub
	audience    string // must match PingFederate's base URL exactly
	ttl         time.Duration
	extraClaims map[string]interface{}
}

/* buildClaims: */
// Returns the standard claims and the sanitized extra claims.
// Separated from signing so tests can drive it with a fixed time and jti.
func buildClaims(p assertionParams, now time.Time, jti string) (jwt.Claims, map[string]interface{}) {
	std := jwt.Claims{
		Issuer:   p.clientID,
		Subject:  p.clientID,
		Audience: jwt.Audience{p.audience},
		Expiry:   jwt.NewNumericDate(now.Add(p.ttl)),
		IssuedAt: jwt.NewNumericDate(now),
		ID:       jti,
	}

	safe := make(map[string]interface{}, len(p.extraClaims))
	for k, v := range p.extraClaims {
		if _, reserved := reservedClaims[k]; !reserved {
			safe[k] = v
		}
	}
	return std, safe
}

/* signAssertion: */
// Builds and signs a Private Key JWT client assertion.
// A fresh jti is generated on every call; the returned string is a short-lived secret and must never be logged.
func signAssertion(key *keyEntry, p assertionParams, now time.Time) (string, error) {
	jti, err := uuid.GenerateUUID()
	if err != nil {
		return "", fmt.Errorf("generating jti: %w", err)
	}

	priv, err := key.privateKey()
	if err != nil {
		return "", err
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: signingAlg, Key: priv},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", key.KeyID),
	)
	if err != nil {
		return "", fmt.Errorf("creating signer: %w", err)
	}

	std, extra := buildClaims(p, now, jti)

	builder := jwt.Signed(signer).Claims(std)
	if len(extra) > 0 {
		builder = builder.Claims(extra)
	}

	token, err := builder.Serialize()
	if err != nil {
		return "", fmt.Errorf("serializing assertion: %w", err)
	}
	return token, nil
}
