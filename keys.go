// Manages the signing keys used by the engine.
//
// Each PingFederate server has a small key ring: previous, current, and next.
// Publishing overlapping public keys lets PingFederate continue validating
// assertions while its JWKS cache catches up after rotation.
package pingfederate

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

const signingKeyBits = 2048
const signingAlg = jose.RS256

/* keyEntry: */
// Holds one signing key.
// The private key is barrier-encrypted at rest and never returned over any API path.
type keyEntry struct {
	KeyID           string    `json:"key_id"`
	PrivateKeyPKCS8 []byte    `json:"private_key_pkcs8"`
	CreatedAt       time.Time `json:"created_at"`
}

/* keyRing: */
// Holds the previous/current/next signing keys for a server.
// Previous is nil until the first rotation; after that all three are set.
type keyRing struct {
	Current  *keyEntry `json:"current"`
	Previous *keyEntry `json:"previous"`
	Next     *keyEntry `json:"next"`

	LastRotated    time.Time     `json:"last_rotated"`
	RotationPeriod time.Duration `json:"rotation_period"`
}

/* newKeyEntry: */
// Generates a fresh RSA key and derives its kid via RFC 7638 thumbprint.
func newKeyEntry(now time.Time) (*keyEntry, error) {
	priv, err := rsa.GenerateKey(rand.Reader, signingKeyBits)
	if err != nil {
		return nil, fmt.Errorf("generating RSA key: %w", err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshaling private key: %w", err)
	}

	kid, err := thumbprintKID(&priv.PublicKey)
	if err != nil {
		return nil, err
	}

	return &keyEntry{
		KeyID:           kid,
		PrivateKeyPKCS8: der,
		CreatedAt:       now,
	}, nil
}

/* thumbprintKID: */
// Computes the RFC 7638 thumbprint of the public key and returns it as a base64url string.
func thumbprintKID(pub *rsa.PublicKey) (string, error) {
	jwk := jose.JSONWebKey{Key: pub, Algorithm: string(signingAlg), Use: "sig"}
	tp, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("computing key thumbprint: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(tp), nil
}

/* privateKey: */
// Returns the RSA private key.
func (k *keyEntry) privateKey() (*rsa.PrivateKey, error) {
	key, err := x509.ParsePKCS8PrivateKey(k.PrivateKeyPKCS8)
	if err != nil {
		return nil, fmt.Errorf("parsing stored private key: %w", err)
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("stored key is not RSA (%T)", key)
	}
	return rsaKey, nil
}

/* publicJWK: */
// Returns only the public half of the key.
func (k *keyEntry) publicJWK() (jose.JSONWebKey, error) {
	priv, err := k.privateKey()
	if err != nil {
		return jose.JSONWebKey{}, err
	}
	return jose.JSONWebKey{
		Key:       &priv.PublicKey,
		KeyID:     k.KeyID,
		Algorithm: string(signingAlg),
		Use:       "sig",
	}, nil
}

/* newKeyRing: */
// Builds the initial ring with current and next already populated.
// Previous is nil; it is set on the first rotation.
func newKeyRing(now time.Time, rotationPeriod time.Duration) (*keyRing, error) {
	current, err := newKeyEntry(now)
	if err != nil {
		return nil, err
	}
	next, err := newKeyEntry(now)
	if err != nil {
		return nil, err
	}
	return &keyRing{
		Current:        current,
		Next:           next,
		LastRotated:    now,
		RotationPeriod: rotationPeriod,
	}, nil
}

/* rotate: */
// Promotes the ring: previous ← current, current ← next, next ← new key.
func (r *keyRing) rotate(now time.Time) error {
	next, err := newKeyEntry(now)
	if err != nil {
		return err
	}
	r.Previous = r.Current
	r.Current = r.Next
	r.Next = next
	r.LastRotated = now
	return nil
}

/* dueForRotation: */
// Returns true if the ring is due for rotation.
func (r *keyRing) dueForRotation(now time.Time) bool {
	if r.RotationPeriod <= 0 {
		return false
	}
	return now.Sub(r.LastRotated) >= r.RotationPeriod
}

/* publicKeySet: */
// Returns the JWKS to publish.
// Nil entries (Previous before the first rotation) are skipped, giving 2 keys initially and 3 after.
func (r *keyRing) publicKeySet() (jose.JSONWebKeySet, error) {
	set := jose.JSONWebKeySet{}
	for _, k := range []*keyEntry{r.Previous, r.Current, r.Next} {
		if k == nil {
			continue
		}
		jwk, err := k.publicJWK()
		if err != nil {
			return jose.JSONWebKeySet{}, err
		}
		set.Keys = append(set.Keys, jwk)
	}
	return set, nil
}
