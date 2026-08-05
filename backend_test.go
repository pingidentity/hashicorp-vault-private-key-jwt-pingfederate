// This file provides the shared test scaffolding for the package: an
// in-memory backend, a fixed-clock helper, and a mock HTTP transport used
// by the token-flow tests.
package pingfederate

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

func testBackend(t *testing.T) (*backend, logical.Storage) {
	t.Helper()
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}

	b := newBackend()
	if err := b.Setup(context.Background(), config); err != nil {
		t.Fatalf("backend setup: %v", err)
	}
	return b, config.StorageView
}

func fixedNow(ts time.Time) func() time.Time {
	return func() time.Time { return ts }
}

// req issues a request and fails the test on an unexpected error.
func (b *backend) req(t *testing.T, s logical.Storage, op logical.Operation, path string, data map[string]interface{}) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: op,
		Path:      path,
		Storage:   s,
		Data:      data,
	})
	if err != nil {
		t.Fatalf("%s %s: unexpected error: %v", op, path, err)
	}
	return resp
}

type mockDoer struct {
	handler func(*http.Request) (*http.Response, error)
}

func (m *mockDoer) Do(req *http.Request) (*http.Response, error) { return m.handler(req) }
