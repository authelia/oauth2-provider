// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7591

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
)

func TestSectorIdentifierValidator(t *testing.T) {
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/good":
			rw.Header().Set("Content-Type", "application/json")
			_, _ = rw.Write([]byte(`["https://example.com/cb","https://example.com/cb2"]`))
		case "/bad-json":
			rw.Header().Set("Content-Type", "application/json")
			_, _ = rw.Write([]byte(`{"not":"an array"}`))
		case "/redirect":
			http.Redirect(rw, r, "/good", http.StatusFound)
		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	}))

	t.Cleanup(server.Close)

	// httpClient is configured with a nil Logger so the retryablehttp default request/response DEBUG logging does
	// not pollute test output, and RetryMax is capped at 0 so ShouldRejectTransportFailure below observes its
	// connection-refused error immediately instead of paying retryablehttp's default four-attempt backoff
	// (1s -> 2s -> 4s -> 8s); the branch is fully exercised the instant Do returns the error, so retries add
	// wall-clock time without adding coverage. Neither change touches production code, which never overrides these
	// defaults itself.
	httpClient := retryablehttp.NewClient()
	httpClient.Logger = nil
	httpClient.RetryMax = 0

	config := &oauth2.Config{HTTPClient: httpClient}
	validator := NewSectorIdentifierValidator(config)

	t.Run("ShouldSkipWhenAbsent", func(t *testing.T) {
		require.NoError(t, validator.ValidateClientRegistrationMetadata(ctx, nil, &oauth2.ClientRegistrationMetadata{
			RedirectURIs: []string{"https://example.com/cb"},
		}))
	})

	t.Run("ShouldAcceptContainedRedirectURIs", func(t *testing.T) {
		require.NoError(t, validator.ValidateClientRegistrationMetadata(ctx, nil, &oauth2.ClientRegistrationMetadata{
			SectorIdentifierURI: server.URL + "/good",
			RedirectURIs:        []string{"https://example.com/cb"},
		}))
	})

	t.Run("ShouldRejectUncontainedRedirectURI", func(t *testing.T) {
		err := validator.ValidateClientRegistrationMetadata(ctx, nil, &oauth2.ClientRegistrationMetadata{
			SectorIdentifierURI: server.URL + "/good",
			RedirectURIs:        []string{"https://example.com/elsewhere"},
		})

		require.Error(t, err)
		assert.Equal(t, "invalid_client_metadata", oauth2.ErrorToRFC6749Error(err).ErrorField)
	})

	t.Run("ShouldRejectNonArrayDocument", func(t *testing.T) {
		err := validator.ValidateClientRegistrationMetadata(ctx, nil, &oauth2.ClientRegistrationMetadata{
			SectorIdentifierURI: server.URL + "/bad-json",
			RedirectURIs:        []string{"https://example.com/cb"},
		})

		require.Error(t, err)
		assert.Equal(t, "invalid_client_metadata", oauth2.ErrorToRFC6749Error(err).ErrorField)
	})

	t.Run("ShouldRejectNonOKStatus", func(t *testing.T) {
		// /missing is answered live by the server with a 404: this exercises the non-200-status branch, not a
		// transport failure (see ShouldRejectTransportFailure below for that).
		err := validator.ValidateClientRegistrationMetadata(ctx, nil, &oauth2.ClientRegistrationMetadata{
			SectorIdentifierURI: server.URL + "/missing",
			RedirectURIs:        []string{"https://example.com/cb"},
		})

		require.Error(t, err)
		assert.Equal(t, "invalid_client_metadata", oauth2.ErrorToRFC6749Error(err).ErrorField)
	})

	t.Run("ShouldRejectTransportFailure", func(t *testing.T) {
		// A closed server's loopback address refuses the connection outright, which is a genuine transport-level
		// failure (httpClient.Do returning a non-nil error), distinct from a live server answering with a non-200
		// status.
		closedServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {}))
		closedServer.Close()

		err := validator.ValidateClientRegistrationMetadata(ctx, nil, &oauth2.ClientRegistrationMetadata{
			SectorIdentifierURI: closedServer.URL + "/unreachable",
			RedirectURIs:        []string{"https://example.com/cb"},
		})

		require.Error(t, err)
		assert.Equal(t, "invalid_client_metadata", oauth2.ErrorToRFC6749Error(err).ErrorField)
	})

	t.Run("ShouldRejectNonHTTPSSectorIdentifierURI", func(t *testing.T) {
		err := validator.ValidateClientRegistrationMetadata(ctx, nil, &oauth2.ClientRegistrationMetadata{
			SectorIdentifierURI: "ftp://example.com/sector",
			RedirectURIs:        []string{"https://example.com/cb"},
		})

		require.Error(t, err)
		assert.Equal(t, "invalid_client_metadata", oauth2.ErrorToRFC6749Error(err).ErrorField)
	})

	t.Run("ShouldRejectUnparseableSectorIdentifierURI", func(t *testing.T) {
		// A non-numeric port fails url.Parse outright ("invalid port \":abc\" after host"), unlike the scheme
		// rejection case above, which parses successfully and fails a later check.
		err := validator.ValidateClientRegistrationMetadata(ctx, nil, &oauth2.ClientRegistrationMetadata{
			SectorIdentifierURI: "https://example.com:abc/sector",
			RedirectURIs:        []string{"https://example.com/cb"},
		})

		require.Error(t, err)
		assert.Equal(t, "invalid_client_metadata", oauth2.ErrorToRFC6749Error(err).ErrorField)
	})

	t.Run("ShouldRejectRedirect", func(t *testing.T) {
		err := validator.ValidateClientRegistrationMetadata(ctx, nil, &oauth2.ClientRegistrationMetadata{
			SectorIdentifierURI: server.URL + "/redirect",
			RedirectURIs:        []string{"https://example.com/cb"},
		})

		require.Error(t, err)
		assert.Equal(t, "invalid_client_metadata", oauth2.ErrorToRFC6749Error(err).ErrorField)
	})
}
