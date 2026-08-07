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

	server := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
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

	httpClient := retryablehttp.NewClient()
	httpClient.Logger = nil
	httpClient.RetryMax = 0

	httpClient.HTTPClient = server.Client()

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
		err := validator.ValidateClientRegistrationMetadata(ctx, nil, &oauth2.ClientRegistrationMetadata{
			SectorIdentifierURI: server.URL + "/missing",
			RedirectURIs:        []string{"https://example.com/cb"},
		})

		require.Error(t, err)
		assert.Equal(t, "invalid_client_metadata", oauth2.ErrorToRFC6749Error(err).ErrorField)
	})

	t.Run("ShouldRejectTransportFailure", func(t *testing.T) {
		closedServer := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {}))
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

	t.Run("ShouldRejectPlainHTTPLoopbackSectorIdentifierURI", func(t *testing.T) {
		err := validator.ValidateClientRegistrationMetadata(ctx, nil, &oauth2.ClientRegistrationMetadata{
			SectorIdentifierURI: "http://127.0.0.1:8080/sector",
			RedirectURIs:        []string{"https://example.com/cb"},
		})

		require.Error(t, err)
		assert.Equal(t, "invalid_client_metadata", oauth2.ErrorToRFC6749Error(err).ErrorField)
		assert.Contains(t, oauth2.ErrorToRFC6749Error(err).HintField, "must use the 'https' scheme")
	})

	t.Run("ShouldRejectUnparseableSectorIdentifierURI", func(t *testing.T) {
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
