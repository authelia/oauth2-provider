// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7591

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
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
		assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The value of one of the client metadata fields is invalid and the server has rejected this request. The 'sector_identifier_uri' document does not contain the 'redirect_uris' value 'https://example.com/elsewhere'.")
	})

	t.Run("ShouldRejectNonArrayDocument", func(t *testing.T) {
		err := validator.ValidateClientRegistrationMetadata(ctx, nil, &oauth2.ClientRegistrationMetadata{
			SectorIdentifierURI: server.URL + "/bad-json",
			RedirectURIs:        []string{"https://example.com/cb"},
		})

		require.Error(t, err)
		assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), fmt.Sprintf("The value of one of the client metadata fields is invalid and the server has rejected this request. The 'sector_identifier_uri' value '%s/bad-json' did not return a JSON array of redirect URI strings. json: cannot unmarshal object into Go value of type []string", server.URL))
	})

	t.Run("ShouldRejectNonOKStatus", func(t *testing.T) {
		// /missing is answered live by the server with a 404: this exercises the non-200-status branch, not a
		// transport failure (see ShouldRejectTransportFailure below for that).
		err := validator.ValidateClientRegistrationMetadata(ctx, nil, &oauth2.ClientRegistrationMetadata{
			SectorIdentifierURI: server.URL + "/missing",
			RedirectURIs:        []string{"https://example.com/cb"},
		})

		require.Error(t, err)
		assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), fmt.Sprintf("The value of one of the client metadata fields is invalid and the server has rejected this request. The 'sector_identifier_uri' value '%s/missing' returned HTTP status code 404 instead of the expected 200.", server.URL))
	})

	t.Run("ShouldRejectTransportFailure", func(t *testing.T) {
		closedServer := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {}))
		closedServer.Close()

		err := validator.ValidateClientRegistrationMetadata(ctx, nil, &oauth2.ClientRegistrationMetadata{
			SectorIdentifierURI: closedServer.URL + "/unreachable",
			RedirectURIs:        []string{"https://example.com/cb"},
		})

		require.Error(t, err)
		assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), fmt.Sprintf("The value of one of the client metadata fields is invalid and the server has rejected this request. The 'sector_identifier_uri' value '%[1]s/unreachable' could not be fetched. GET %[1]s/unreachable giving up after 1 attempt(s): Get '%[1]s/unreachable': dial tcp %[2]s: connect: connection refused", closedServer.URL, strings.TrimPrefix(closedServer.URL, "https://")))
	})

	t.Run("ShouldRejectNonHTTPSSectorIdentifierURI", func(t *testing.T) {
		err := validator.ValidateClientRegistrationMetadata(ctx, nil, &oauth2.ClientRegistrationMetadata{
			SectorIdentifierURI: "ftp://example.com/sector",
			RedirectURIs:        []string{"https://example.com/cb"},
		})

		require.Error(t, err)
		assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The value of one of the client metadata fields is invalid and the server has rejected this request. The 'sector_identifier_uri' value 'ftp://example.com/sector' must use the 'https' scheme.")
	})

	t.Run("ShouldRejectPlainHTTPLoopbackSectorIdentifierURI", func(t *testing.T) {
		err := validator.ValidateClientRegistrationMetadata(ctx, nil, &oauth2.ClientRegistrationMetadata{
			SectorIdentifierURI: "http://127.0.0.1:8080/sector",
			RedirectURIs:        []string{"https://example.com/cb"},
		})

		require.Error(t, err)
		assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The value of one of the client metadata fields is invalid and the server has rejected this request. The 'sector_identifier_uri' value 'http://127.0.0.1:8080/sector' must use the 'https' scheme.")
	})

	t.Run("ShouldRejectUnparseableSectorIdentifierURI", func(t *testing.T) {
		err := validator.ValidateClientRegistrationMetadata(ctx, nil, &oauth2.ClientRegistrationMetadata{
			SectorIdentifierURI: "https://example.com:abc/sector",
			RedirectURIs:        []string{"https://example.com/cb"},
		})

		require.Error(t, err)
		assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The value of one of the client metadata fields is invalid and the server has rejected this request. The 'sector_identifier_uri' value 'https://example.com:abc/sector' could not be parsed as a URI. parse 'https://example.com:abc/sector': invalid port ':abc' after host")
	})

	t.Run("ShouldRejectRedirect", func(t *testing.T) {
		err := validator.ValidateClientRegistrationMetadata(ctx, nil, &oauth2.ClientRegistrationMetadata{
			SectorIdentifierURI: server.URL + "/redirect",
			RedirectURIs:        []string{"https://example.com/cb"},
		})

		require.Error(t, err)
		assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), fmt.Sprintf("The value of one of the client metadata fields is invalid and the server has rejected this request. The 'sector_identifier_uri' value '%s/redirect' returned HTTP status code 302 instead of the expected 200.", server.URL))
	})
}
