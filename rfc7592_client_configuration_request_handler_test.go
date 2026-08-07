// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	. "authelia.com/provider/oauth2"
)

func TestFositeNewRFC7592ClientConfigurationRequest(t *testing.T) {
	ctx := context.Background()

	t.Run("ShouldRejectEmptyClientID", func(t *testing.T) {
		strategy := &recordingEndpointAuth{
			requester: NewRequest(),
			onCall: func(string) {
				require.Fail(t, "AuthenticateClientRegistrationRequest must not be called when the derived client_id is empty")
			},
		}

		provider := &Fosite{Config: &Config{
			RFC7591ClientRegistrationEndpointAuthStrategy: strategy,
		}}

		r := httptest.NewRequest(http.MethodGet, "https://auth.example.com/register/", nil)

		_, err := provider.NewRFC7592ClientConfigurationRequest(ctx, r)
		require.Error(t, err)
		assert.EqualError(t, ErrorToDebugRFC6749Error(err), "Could not find the requested resource(s). The request does not specify a client_id.")
	})

	t.Run("ShouldPopulateClientIDAndSignatureFromAuthenticatedRequester", func(t *testing.T) {
		authenticated := NewRequest()
		authenticated.SetID("the-token-signature")

		provider := &Fosite{Config: &Config{
			RFC7591ClientRegistrationEndpointAuthStrategy: &staticEndpointAuth{requester: authenticated},
		}}

		r := httptest.NewRequest(http.MethodGet, "https://auth.example.com/register/client-1", nil)

		requester, err := provider.NewRFC7592ClientConfigurationRequest(ctx, r)
		require.NoError(t, err)

		assert.Equal(t, "client-1", requester.GetClientID())
		assert.Equal(t, "the-token-signature", requester.GetSignature())
		assert.Equal(t, http.MethodGet, requester.GetMethod())
		assert.Equal(t, authenticated, requester.GetAuthenticatedRequester())
	})

	t.Run("ShouldNotPanicWhenAuthStrategyReturnsNoRequester", func(t *testing.T) {
		provider := &Fosite{Config: &Config{
			RFC7591ClientRegistrationEndpointAuthStrategy: &staticEndpointAuth{requester: nil},
		}}

		r := httptest.NewRequest(http.MethodGet, "https://auth.example.com/register/client-1", nil)

		requester, err := provider.NewRFC7592ClientConfigurationRequest(ctx, r)
		require.NoError(t, err)

		assert.Equal(t, "client-1", requester.GetClientID())
		assert.Nil(t, requester.GetAuthenticatedRequester())
		assert.Empty(t, requester.GetSignature())
	})

	t.Run("ShouldDecodeJSONBodyForPUT", func(t *testing.T) {
		provider := &Fosite{Config: &Config{
			RFC7591ClientRegistrationEndpointAuthStrategy: &staticEndpointAuth{requester: NewRequest()},
		}}

		body := `{"client_name":"Example"}`
		r := httptest.NewRequest(http.MethodPut, "https://auth.example.com/register/client-1", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")

		requester, err := provider.NewRFC7592ClientConfigurationRequest(ctx, r)
		require.NoError(t, err)
		require.NotNil(t, requester.GetMetadata())
		assert.Equal(t, "Example", requester.GetMetadata().ClientName)
	})

	t.Run("ShouldRejectMalformedJSONBodyForPUT", func(t *testing.T) {
		provider := &Fosite{Config: &Config{
			RFC7591ClientRegistrationEndpointAuthStrategy: &staticEndpointAuth{requester: NewRequest()},
		}}

		r := httptest.NewRequest(http.MethodPut, "https://auth.example.com/register/client-1", strings.NewReader(`{`))
		r.Header.Set("Content-Type", "application/json")

		_, err := provider.NewRFC7592ClientConfigurationRequest(ctx, r)
		require.Error(t, err)
	})

	t.Run("ShouldNotDecodeBodyForGET", func(t *testing.T) {
		provider := &Fosite{Config: &Config{
			RFC7591ClientRegistrationEndpointAuthStrategy: &staticEndpointAuth{requester: NewRequest()},
		}}

		r := httptest.NewRequest(http.MethodGet, "https://auth.example.com/register/client-1", nil)

		requester, err := provider.NewRFC7592ClientConfigurationRequest(ctx, r)
		require.NoError(t, err)
		assert.Nil(t, requester.GetMetadata())
	})

	t.Run("ShouldNotDecodeBodyForDELETE", func(t *testing.T) {
		provider := &Fosite{Config: &Config{
			RFC7591ClientRegistrationEndpointAuthStrategy: &staticEndpointAuth{requester: NewRequest()},
		}}

		r := httptest.NewRequest(http.MethodDelete, "https://auth.example.com/register/client-1", nil)

		requester, err := provider.NewRFC7592ClientConfigurationRequest(ctx, r)
		require.NoError(t, err)
		assert.Nil(t, requester.GetMetadata())
		assert.Equal(t, http.MethodDelete, requester.GetMethod())
	})

	t.Run("ShouldReturnServerErrorWhenAuthStrategyMissing", func(t *testing.T) {
		provider := &Fosite{Config: &Config{}}

		r := httptest.NewRequest(http.MethodGet, "https://auth.example.com/register/client-1", nil)

		_, err := provider.NewRFC7592ClientConfigurationRequest(ctx, r)
		require.Error(t, err)
		assert.EqualError(t, ErrorToDebugRFC6749Error(err), "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. 'RFC7591ClientRegistrationConfigProvider' not implemented")
	})

	t.Run("ShouldRoundTripClientIDContainingSlash", func(t *testing.T) {
		id := "a/b"
		escaped := url.PathEscape(id)
		require.Equal(t, "a%2Fb", escaped)

		provider := &Fosite{Config: &Config{
			RFC7591ClientRegistrationEndpointAuthStrategy: &staticEndpointAuth{requester: NewRequest()},
		}}

		r := httptest.NewRequest(http.MethodGet, "https://auth.example.com/register/"+escaped, nil)

		requester, err := provider.NewRFC7592ClientConfigurationRequest(ctx, r)
		require.NoError(t, err)
		assert.Equal(t, id, requester.GetClientID())
	})

	t.Run("ShouldPassClientIDToAuthStrategy", func(t *testing.T) {
		var seenID string

		strategy := &recordingEndpointAuth{
			requester: NewRequest(),
			onCall: func(id string) {
				seenID = id
			},
		}

		provider := &Fosite{Config: &Config{
			RFC7591ClientRegistrationEndpointAuthStrategy: strategy,
		}}

		r := httptest.NewRequest(http.MethodGet, "https://auth.example.com/register/client-42", nil)

		_, err := provider.NewRFC7592ClientConfigurationRequest(ctx, r)
		require.NoError(t, err)
		assert.Equal(t, "client-42", seenID)
	})
}

type recordingEndpointAuth struct {
	requester Requester
	onCall    func(id string)
}

func (r *recordingEndpointAuth) AuthenticateClientRegistrationRequest(_ context.Context, _ *http.Request, id string) (requester Requester, err error) {
	r.onCall(id)

	return r.requester, nil
}
