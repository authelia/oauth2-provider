// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/testing/mock"
	"authelia.com/provider/oauth2/x/errorsx"
)

func TestFositeNewRFC7591ClientRegistrationRequest(t *testing.T) {
	ctx := context.Background()

	authenticated := NewRequest()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	store := mock.NewMockStorage(ctrl)

	config := &Config{
		RFC7591ClientRegistrationEndpointAuthStrategy: &staticEndpointAuth{requester: authenticated},
	}

	provider := New(store, config)

	t.Run("ShouldParseJSONBody", func(t *testing.T) {
		body := `{"redirect_uris":["https://example.com/cb"],"client_name":"Example"}`

		r := httptest.NewRequest(http.MethodPost, "https://auth.example.com/register", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")

		requester, err := provider.NewRFC7591ClientRegistrationRequest(ctx, r)
		require.NoError(t, err)

		assert.Equal(t, []string{"https://example.com/cb"}, requester.GetMetadata().RedirectURIs)
		assert.Equal(t, "Example", requester.GetMetadata().ClientName)
		assert.Equal(t, authenticated, requester.GetAuthenticatedRequester())
	})

	t.Run("ShouldRejectNonPOST", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "https://auth.example.com/register", nil)

		_, err := provider.NewRFC7591ClientRegistrationRequest(ctx, r)
		require.Error(t, err)
	})

	t.Run("ShouldRejectMalformedJSON", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "https://auth.example.com/register", strings.NewReader(`{`))
		r.Header.Set("Content-Type", "application/json")

		_, err := provider.NewRFC7591ClientRegistrationRequest(ctx, r)
		require.Error(t, err)
	})

	// RFC 7591 Section 2 defines the request body as a JSON object. A literal 'null' is valid JSON but not an object,
	// and decoding it into a value would leave a zero-valued struct behind and register a client from a body that
	// carried no metadata at all.
	t.Run("ShouldRejectNullBody", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "https://auth.example.com/register", strings.NewReader(`null`))
		r.Header.Set("Content-Type", "application/json")

		_, err := provider.NewRFC7591ClientRegistrationRequest(ctx, r)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidClientMetadata)
		assert.Equal(t, "The request body must be a JSON object.", ErrorToRFC6749Error(err).HintField)
	})

	// A decoder stops at the end of the first value, so without an explicit end-of-input check a second document
	// would be silently ignored rather than reported.
	t.Run("ShouldRejectMultipleJSONDocuments", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "https://auth.example.com/register", strings.NewReader(`{} {}`))
		r.Header.Set("Content-Type", "application/json")

		_, err := provider.NewRFC7591ClientRegistrationRequest(ctx, r)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidClientMetadata)
		assert.Equal(t, "The request body must contain a single JSON object.", ErrorToRFC6749Error(err).HintField)
	})

	t.Run("ShouldRejectTrailingGarbage", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "https://auth.example.com/register", strings.NewReader(`{"client_name":"Example"} not-json`))
		r.Header.Set("Content-Type", "application/json")

		_, err := provider.NewRFC7591ClientRegistrationRequest(ctx, r)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidClientMetadata)
	})

	t.Run("ShouldAcceptTrailingWhitespace", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "https://auth.example.com/register", strings.NewReader(`{"client_name":"Example"}`+"\n\n"))
		r.Header.Set("Content-Type", "application/json")

		requester, err := provider.NewRFC7591ClientRegistrationRequest(ctx, r)
		require.NoError(t, err)

		assert.Equal(t, "Example", requester.GetMetadata().ClientName)
	})

	t.Run("ShouldRejectMissingContentType", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "https://auth.example.com/register", strings.NewReader(`{}`))

		_, err := provider.NewRFC7591ClientRegistrationRequest(ctx, r)
		require.Error(t, err)
	})

	t.Run("ShouldRejectWrongContentType", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "https://auth.example.com/register", strings.NewReader(`{}`))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		_, err := provider.NewRFC7591ClientRegistrationRequest(ctx, r)
		require.Error(t, err)
	})

	t.Run("ShouldReturnServerErrorWhenAuthStrategyMissing", func(t *testing.T) {
		unconfigured := New(store, &Config{})

		r := httptest.NewRequest(http.MethodPost, "https://auth.example.com/register", strings.NewReader(`{}`))
		r.Header.Set("Content-Type", "application/json")

		_, err := unconfigured.NewRFC7591ClientRegistrationRequest(ctx, r)
		require.Error(t, err)
		assert.EqualError(t, ErrorToDebugRFC6749Error(err), "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. 'RFC7591ClientRegistrationConfigProvider' not implemented")
	})

	t.Run("ShouldPropagateAuthStrategyError", func(t *testing.T) {
		failing := New(store, &Config{
			RFC7591ClientRegistrationEndpointAuthStrategy: &staticEndpointAuth{err: errorsx.WithStack(ErrRequestUnauthorized)},
		})

		r := httptest.NewRequest(http.MethodPost, "https://auth.example.com/register", strings.NewReader(`{}`))
		r.Header.Set("Content-Type", "application/json")

		_, err := failing.NewRFC7591ClientRegistrationRequest(ctx, r)
		require.Error(t, err)
		assert.EqualError(t, ErrorToDebugRFC6749Error(err), "The request could not be authorized. Check that you provided valid credentials in the right format.")
	})
}

func TestFositeWriteRFC7591ClientRegistrationResponse(t *testing.T) {
	ctx := context.Background()

	provider := &Fosite{Config: new(Config)}

	response := NewClientRegistrationResponse()
	response.SetMetadata(&ClientRegistrationMetadata{RedirectURIs: []string{"https://example.com/cb"}})
	response.SetClientID("abc")
	response.SetStatusCode(http.StatusCreated)

	rw := httptest.NewRecorder()

	provider.WriteRFC7591ClientRegistrationResponse(ctx, rw, NewClientRegistrationRequest(), response)

	assert.Equal(t, http.StatusCreated, rw.Code)
	assert.Equal(t, "application/json; charset=utf-8", rw.Header().Get("Content-Type"))
	assert.Equal(t, "no-store", rw.Header().Get("Cache-Control"))
	assert.Equal(t, "no-cache", rw.Header().Get("Pragma"))
	assert.Contains(t, rw.Body.String(), `"client_id":"abc"`)
}

func TestFositeWriteRFC7591ClientRegistrationError(t *testing.T) {
	provider := &Fosite{Config: new(Config)}

	rw := httptest.NewRecorder()

	provider.WriteRFC7591ClientRegistrationError(context.Background(), rw, NewClientRegistrationRequest(), errorsx.WithStack(ErrInvalidClientMetadata.WithHint("bad metadata")))

	assert.Equal(t, http.StatusBadRequest, rw.Code)
	assert.Contains(t, rw.Body.String(), `"error":"invalid_client_metadata"`)
}

type staticEndpointAuth struct {
	requester Requester
	err       error
}

func (s *staticEndpointAuth) AuthenticateClientRegistrationRequest(_ context.Context, _ *http.Request, _ string) (requester Requester, err error) {
	return s.requester, s.err
}
