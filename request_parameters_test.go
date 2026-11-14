// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/compose"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
)

func TestValidateRequestParametersNotRepeated(t *testing.T) {
	testCases := []struct {
		name string
		form url.Values
		hint string
	}{
		{name: "ShouldAcceptEmptyForm", form: url.Values{}},
		{name: "ShouldAcceptSingleValues", form: url.Values{consts.FormParameterClientID: {"a"}, consts.FormParameterScope: {"a b"}, consts.FormParameterState: {"s"}}},
		{name: "ShouldAcceptRepeatedResource", form: url.Values{consts.FormParameterResource: {"https://a.example.com", "https://b.example.com"}}},
		{name: "ShouldAcceptRepeatedAudience", form: url.Values{consts.FormParameterAudience: {"a", "b"}}},
		{name: "ShouldAcceptRepeatedUnknownParameter", form: url.Values{"extension": {"a", "b"}}},
		{name: "ShouldRejectRepeatedScope", form: url.Values{consts.FormParameterScope: {"a", "b"}}, hint: "The 'scope' parameter must not be included more than once."},
		{name: "ShouldRejectRepeatedEmptyValues", form: url.Values{consts.FormParameterState: {"", ""}}, hint: "The 'state' parameter must not be included more than once."},
		{name: "ShouldRejectRepeatedGrantType", form: url.Values{consts.FormParameterGrantType: {"a", "a"}}, hint: "The 'grant_type' parameter must not be included more than once."},
		{name: "ShouldRejectRepeatedSubjectToken", form: url.Values{consts.FormParameterSubjectToken: {"a", "b"}, consts.FormParameterAudience: {"a", "b"}}, hint: "The 'subject_token' parameter must not be included more than once."},
		{name: "ShouldRejectRepeatedToken", form: url.Values{consts.FormParameterToken: {"a", "b"}}, hint: "The 'token' parameter must not be included more than once."},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateRequestParametersNotRepeated(tc.form)

			if tc.hint == "" {
				assert.NoError(t, err)

				return
			}

			require.ErrorIs(t, err, ErrInvalidRequest)
			assert.Equal(t, tc.hint, ErrorToRFC6749Error(err).HintField)
		})
	}
}

func TestNewAuthorizeRequestRepeatedParameters(t *testing.T) {
	base := func() url.Values {
		return url.Values{
			consts.FormParameterClientID:     {"repeat"},
			consts.FormParameterRedirectURI:  {"https://client.example.com/cb"},
			consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow},
			consts.FormParameterScope:        {"foo"},
			consts.FormParameterState:        {"strong-enough-state"},
		}
	}

	testCases := []struct {
		name      string
		query     func(query url.Values)
		body      url.Values
		parameter string
		redirect  bool
	}{
		{
			name:      "ShouldRedirectRepeatedScope",
			query:     func(query url.Values) { query.Add(consts.FormParameterScope, "bar") },
			parameter: consts.FormParameterScope,
			redirect:  true,
		},
		{
			name: "ShouldRedirectRepeatedNonce",
			query: func(query url.Values) {
				query[consts.FormParameterNonce] = []string{"strong-enough-nonce", "strong-enough-nonce"}
			},
			parameter: consts.FormParameterNonce,
			redirect:  true,
		},
		{
			name:      "ShouldNotRedirectRepeatedClientID",
			query:     func(query url.Values) { query.Add(consts.FormParameterClientID, "other") },
			parameter: consts.FormParameterClientID,
		},
		{
			name:      "ShouldNotRedirectRepeatedRedirectURI",
			query:     func(query url.Values) { query.Add(consts.FormParameterRedirectURI, "https://client.example.com/cb") },
			parameter: consts.FormParameterRedirectURI,
		},
		{
			name: "ShouldNotRedirectRepeatedResponseType",
			query: func(query url.Values) {
				query.Add(consts.FormParameterResponseType, consts.ResponseTypeImplicitFlowToken)
			},
			parameter: consts.FormParameterResponseType,
		},
		{
			name:      "ShouldNotRedirectRepeatedResponseMode",
			query:     func(query url.Values) { query[consts.FormParameterResponseMode] = []string{"query", "fragment"} },
			parameter: consts.FormParameterResponseMode,
		},
		{
			name:      "ShouldNotRedirectRepeatedState",
			query:     func(query url.Values) { query.Add(consts.FormParameterState, "another-strong-state") },
			parameter: consts.FormParameterState,
		},
		{
			name:      "ShouldNotRedirectClientIDInQueryAndBody",
			body:      url.Values{consts.FormParameterClientID: {"repeat"}},
			parameter: consts.FormParameterClientID,
		},
		{
			name:      "ShouldRedirectScopeInQueryAndBody",
			body:      url.Values{consts.FormParameterScope: {"foo"}},
			parameter: consts.FormParameterScope,
			redirect:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider, _ := newRepeatedParametersProvider()

			query := base()

			if tc.query != nil {
				tc.query(query)
			}

			var r *http.Request

			if tc.body != nil {
				r = httptest.NewRequest(http.MethodPost, "https://auth.example.com/authorize?"+query.Encode(), strings.NewReader(tc.body.Encode()))
				r.Header.Set(consts.HeaderContentType, consts.ContentTypeApplicationURLEncodedForm)
			} else {
				r = httptest.NewRequest(http.MethodGet, "https://auth.example.com/authorize?"+query.Encode(), nil)
			}

			requester, err := provider.NewAuthorizeRequest(t.Context(), r)
			require.ErrorIs(t, err, ErrInvalidRequest)
			assert.Equal(t, "The '"+tc.parameter+"' parameter must not be included more than once.", ErrorToRFC6749Error(err).HintField)

			rw := httptest.NewRecorder()

			provider.WriteAuthorizeError(t.Context(), rw, requester, err)

			if !tc.redirect {
				assert.Equal(t, http.StatusBadRequest, rw.Code)
				assert.Empty(t, rw.Header().Get(consts.HeaderLocation))
				assert.Contains(t, rw.Body.String(), ErrInvalidRequest.ErrorField)

				return
			}

			require.Equal(t, http.StatusSeeOther, rw.Code)

			location, err := url.Parse(rw.Header().Get(consts.HeaderLocation))
			require.NoError(t, err)

			assert.Equal(t, "client.example.com", location.Host)
			assert.Equal(t, ErrInvalidRequest.ErrorField, location.Query().Get(consts.FormParameterError))
			assert.Equal(t, "strong-enough-state", location.Query().Get(consts.FormParameterState))
		})
	}

	t.Run("ShouldAcceptRepeatedResource", func(t *testing.T) {
		provider, _ := newRepeatedParametersProvider()

		query := base()
		query[consts.FormParameterResource] = []string{"https://a.example.com/", "https://b.example.com/"}

		r := httptest.NewRequest(http.MethodGet, "https://auth.example.com/authorize?"+query.Encode(), nil)

		requester, err := provider.NewAuthorizeRequest(t.Context(), r)
		require.NoError(t, ErrorToDebugRFC6749Error(err))

		assert.ElementsMatch(t, []string{"https://a.example.com/", "https://b.example.com/"}, requester.GetRequestedResource())
	})

	t.Run("ShouldRejectRepeatedParameterAlongsideRequestObject", func(t *testing.T) {
		provider, store := newRepeatedParametersProvider()

		key := gen.MustRSAKey()

		store.Clients["jar"] = &DefaultJARClient{
			DefaultClient: &DefaultClient{
				ID:            "jar",
				RedirectURIs:  []string{"https://client.example.com/cb"},
				ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow},
				Scopes:        []string{consts.ScopeOpenID, "foo"},
			},
			JSONWebKeys:             &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{KeyID: "k", Use: "sig", Algorithm: "RS256", Key: &key.PublicKey}}},
			RequestObjectSigningAlg: "RS256",
		}

		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: key, KeyID: "k"}}, (&jose.SignerOptions{}).WithType("oauth-authz-req+jwt"))
		require.NoError(t, err)

		payload, err := json.Marshal(map[string]any{consts.FormParameterClientID: "jar", consts.FormParameterResponseType: consts.ResponseTypeAuthorizationCodeFlow, consts.FormParameterScope: "openid foo"})
		require.NoError(t, err)

		signed, err := signer.Sign(payload)
		require.NoError(t, err)

		assertion, err := signed.CompactSerialize()
		require.NoError(t, err)

		query := base()
		query.Set(consts.FormParameterClientID, "jar")
		query[consts.FormParameterScope] = []string{"openid", "openid foo"}
		query.Set(consts.FormParameterRequest, assertion)

		r := httptest.NewRequest(http.MethodGet, "https://auth.example.com/authorize?"+query.Encode(), nil)

		_, err = provider.NewAuthorizeRequest(t.Context(), r)
		require.ErrorIs(t, err, ErrInvalidRequest)
		assert.Equal(t, "The 'scope' parameter must not be included more than once.", ErrorToRFC6749Error(err).HintField)
	})

	t.Run("ShouldRejectRepeatedParameterAlongsidePushedRequestURI", func(t *testing.T) {
		provider, _ := newRepeatedParametersProvider()

		push := base()

		r := httptest.NewRequest(http.MethodPost, "https://auth.example.com/par", strings.NewReader(push.Encode()))
		r.Header.Set(consts.HeaderContentType, consts.ContentTypeApplicationURLEncodedForm)
		r.SetBasicAuth("repeat", "foobar")

		pushed, err := provider.NewPushedAuthorizeRequest(t.Context(), r)
		require.NoError(t, ErrorToDebugRFC6749Error(err))

		response, err := provider.NewPushedAuthorizeResponse(t.Context(), pushed, &DefaultSession{})
		require.NoError(t, ErrorToDebugRFC6749Error(err))

		query := url.Values{
			consts.FormParameterClientID:   {"repeat"},
			consts.FormParameterRequestURI: {response.GetRequestURI()},
			consts.FormParameterScope:      {"foo", "bar"},
		}

		r = httptest.NewRequest(http.MethodGet, "https://auth.example.com/authorize?"+query.Encode(), nil)

		requester, err := provider.NewAuthorizeRequest(t.Context(), r)
		require.ErrorIs(t, err, ErrInvalidRequest)
		assert.Equal(t, "The 'scope' parameter must not be included more than once.", ErrorToRFC6749Error(err).HintField)

		rw := httptest.NewRecorder()

		provider.WriteAuthorizeError(t.Context(), rw, requester, err)

		require.Equal(t, http.StatusSeeOther, rw.Code)

		location, err := url.Parse(rw.Header().Get(consts.HeaderLocation))
		require.NoError(t, err)

		assert.Equal(t, ErrInvalidRequest.ErrorField, location.Query().Get(consts.FormParameterError))
		assert.Equal(t, "strong-enough-state", location.Query().Get(consts.FormParameterState))
	})
}

func TestNewPushedAuthorizeRequestRepeatedParameters(t *testing.T) {
	base := func() url.Values {
		return url.Values{
			consts.FormParameterRedirectURI:  {"https://client.example.com/cb"},
			consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow},
			consts.FormParameterScope:        {"foo"},
			consts.FormParameterState:        {"strong-enough-state"},
		}
	}

	testCases := []struct {
		name      string
		query     url.Values
		body      func(body url.Values)
		parameter string
	}{
		{
			name:      "ShouldRejectRepeatedScope",
			body:      func(body url.Values) { body.Add(consts.FormParameterScope, "bar") },
			parameter: consts.FormParameterScope,
		},
		{
			name:      "ShouldRejectRepeatedClientSecret",
			body:      func(body url.Values) { body[consts.FormParameterClientSecret] = []string{"foobar", "other"} },
			parameter: consts.FormParameterClientSecret,
		},
		{
			name:      "ShouldRejectRedirectURIInQueryAndBody",
			query:     url.Values{consts.FormParameterRedirectURI: {"https://client.example.com/cb"}},
			parameter: consts.FormParameterRedirectURI,
		},
		{
			name: "ShouldAcceptRepeatedResource",
			body: func(body url.Values) {
				body[consts.FormParameterResource] = []string{"https://a.example.com/", "https://b.example.com/"}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider, _ := newRepeatedParametersProvider()

			body := base()

			if tc.body != nil {
				tc.body(body)
			}

			r := httptest.NewRequest(http.MethodPost, "https://auth.example.com/par?"+tc.query.Encode(), strings.NewReader(body.Encode()))
			r.Header.Set(consts.HeaderContentType, consts.ContentTypeApplicationURLEncodedForm)
			r.SetBasicAuth("repeat", "foobar")

			requester, err := provider.NewPushedAuthorizeRequest(t.Context(), r)

			if tc.parameter == "" {
				require.NoError(t, ErrorToDebugRFC6749Error(err))
				assert.ElementsMatch(t, []string{"https://a.example.com/", "https://b.example.com/"}, requester.GetRequestedResource())

				return
			}

			require.ErrorIs(t, err, ErrInvalidRequest)
			assert.Equal(t, "The '"+tc.parameter+"' parameter must not be included more than once.", ErrorToRFC6749Error(err).HintField)
		})
	}
}

func TestNewAccessRequestRepeatedParameters(t *testing.T) {
	testCases := []struct {
		name      string
		form      url.Values
		parameter string
	}{
		{
			name:      "ShouldRejectRepeatedGrantType",
			form:      url.Values{consts.FormParameterGrantType: {"client_credentials", "password"}},
			parameter: consts.FormParameterGrantType,
		},
		{
			name:      "ShouldRejectRepeatedScope",
			form:      url.Values{consts.FormParameterGrantType: {"client_credentials"}, consts.FormParameterScope: {"foo", "bar"}},
			parameter: consts.FormParameterScope,
		},
		{
			name:      "ShouldRejectRepeatedCode",
			form:      url.Values{consts.FormParameterGrantType: {"authorization_code"}, consts.FormParameterAuthorizationCode: {"a", "b"}},
			parameter: consts.FormParameterAuthorizationCode,
		},
		{
			name: "ShouldAcceptRepeatedResource",
			form: url.Values{consts.FormParameterGrantType: {"client_credentials"}, consts.FormParameterResource: {"https://a.example.com/", "https://b.example.com/"}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider, _ := newRepeatedParametersProvider()

			requester, err := provider.NewAccessRequest(t.Context(), newRepeatedParametersPostRequest("https://auth.example.com/token", tc.form), &DefaultSession{})

			if tc.parameter == "" {
				require.NoError(t, ErrorToDebugRFC6749Error(err))
				assert.ElementsMatch(t, []string{"https://a.example.com/", "https://b.example.com/"}, requester.GetRequestedResource())

				return
			}

			require.ErrorIs(t, err, ErrInvalidRequest)
			assert.Equal(t, "The '"+tc.parameter+"' parameter must not be included more than once.", ErrorToRFC6749Error(err).HintField)
		})
	}
}

func TestNewRevocationRequestRepeatedParameters(t *testing.T) {
	testCases := []struct {
		name      string
		form      url.Values
		parameter string
	}{
		{
			name:      "ShouldRejectRepeatedToken",
			form:      url.Values{consts.FormParameterToken: {"a", "b"}},
			parameter: consts.FormParameterToken,
		},
		{
			name:      "ShouldRejectRepeatedTokenTypeHint",
			form:      url.Values{consts.FormParameterToken: {"a"}, consts.FormParameterTokenTypeHint: {"access_token", "refresh_token"}},
			parameter: consts.FormParameterTokenTypeHint,
		},
		{
			name: "ShouldAcceptRepeatedResource",
			form: url.Values{consts.FormParameterToken: {"a"}, consts.FormParameterResource: {"https://a.example.com/", "https://b.example.com/"}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider, _ := newRepeatedParametersProvider()

			err := provider.NewRevocationRequest(t.Context(), newRepeatedParametersPostRequest("https://auth.example.com/revoke", tc.form))

			if tc.parameter == "" {
				assert.NoError(t, ErrorToDebugRFC6749Error(err))

				return
			}

			require.ErrorIs(t, err, ErrInvalidRequest)
			assert.Equal(t, "The '"+tc.parameter+"' parameter must not be included more than once.", ErrorToRFC6749Error(err).HintField)
		})
	}
}

func TestNewIntrospectionRequestRepeatedParameters(t *testing.T) {
	testCases := []struct {
		name      string
		form      func(token string) url.Values
		parameter string
	}{
		{
			name:      "ShouldRejectRepeatedToken",
			form:      func(token string) url.Values { return url.Values{consts.FormParameterToken: {token, "other"}} },
			parameter: consts.FormParameterToken,
		},
		{
			name: "ShouldRejectRepeatedTokenTypeHint",
			form: func(token string) url.Values {
				return url.Values{consts.FormParameterToken: {token}, consts.FormParameterTokenTypeHint: {"access_token", "refresh_token"}}
			},
			parameter: consts.FormParameterTokenTypeHint,
		},
		{
			name: "ShouldAcceptRepeatedResource",
			form: func(token string) url.Values {
				return url.Values{consts.FormParameterToken: {token}, consts.FormParameterResource: {"https://a.example.com/", "https://b.example.com/"}}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider, _ := newRepeatedParametersProvider()

			requester, err := provider.NewAccessRequest(t.Context(), newRepeatedParametersPostRequest("https://auth.example.com/token", url.Values{consts.FormParameterGrantType: {"client_credentials"}}), &DefaultSession{})
			require.NoError(t, ErrorToDebugRFC6749Error(err))

			response, err := provider.NewAccessResponse(t.Context(), requester)
			require.NoError(t, ErrorToDebugRFC6749Error(err))

			introspection, err := provider.NewIntrospectionRequest(t.Context(), newRepeatedParametersPostRequest("https://auth.example.com/introspect", tc.form(response.GetAccessToken())), &DefaultSession{})

			if tc.parameter == "" {
				require.NoError(t, ErrorToDebugRFC6749Error(err))
				assert.True(t, introspection.IsActive())

				return
			}

			require.ErrorIs(t, err, ErrInvalidRequest)
			assert.Equal(t, "The '"+tc.parameter+"' parameter must not be included more than once.", ErrorToRFC6749Error(err).HintField)
		})
	}
}

func TestNewDeviceAuthorizeRequestRepeatedParameters(t *testing.T) {
	testCases := []struct {
		name      string
		form      url.Values
		parameter string
	}{
		{
			name:      "ShouldRejectRepeatedScope",
			form:      url.Values{consts.FormParameterScope: {"foo", "bar"}},
			parameter: consts.FormParameterScope,
		},
		{
			name:      "ShouldRejectRepeatedClientID",
			form:      url.Values{consts.FormParameterClientID: {"repeat", "repeat"}},
			parameter: consts.FormParameterClientID,
		},
		{
			name: "ShouldAcceptRepeatedResource",
			form: url.Values{consts.FormParameterScope: {"foo"}, consts.FormParameterResource: {"https://a.example.com/", "https://b.example.com/"}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider, _ := newRepeatedParametersProvider()

			requester, err := provider.NewRFC862DeviceAuthorizeRequest(t.Context(), newRepeatedParametersPostRequest("https://auth.example.com/device", tc.form))

			if tc.parameter == "" {
				require.NoError(t, ErrorToDebugRFC6749Error(err))
				assert.ElementsMatch(t, []string{"https://a.example.com/", "https://b.example.com/"}, requester.GetRequestedResource())

				return
			}

			require.ErrorIs(t, err, ErrInvalidRequest)
			assert.Equal(t, "The '"+tc.parameter+"' parameter must not be included more than once.", ErrorToRFC6749Error(err).HintField)
		})
	}
}

func newRepeatedParametersProvider() (provider *Fosite, store *storage.MemoryStore) {
	store = storage.NewMemoryStore()

	store.Clients["repeat"] = &DefaultClient{
		ID:            "repeat",
		ClientSecret:  NewBCryptClientSecret(`$2a$04$6i/O2OM9CcEVTRLq9uFDtOze4AtISH79iYkZeEUsos4WzWtCnJ52y`),
		RedirectURIs:  []string{"https://client.example.com/cb"},
		ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow},
		GrantTypes:    []string{consts.GrantTypeAuthorizationCode, consts.GrantTypeClientCredentials, consts.GrantTypeOAuthDeviceCode},
		Scopes:        []string{"foo", "bar"},
		Resource:      []string{"https://a.example.com/", "https://b.example.com/"},
	}

	config := &Config{
		ScopeStrategy:                         ExactScopeStrategy,
		Issuer:                                "https://auth.example.com",
		GlobalSecret:                          []byte("some-super-cool-secret-that-nobody-knows"),
		RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b"),
	}

	return compose.ComposeAllEnabled(config, store, nil).(*Fosite), store
}

func newRepeatedParametersPostRequest(target string, form url.Values) (r *http.Request) {
	r = httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	r.Header.Set(consts.HeaderContentType, consts.ContentTypeApplicationURLEncodedForm)
	r.SetBasicAuth("repeat", "foobar")

	return r
}
