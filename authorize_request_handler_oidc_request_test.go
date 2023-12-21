// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/go-jose/go-jose/v3"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
)

func mustGenerateAssertion(t *testing.T, claims jwt.MapClaims, key *rsa.PrivateKey, kid string) string {
	token := jwt.NewWithClaims(jose.RS256, claims)
	if kid != "" {
		token.Header[consts.JSONWebTokenHeaderKeyIdentifier] = kid
	}
	tokenString, err := token.SignedString(key)
	require.NoError(t, err)
	return tokenString
}

func mustGenerateHSAssertion(t *testing.T, claims jwt.MapClaims) string {
	token := jwt.NewWithClaims(jose.HS256, claims)
	tokenString, err := token.SignedString([]byte("aaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbcccccccccccccccccccccddddddddddddddddddddddd"))
	require.NoError(t, err)
	return tokenString
}

func mustGenerateNoneAssertion(t *testing.T, claims jwt.MapClaims) string {
	token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	tokenString, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)
	return tokenString
}

func TestAuthorizeRequestParametersFromOpenIDConnectRequest(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	jwks := &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				KeyID: "kid-foo",
				Use:   "sig",
				Key:   &key.PublicKey,
			},
		},
	}

	validRequestObject := mustGenerateAssertion(t, jwt.MapClaims{consts.FormParameterScope: "foo", "foo": "bar", "baz": "baz", consts.FormParameterResponseType: consts.ResponseTypeImplicitFlowToken, consts.FormParameterResponseMode: consts.ResponseModeFormPost}, key, "kid-foo")
	validRequestObjectWithoutKid := mustGenerateAssertion(t, jwt.MapClaims{consts.FormParameterScope: "foo", "foo": "bar", "baz": "baz"}, key, "")
	validNoneRequestObject := mustGenerateNoneAssertion(t, jwt.MapClaims{consts.FormParameterScope: "foo", "foo": "bar", "baz": "baz", consts.FormParameterState: "some-state"})

	var reqH http.HandlerFunc = func(rw http.ResponseWriter, r *http.Request) {
		rw.Write([]byte(validRequestObject))
	}
	reqTS := httptest.NewServer(reqH)
	defer reqTS.Close()

	var hJWK http.HandlerFunc = func(rw http.ResponseWriter, r *http.Request) {
		require.NoError(t, json.NewEncoder(rw).Encode(jwks))
	}
	reqJWK := httptest.NewServer(hJWK)
	defer reqJWK.Close()

	provider := &Fosite{Config: &Config{JWKSFetcherStrategy: NewDefaultJWKSFetcherStrategy()}}
	for k, tc := range []struct {
		client Client
		form   url.Values
		d      string

		expectErr       error
		expectErrReason string
		expectForm      url.Values
	}{
		{
			d:          "should pass because no request context given and not openid",
			form:       url.Values{},
			expectErr:  nil,
			expectForm: url.Values{},
		},
		{
			d:          "should pass because no request context given",
			form:       url.Values{consts.FormParameterScope: {consts.ScopeOpenID}},
			expectErr:  nil,
			expectForm: url.Values{consts.FormParameterScope: {consts.ScopeOpenID}},
		},
		{
			d:          "should pass because request context given but not openid",
			form:       url.Values{consts.FormParameterRequest: {"foo"}},
			expectErr:  nil,
			expectForm: url.Values{consts.FormParameterRequest: {"foo"}},
		},
		{
			d:          "should fail because not an OpenIDConnect compliant client",
			form:       url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterRequest: {"foo"}},
			expectErr:  ErrRequestNotSupported,
			expectForm: url.Values{consts.FormParameterScope: {consts.ScopeOpenID}},
		},
		{
			d:          "should fail because not an OpenIDConnect compliant client",
			form:       url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterRequestURI: {"foo"}},
			expectErr:  ErrRequestURINotSupported,
			expectForm: url.Values{consts.FormParameterScope: {consts.ScopeOpenID}},
		},
		{
			d:          "should fail because token invalid an no key set",
			form:       url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterRequestURI: {"foo"}},
			client:     &DefaultOpenIDConnectClient{RequestObjectSigningAlgorithm: "RS256"},
			expectErr:  ErrInvalidRequest,
			expectForm: url.Values{consts.FormParameterScope: {consts.ScopeOpenID}},
		},
		{
			d:          "should fail because token invalid",
			form:       url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterRequest: {"foo"}},
			client:     &DefaultOpenIDConnectClient{JSONWebKeys: jwks, RequestObjectSigningAlgorithm: "RS256"},
			expectErr:  ErrInvalidRequestObject,
			expectForm: url.Values{consts.FormParameterScope: {consts.ScopeOpenID}},
		},
		{
			d:               "should fail because kid does not exist",
			form:            url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterRequest: {mustGenerateAssertion(t, jwt.MapClaims{}, key, "does-not-exists")}},
			client:          &DefaultOpenIDConnectClient{JSONWebKeys: jwks, RequestObjectSigningAlgorithm: "RS256"},
			expectErr:       ErrInvalidRequestObject,
			expectErrReason: "Unable to retrieve RSA signing key from OAuth 2.0 Client. The JSON Web Token uses signing key with kid 'does-not-exists', which could not be found.",
			expectForm:      url.Values{consts.FormParameterScope: {consts.ScopeOpenID}},
		},
		{
			d:               "should fail because not RS256 token",
			form:            url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterRequest: {mustGenerateHSAssertion(t, jwt.MapClaims{})}},
			client:          &DefaultOpenIDConnectClient{JSONWebKeys: jwks, RequestObjectSigningAlgorithm: "RS256"},
			expectErr:       ErrInvalidRequestObject,
			expectErrReason: "The request object uses signing algorithm 'HS256', but the requested OAuth 2.0 Client enforces signing algorithm 'RS256'.",
			expectForm:      url.Values{consts.FormParameterScope: {consts.ScopeOpenID}},
		},
		{
			d:      "should pass and set request parameters properly",
			form:   url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow}, consts.FormParameterResponseMode: {consts.ResponseModeNone}, consts.FormParameterRequest: {validRequestObject}},
			client: &DefaultOpenIDConnectClient{JSONWebKeys: jwks, RequestObjectSigningAlgorithm: "RS256"},
			// The values from form are overwritten by the request object.
			expectForm: url.Values{consts.FormParameterResponseType: {consts.ResponseTypeImplicitFlowToken}, consts.FormParameterResponseMode: {consts.ResponseModeFormPost}, consts.FormParameterScope: {"foo openid"}, consts.FormParameterRequest: {validRequestObject}, "foo": {"bar"}, "baz": {"baz"}},
		},
		{
			d:          "should pass even if kid is unset",
			form:       url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterRequest: {validRequestObjectWithoutKid}},
			client:     &DefaultOpenIDConnectClient{JSONWebKeys: jwks, RequestObjectSigningAlgorithm: "RS256"},
			expectForm: url.Values{consts.FormParameterScope: {"foo openid"}, consts.FormParameterRequest: {validRequestObjectWithoutKid}, "foo": {"bar"}, "baz": {"baz"}},
		},
		{
			d:          "should fail because request uri is not whitelisted",
			form:       url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterRequestURI: {reqTS.URL}},
			client:     &DefaultOpenIDConnectClient{JSONWebKeysURI: reqJWK.URL, RequestObjectSigningAlgorithm: "RS256"},
			expectForm: url.Values{consts.FormParameterScope: {"foo openid"}, consts.FormParameterRequestURI: {reqTS.URL}, "foo": {"bar"}, "baz": {"baz"}},
			expectErr:  ErrInvalidRequestURI,
		},
		{
			d:          "should pass and set request_uri parameters properly and also fetch jwk from remote",
			form:       url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterRequestURI: {reqTS.URL}},
			client:     &DefaultOpenIDConnectClient{JSONWebKeysURI: reqJWK.URL, RequestObjectSigningAlgorithm: "RS256", RequestURIs: []string{reqTS.URL}},
			expectForm: url.Values{consts.FormParameterResponseType: {"token"}, consts.FormParameterResponseMode: {consts.ResponseModeFormPost}, consts.FormParameterScope: {"foo openid"}, consts.FormParameterRequestURI: {reqTS.URL}, "foo": {"bar"}, "baz": {"baz"}},
		},
		{
			d:          "should pass when request object uses algorithm none",
			form:       url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterRequest: {validNoneRequestObject}},
			client:     &DefaultOpenIDConnectClient{JSONWebKeysURI: reqJWK.URL, RequestObjectSigningAlgorithm: "none"},
			expectForm: url.Values{consts.FormParameterState: {"some-state"}, consts.FormParameterScope: {"foo openid"}, consts.FormParameterRequest: {validNoneRequestObject}, "foo": {"bar"}, "baz": {"baz"}},
		},
		{
			d:          "should pass when request object uses algorithm none and the client did not explicitly allow any algorithm",
			form:       url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterRequest: {validNoneRequestObject}},
			client:     &DefaultOpenIDConnectClient{JSONWebKeysURI: reqJWK.URL},
			expectForm: url.Values{consts.FormParameterState: {"some-state"}, consts.FormParameterScope: {"foo openid"}, consts.FormParameterRequest: {validNoneRequestObject}, "foo": {"bar"}, "baz": {"baz"}},
		},
	} {
		t.Run(fmt.Sprintf("case=%d/description=%s", k, tc.d), func(t *testing.T) {
			req := &AuthorizeRequest{
				Request: Request{
					Client: tc.client,
					Form:   tc.form,
				},
			}

			err := provider.authorizeRequestParametersFromOpenIDConnectRequest(context.Background(), req, false)
			if tc.expectErr != nil {
				require.EqualError(t, err, tc.expectErr.Error(), "%+v", err)
				if tc.expectErrReason != "" {
					actual := new(RFC6749Error)
					require.True(t, errors.As(err, &actual))
					assert.EqualValues(t, tc.expectErrReason, actual.Reason())
				}
			} else {
				if err != nil {
					actual := new(RFC6749Error)
					errors.As(err, &actual)
					require.NoErrorf(t, err, "Hint: %v\nDebug:%v", actual.HintField, actual.DebugField)
				}
				require.NoErrorf(t, err, "%+v", err)
				require.Equal(t, len(tc.expectForm), len(req.Form))
				for k, v := range tc.expectForm {
					assert.EqualValues(t, v, req.Form[k])
				}
			}
		})
	}
}
