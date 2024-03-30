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
	"regexp"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestAuthorizeRequestParametersFromOpenIDConnectRequestObject(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec
	require.NoError(t, err)

	jwks := &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				KeyID: "kid-foo",
				Use:   "sig",
				Key:   &key.PublicKey,
			},
		},
	}

	assertionRequestObjectValid := mustGenerateAssertion(t, jwt.MapClaims{consts.ClaimIssuer: "foo", consts.ClaimClientIdentifier: "foo", consts.ClaimAudience: []string{"https://auth.example.com"}, consts.FormParameterScope: "foo", "foo": "bar", "baz": "baz", consts.FormParameterResponseType: consts.ResponseTypeImplicitFlowToken, consts.FormParameterResponseMode: consts.ResponseModeFormPost}, key, "kid-foo")
	assertionRequestObjectInvalidRequestInRequest := mustGenerateAssertion(t, jwt.MapClaims{consts.ClaimIssuer: "foo", consts.FormParameterRequest: "abc", consts.ClaimClientIdentifier: "foo", consts.ClaimAudience: []string{"https://auth.example.com"}, consts.FormParameterScope: "foo", "foo": "bar", "baz": "baz", consts.FormParameterResponseType: consts.ResponseTypeImplicitFlowToken, consts.FormParameterResponseMode: consts.ResponseModeFormPost}, key, "kid-foo")
	assertionRequestObjectInvalidRequestURIInRequest := mustGenerateAssertion(t, jwt.MapClaims{consts.ClaimIssuer: "foo", consts.FormParameterRequestURI: "https://auth.example.com", consts.ClaimClientIdentifier: "foo", consts.ClaimAudience: []string{"https://auth.example.com"}, consts.FormParameterScope: "foo", "foo": "bar", "baz": "baz", consts.FormParameterResponseType: consts.ResponseTypeImplicitFlowToken, consts.FormParameterResponseMode: consts.ResponseModeFormPost}, key, "kid-foo")
	assertionRequestObjectInvalidClientIDValue := mustGenerateAssertion(t, jwt.MapClaims{consts.ClaimIssuer: "foo", consts.ClaimClientIdentifier: 100, consts.ClaimAudience: []string{"https://auth.example.com"}, consts.FormParameterScope: "foo", "foo": "bar", "baz": "baz", consts.FormParameterResponseType: consts.ResponseTypeImplicitFlowToken, consts.FormParameterResponseMode: consts.ResponseModeFormPost}, key, "kid-foo")
	assertionRequestObjectInvalidResponseTypeValue := mustGenerateAssertion(t, jwt.MapClaims{consts.ClaimIssuer: "foo", consts.ClaimAudience: []string{"https://auth.example.com"}, consts.FormParameterScope: "foo", "foo": "bar", "baz": "baz", consts.FormParameterResponseType: 100, consts.FormParameterResponseMode: consts.ResponseModeFormPost}, key, "kid-foo")
	assertionRequestObjectInvalidAudience := mustGenerateAssertion(t, jwt.MapClaims{consts.ClaimIssuer: "foo", consts.ClaimAudience: []string{"https://auth.not-example.com"}, consts.FormParameterScope: "foo", "foo": "bar", "baz": "baz", consts.FormParameterResponseType: consts.ResponseTypeAuthorizationCodeFlow, consts.FormParameterResponseMode: consts.ResponseModeFormPost}, key, "kid-foo")
	assertionRequestObjectInvalidIssuer := mustGenerateAssertion(t, jwt.MapClaims{consts.ClaimIssuer: "not-foo", consts.ClaimAudience: []string{"https://auth.example.com"}, consts.FormParameterScope: "foo", "foo": "bar", "baz": "baz", consts.FormParameterResponseType: consts.ResponseTypeAuthorizationCodeFlow, consts.FormParameterResponseMode: consts.ResponseModeFormPost}, key, "kid-foo")
	assertionRequestObjectValidWithoutKID := mustGenerateAssertion(t, jwt.MapClaims{consts.ClaimIssuer: "foo", consts.ClaimAudience: []string{"https://auth.example.com"}, consts.FormParameterScope: "foo", "foo": "bar", "baz": "baz"}, key, "")
	assertionRequestObjectValidNone := mustGenerateNoneAssertion(t, jwt.MapClaims{consts.FormParameterScope: "foo", "foo": "bar", "baz": "baz", consts.FormParameterState: "some-state"})

	mux := http.NewServeMux()

	var handlerJWKS http.HandlerFunc = func(rw http.ResponseWriter, r *http.Request) {
		require.NoError(t, json.NewEncoder(rw).Encode(jwks))
	}

	handleString := func(in string) http.HandlerFunc {
		var h http.HandlerFunc = func(rw http.ResponseWriter, r *http.Request) {
			_, _ = rw.Write([]byte(in))
		}

		return h
	}

	mux.Handle("/jwks.json", handlerJWKS)
	mux.Handle("/request-object/valid/standard.jwk", handleString(assertionRequestObjectValid))
	mux.Handle("/request-object/invalid/issuer.jwk", handleString(assertionRequestObjectInvalidIssuer))
	mux.Handle("/request-object/invalid/audience.jwk", handleString(assertionRequestObjectInvalidAudience))
	mux.Handle("/request-object/invalid/response-type-value.jwk", handleString(assertionRequestObjectInvalidResponseTypeValue))
	mux.Handle("/request-object/invalid/client-id-value.jwk", handleString(assertionRequestObjectInvalidClientIDValue))
	mux.Handle("/request-object/invalid/has-request.jwk", handleString(assertionRequestObjectInvalidRequestInRequest))
	mux.Handle("/request-object/invalid/has-request-uri.jwk", handleString(assertionRequestObjectInvalidRequestURIInRequest))
	mux.Handle("/request-object/valid/without-kid.jwk", handleString(assertionRequestObjectValidWithoutKID))
	mux.Handle("/request-object/valid/none.jwk", handleString(assertionRequestObjectValidNone))

	server := httptest.NewServer(mux)
	defer server.Close()

	root, err := url.ParseRequestURI(server.URL)
	require.NoError(t, err)

	testCases := []struct {
		name      string
		have      url.Values
		par       bool
		client    Client
		expected  url.Values
		err       error
		errString string
		errRegex  *regexp.Regexp
	}{
		{
			name:     "ShouldPassWithoutRequestObject",
			have:     url.Values{consts.FormParameterScope: {consts.ScopeOpenID}},
			expected: url.Values{consts.FormParameterScope: {consts.ScopeOpenID}},
		},
		{
			name:     "ShouldPassWithoutRequestObjectAndNotOpenID",
			have:     url.Values{},
			expected: url.Values{},
		},
		{
			name:     "ShouldPassRequestWithRequestObjectNotOpenID",
			have:     url.Values{consts.FormParameterRequest: {"foo"}},
			client:   &DefaultClient{ID: "foo"},
			expected: url.Values{consts.FormParameterRequest: {"foo"}},
		},
		{
			name:     "ShouldPassRequest",
			have:     url.Values{consts.FormParameterScope: {"foo openid"}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeImplicitFlowToken}, consts.FormParameterRequest: {assertionRequestObjectValid}},
			client:   &DefaultOpenIDConnectClient{JSONWebKeys: jwks, RequestObjectSigningAlg: "RS256", DefaultClient: &DefaultClient{ID: "foo"}},
			expected: url.Values{consts.FormParameterScope: {"foo openid"}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeImplicitFlowToken}, consts.FormParameterResponseMode: {consts.ResponseModeFormPost}, consts.FormParameterRequest: {assertionRequestObjectValid}, "foo": {"bar"}, "baz": {"baz"}},
		},
		{
			name:      "ShouldFailRequestNotOpenIDConnectClient",
			have:      url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterRequest: {"foo"}},
			client:    &DefaultClient{ID: "foo"},
			expected:  url.Values{consts.FormParameterScope: {consts.ScopeOpenID}},
			err:       ErrRequestNotSupported,
			errString: "The OP does not support use of the request parameter. OpenID Connect 1.0 parameter 'request' was used, but the OAuth 2.0 Client does not implement advanced OpenID Connect 1.0 capabilities. The OAuth 2.0 client with id 'foo' doesn't implement the correct functionality for this request.",
		},
		{
			name:      "ShouldFailRequestURINotOpenIDConnectClient",
			have:      url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterRequestURI: {"foo"}},
			client:    &DefaultClient{ID: "foo"},
			expected:  url.Values{consts.FormParameterScope: {consts.ScopeOpenID}},
			err:       ErrRequestURINotSupported,
			errString: "The OP does not support use of the request_uri parameter. OpenID Connect 1.0 parameter 'request_uri' was used, but the OAuth 2.0 Client does not implement advanced OpenID Connect 1.0 capabilities. The OAuth 2.0 client with id 'foo' doesn't implement the correct functionality for this request.",
		},
		{
			name:      "ShouldFailRequestAndRequestURI",
			have:      url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterRequest: {"foo"}, consts.FormParameterRequestURI: {"foo"}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow}},
			client:    &DefaultOpenIDConnectClient{RequestObjectSigningAlg: "", DefaultClient: &DefaultClient{ID: "foo"}},
			par:       true,
			expected:  url.Values{consts.FormParameterRequest: {"foo"}},
			err:       ErrInvalidRequest,
			errString: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. OpenID Connect 1.0 parameters 'request' and 'request_uri' were both used, but only one may be used in any given request.",
		},
		{
			name:      "ShouldFailRequestMissingResponseType",
			have:      url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterRequest: {"foo"}, consts.FormParameterClientID: {"foo"}},
			client:    &DefaultOpenIDConnectClient{RequestObjectSigningAlg: "", DefaultClient: &DefaultClient{ID: "foo"}},
			par:       true,
			expected:  url.Values{consts.FormParameterRequest: {"foo"}},
			err:       ErrInvalidRequest,
			errString: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. OpenID Connect 1.0 parameter 'request' must be accompanied by the `client_id' and 'response_type' in the request syntax. The OAuth 2.0 client with id 'foo' provided the 'request' with value but either did not include the 'client_id' or 'response_type' parameter.",
		},
		{
			name:      "ShouldFailRequestMissingClientID",
			have:      url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterRequest: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow}},
			client:    &DefaultOpenIDConnectClient{RequestObjectSigningAlg: "", DefaultClient: &DefaultClient{ID: "foo"}},
			par:       true,
			expected:  url.Values{consts.FormParameterRequest: {"foo"}},
			err:       ErrInvalidRequest,
			errString: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. OpenID Connect 1.0 parameter 'request' must be accompanied by the `client_id' and 'response_type' in the request syntax. The OAuth 2.0 client with id 'foo' provided the 'request' with value but either did not include the 'client_id' or 'response_type' parameter.",
		},
		{
			name:      "ShouldFailRequestURIWithPAR",
			have:      url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterRequestURI: {"foo"}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow}},
			client:    &DefaultOpenIDConnectClient{RequestObjectSigningAlg: "", DefaultClient: &DefaultClient{ID: "foo"}},
			par:       true,
			expected:  url.Values{consts.FormParameterRequest: {"foo"}},
			err:       ErrInvalidRequest,
			errString: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. OpenID Connect 1.0 parameter 'request_uri' was used, but must not be used with a Pushed Authorization Request. The OAuth 2.0 client with id 'foo' attempted to perform an invalid Authorization Request.",
		},
		{
			name:      "ShouldFailRequestClientNoJWKS",
			have:      url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterRequest: {"foo"}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow}},
			client:    &DefaultOpenIDConnectClient{RequestObjectSigningAlg: "RS256", DefaultClient: &DefaultClient{ID: "foo"}},
			expected:  url.Values{consts.FormParameterScope: {consts.ScopeOpenID}},
			err:       ErrInvalidRequest,
			errString: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. OpenID Connect 1.0 parameter 'request' was used, but the OAuth 2.0 Client does not have any JSON Web Keys registered. The OAuth 2.0 client with id 'foo' doesn't have any known JSON Web Keys but requires them when not explicitly registered with a 'request_object_signing_alg' with the value of 'none' or an empty value but it's registered with 'RS256'.",
		},
		{
			name:      "ShouldFailRequestURIClientNoJWKS",
			have:      url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterRequestURI: {"foo"}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow}},
			client:    &DefaultOpenIDConnectClient{RequestObjectSigningAlg: "RS256", DefaultClient: &DefaultClient{ID: "foo"}},
			expected:  url.Values{consts.FormParameterScope: {consts.ScopeOpenID}},
			err:       ErrInvalidRequest,
			errString: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. OpenID Connect 1.0 parameter 'request_uri' was used, but the OAuth 2.0 Client does not have any JSON Web Keys registered. The OAuth 2.0 client with id 'foo' doesn't have any known JSON Web Keys but requires them when not explicitly registered with a 'request_object_signing_alg' with the value of 'none' or an empty value but it's registered with 'RS256'.",
		},
		{
			name:      "ShouldFailInvalidTokenMalformed",
			have:      url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow}, consts.FormParameterRequest: {"bad-token"}},
			client:    &DefaultOpenIDConnectClient{JSONWebKeys: jwks, RequestObjectSigningAlg: "RS256", DefaultClient: &DefaultClient{ID: "foo"}},
			expected:  url.Values{consts.FormParameterScope: {consts.ScopeOpenID}},
			err:       ErrInvalidRequestObject,
			errString: "The request parameter contains an invalid Request Object. Unable to verify the request object's signature. go-jose/go-jose: compact JWS format must have three parts",
		},
		{
			name:      "ShouldFailUnknownKID",
			have:      url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow}, consts.FormParameterRequest: {mustGenerateAssertion(t, jwt.MapClaims{}, key, "does-not-exists")}},
			client:    &DefaultOpenIDConnectClient{JSONWebKeys: jwks, RequestObjectSigningAlg: "RS256", DefaultClient: &DefaultClient{ID: "test"}},
			expected:  url.Values{consts.FormParameterScope: {consts.ScopeOpenID}},
			err:       ErrInvalidRequestObject,
			errString: "The request parameter contains an invalid Request Object. Unable to retrieve RSA signing key from OAuth 2.0 Client. The JSON Web Token uses signing key with kid 'does-not-exists', which could not be found. The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The JSON Web Token uses signing key with kid 'does-not-exists', which could not be found.",
		},
		{
			name:      "ShouldFailBadAlgRS256",
			have:      url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow}, consts.FormParameterRequest: {mustGenerateHSAssertion(t, jwt.MapClaims{})}},
			client:    &DefaultOpenIDConnectClient{JSONWebKeys: jwks, RequestObjectSigningAlg: "RS256", DefaultClient: &DefaultClient{ID: "test"}},
			expected:  url.Values{consts.FormParameterScope: {consts.ScopeOpenID}},
			err:       ErrInvalidRequestObject,
			errString: "The request parameter contains an invalid Request Object. The request object uses signing algorithm 'HS256', but the requested OAuth 2.0 Client enforces signing algorithm 'RS256'. The OAuth 2.0 client with id 'test' made the Authorization Request.",
		},
		{
			name:      "ShouldFailMismatchedClientID",
			have:      url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterClientID: {"not-foo"}, consts.FormParameterResponseType: {consts.ResponseTypeImplicitFlowToken}, consts.FormParameterResponseMode: {consts.ResponseModeNone}, consts.FormParameterRequest: {assertionRequestObjectValid}},
			client:    &DefaultOpenIDConnectClient{JSONWebKeys: jwks, RequestObjectSigningAlg: "RS256", DefaultClient: &DefaultClient{ID: "foo"}},
			expected:  url.Values{consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeImplicitFlowToken}, consts.FormParameterResponseMode: {consts.ResponseModeFormPost}, consts.FormParameterScope: {"foo openid"}, consts.FormParameterRequest: {assertionRequestObjectValid}, "foo": {"bar"}, "baz": {"baz"}},
			err:       ErrInvalidRequestObject,
			errString: "The request parameter contains an invalid Request Object. OpenID Connect 1.0 request object's `client_id' claim if provided must match the values provided in the standard OAuth 2.0 request syntax. The OAuth 2.0 client with id 'foo' included a 'client_id' claim with a value of 'foo' in the request object which is required to match the value in the OAuth 2.0 request syntax but the value 'not-foo' was included instead.",
		},
		{
			name:      "ShouldFailRequestClientIDAssert",
			have:      url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterClientID: {"not-foo"}, consts.FormParameterResponseType: {consts.ResponseTypeImplicitFlowToken}, consts.FormParameterResponseMode: {consts.ResponseModeNone}, consts.FormParameterRequest: {assertionRequestObjectInvalidClientIDValue}},
			client:    &DefaultOpenIDConnectClient{JSONWebKeys: jwks, RequestObjectSigningAlg: "RS256", DefaultClient: &DefaultClient{ID: "foo"}},
			expected:  url.Values{consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeImplicitFlowToken}, consts.FormParameterResponseMode: {consts.ResponseModeFormPost}, consts.FormParameterScope: {"foo openid"}, consts.FormParameterRequest: {assertionRequestObjectInvalidClientIDValue}, "foo": {"bar"}, "baz": {"baz"}},
			err:       ErrInvalidRequestObject,
			errString: "The request parameter contains an invalid Request Object. OpenID Connect 1.0 request object's `client_id' claim if provided must match the values provided in the standard OAuth 2.0 request syntax. The OAuth 2.0 client with id 'foo' included a 'client_id' claim with a value of '100' which is meant to be a string, not a int64.",
		},
		{
			name:      "ShouldFailRequestWithRequest",
			have:      url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeImplicitFlowToken}, consts.FormParameterResponseMode: {consts.ResponseModeNone}, consts.FormParameterRequest: {assertionRequestObjectInvalidRequestInRequest}},
			client:    &DefaultOpenIDConnectClient{JSONWebKeys: jwks, RequestObjectSigningAlg: "RS256", DefaultClient: &DefaultClient{ID: "foo"}},
			expected:  url.Values{consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeImplicitFlowToken}, consts.FormParameterResponseMode: {consts.ResponseModeFormPost}, consts.FormParameterScope: {"foo openid"}, consts.FormParameterRequest: {assertionRequestObjectInvalidRequestInRequest}, "foo": {"bar"}, "baz": {"baz"}},
			err:       ErrInvalidRequestObject,
			errString: "The request parameter contains an invalid Request Object. OpenID Connect 1.0 request object must not contain the 'request' or 'request_uri' claims. The OAuth 2.0 client with id 'foo' made the Authorization Request.",
		},
		{
			name:      "ShouldFailRequestWithRequestURI",
			have:      url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeImplicitFlowToken}, consts.FormParameterResponseMode: {consts.ResponseModeNone}, consts.FormParameterRequest: {assertionRequestObjectInvalidRequestURIInRequest}},
			client:    &DefaultOpenIDConnectClient{JSONWebKeys: jwks, RequestObjectSigningAlg: "RS256", DefaultClient: &DefaultClient{ID: "foo"}},
			expected:  url.Values{consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeImplicitFlowToken}, consts.FormParameterResponseMode: {consts.ResponseModeFormPost}, consts.FormParameterScope: {"foo openid"}, consts.FormParameterRequest: {assertionRequestObjectInvalidRequestURIInRequest}, "foo": {"bar"}, "baz": {"baz"}},
			err:       ErrInvalidRequestObject,
			errString: "The request parameter contains an invalid Request Object. OpenID Connect 1.0 request object must not contain the 'request' or 'request_uri' claims. The OAuth 2.0 client with id 'foo' made the Authorization Request.",
		},
		{
			name:      "ShouldFailMismatchedResponseType",
			have:      url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow}, consts.FormParameterResponseMode: {consts.ResponseModeNone}, consts.FormParameterRequest: {assertionRequestObjectValid}},
			client:    &DefaultOpenIDConnectClient{JSONWebKeys: jwks, RequestObjectSigningAlg: "RS256", DefaultClient: &DefaultClient{ID: "foo"}},
			expected:  url.Values{consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeImplicitFlowToken}, consts.FormParameterResponseMode: {consts.ResponseModeFormPost}, consts.FormParameterScope: {"foo openid"}, consts.FormParameterRequest: {assertionRequestObjectValid}, "foo": {"bar"}, "baz": {"baz"}},
			err:       ErrInvalidRequestObject,
			errString: "The request parameter contains an invalid Request Object. OpenID Connect 1.0 request object's `response_type' claim if provided must match the values provided in the standard OAuth 2.0 request syntax. The OAuth 2.0 client with id 'foo' included a 'response_type' claim with a value of 'token' in the request object which when provided is required to match the value in the OAuth 2.0 request syntax but the value 'code' was included instead.",
		},
		{
			name:      "ShouldFailMismatchedResponseTypeAsserted",
			have:      url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow}, consts.FormParameterResponseMode: {consts.ResponseModeNone}, consts.FormParameterRequest: {assertionRequestObjectInvalidResponseTypeValue}},
			client:    &DefaultOpenIDConnectClient{JSONWebKeys: jwks, RequestObjectSigningAlg: "RS256", DefaultClient: &DefaultClient{ID: "foo"}},
			expected:  url.Values{consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeImplicitFlowToken}, consts.FormParameterResponseMode: {consts.ResponseModeFormPost}, consts.FormParameterScope: {"foo openid"}, consts.FormParameterRequest: {assertionRequestObjectInvalidResponseTypeValue}, "foo": {"bar"}, "baz": {"baz"}},
			err:       ErrInvalidRequestObject,
			errString: "The request parameter contains an invalid Request Object. OpenID Connect 1.0 request object's `response_type' claim if provided must match the values provided in the standard OAuth 2.0 request syntax. The OAuth 2.0 client with id 'foo' included a 'response_type' claim with a value of '100' which is meant to be a string, not a int64.",
		},
		{
			name:     "ShouldPassWithoutKID",
			have:     url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow}, consts.FormParameterRequest: {assertionRequestObjectValidWithoutKID}},
			client:   &DefaultOpenIDConnectClient{JSONWebKeys: jwks, RequestObjectSigningAlg: "RS256", DefaultClient: &DefaultClient{ID: "foo"}},
			expected: url.Values{consts.FormParameterScope: {"foo openid"}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow}, consts.FormParameterRequest: {assertionRequestObjectValidWithoutKID}, "foo": {"bar"}, "baz": {"baz"}},
		},
		{
			name:     "ShouldFailRequestURINotWhiteListed",
			have:     url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow}, consts.FormParameterRequestURI: {root.JoinPath("request-object", "valid", "standard.jwk").String()}},
			client:   &DefaultOpenIDConnectClient{JSONWebKeys: jwks, RequestObjectSigningAlg: "RS256", DefaultClient: &DefaultClient{ID: "foo"}},
			expected: url.Values{consts.FormParameterScope: {"foo openid"}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow}, consts.FormParameterRequest: {assertionRequestObjectValidWithoutKID}, "foo": {"bar"}, "baz": {"baz"}},
			err:      ErrInvalidRequestURI,
			errRegex: regexp.MustCompile(`^The request_uri in the Authorization Request returns an error or contains invalid data\. OpenID Connect 1\.0 parameter 'request_uri' does not exist in the registered OAuth 2.0 registered 'request_uris' and is therefore not whitelisted. The OAuth 2.0 client with id 'foo' provided the 'request_uri' parameter with value 'http://127\.0\.0\.1:\d+/request-object/valid/standard\.jwk' which is not whitelisted.`),
		},
		{
			name:     "ShouldPassRequestURIFetch",
			have:     url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeImplicitFlowToken}, consts.FormParameterRequestURI: {root.JoinPath("request-object", "valid", "standard.jwk").String()}},
			client:   &DefaultOpenIDConnectClient{JSONWebKeysURI: root.JoinPath("jwks.json").String(), RequestObjectSigningAlg: "RS256", RequestURIs: []string{root.JoinPath("request-object", "valid", "standard.jwk").String()}, DefaultClient: &DefaultClient{ID: "foo"}},
			expected: url.Values{consts.FormParameterResponseType: {"token"}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseMode: {consts.ResponseModeFormPost}, consts.FormParameterScope: {"foo openid"}, consts.FormParameterRequestURI: {root.JoinPath("request-object", "valid", "standard.jwk").String()}, "foo": {"bar"}, "baz": {"baz"}},
		},
		{
			name:      "ShouldFailRequestAlgNone",
			have:      url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow}, consts.FormParameterRequest: {assertionRequestObjectValidNone}},
			client:    &DefaultOpenIDConnectClient{JSONWebKeysURI: root.JoinPath("jwks.json").String(), RequestObjectSigningAlg: "RS256", DefaultClient: &DefaultClient{ID: "foo"}},
			expected:  url.Values{consts.FormParameterState: {"some-state"}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow}, consts.FormParameterScope: {"foo openid"}, consts.FormParameterRequest: {assertionRequestObjectValidNone}, "foo": {"bar"}, "baz": {"baz"}},
			err:       ErrInvalidRequestObject,
			errString: "The request parameter contains an invalid Request Object. The request object uses signing algorithm 'none', but the requested OAuth 2.0 Client enforces signing algorithm 'RS256'. The OAuth 2.0 client with id 'foo' made the Authorization Request.",
		},
		{
			name:      "ShouldFailRequestURIAlgNone",
			have:      url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeImplicitFlowToken}, consts.FormParameterRequestURI: {root.JoinPath("request-object", "valid", "none.jwk").String()}},
			client:    &DefaultOpenIDConnectClient{JSONWebKeysURI: root.JoinPath("jwks.json").String(), RequestObjectSigningAlg: "RS256", RequestURIs: []string{root.JoinPath("request-object", "valid", "none.jwk").String()}, DefaultClient: &DefaultClient{ID: "foo"}},
			expected:  url.Values{consts.FormParameterResponseType: {"token"}, consts.FormParameterClientID: {"foo"}, consts.FormParameterState: {"some-state"}, consts.FormParameterScope: {"foo openid"}, consts.FormParameterRequestURI: {root.JoinPath("request-object", "valid", "none.jwk").String()}, "foo": {"bar"}, "baz": {"baz"}},
			err:       ErrInvalidRequestObject,
			errString: "The request parameter contains an invalid Request Object. The request object uses signing algorithm 'none', but the requested OAuth 2.0 Client enforces signing algorithm 'RS256'. The OAuth 2.0 client with id 'foo' made the Authorization Request.",
		},
		{
			name:      "ShouldFailRequestRS256",
			have:      url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow}, consts.FormParameterRequest: {assertionRequestObjectValid}},
			client:    &DefaultOpenIDConnectClient{JSONWebKeysURI: root.JoinPath("jwks.json").String(), RequestObjectSigningAlg: consts.JSONWebTokenAlgNone, DefaultClient: &DefaultClient{ID: "foo"}},
			expected:  url.Values{consts.FormParameterState: {"some-state"}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow}, consts.FormParameterScope: {"foo openid"}, consts.FormParameterRequest: {assertionRequestObjectValid}, "foo": {"bar"}, "baz": {"baz"}},
			err:       ErrInvalidRequestObject,
			errString: "The request parameter contains an invalid Request Object. The request object uses signing algorithm 'RS256', but the requested OAuth 2.0 Client enforces signing algorithm 'none'. The OAuth 2.0 client with id 'foo' made the Authorization Request.",
		},
		{
			name:      "ShouldFailRequestURIRS256",
			have:      url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeImplicitFlowToken}, consts.FormParameterRequestURI: {root.JoinPath("request-object", "valid", "standard.jwk").String()}},
			client:    &DefaultOpenIDConnectClient{JSONWebKeysURI: root.JoinPath("jwks.json").String(), RequestObjectSigningAlg: consts.JSONWebTokenAlgNone, RequestURIs: []string{root.JoinPath("request-object", "valid", "standard.jwk").String()}, DefaultClient: &DefaultClient{ID: "foo"}},
			expected:  url.Values{consts.FormParameterResponseType: {"token"}, consts.FormParameterClientID: {"foo"}, consts.FormParameterState: {"some-state"}, consts.FormParameterScope: {"foo openid"}, consts.FormParameterRequestURI: {root.JoinPath("request-object", "valid", "standard.jwk").String()}, "foo": {"bar"}, "baz": {"baz"}},
			err:       ErrInvalidRequestObject,
			errString: "The request parameter contains an invalid Request Object. The request object uses signing algorithm 'RS256', but the requested OAuth 2.0 Client enforces signing algorithm 'none'. The OAuth 2.0 client with id 'foo' made the Authorization Request.",
		},
		{
			name:     "ShouldPassRequestAlgNone",
			have:     url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow}, consts.FormParameterRequest: {assertionRequestObjectValidNone}},
			client:   &DefaultOpenIDConnectClient{JSONWebKeysURI: root.JoinPath("jwks.json").String(), RequestObjectSigningAlg: consts.JSONWebTokenAlgNone},
			expected: url.Values{consts.FormParameterState: {"some-state"}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow}, consts.FormParameterScope: {"foo openid"}, consts.FormParameterRequest: {assertionRequestObjectValidNone}, "foo": {"bar"}, "baz": {"baz"}},
		},
		{
			name:     "ShouldPassRequestURIAlgNone",
			have:     url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeImplicitFlowToken}, consts.FormParameterRequestURI: {root.JoinPath("request-object", "valid", "none.jwk").String()}},
			client:   &DefaultOpenIDConnectClient{JSONWebKeysURI: root.JoinPath("jwks.json").String(), RequestObjectSigningAlg: consts.JSONWebTokenAlgNone, RequestURIs: []string{root.JoinPath("request-object", "valid", "none.jwk").String()}, DefaultClient: &DefaultClient{ID: "foo"}},
			expected: url.Values{consts.FormParameterResponseType: {"token"}, consts.FormParameterClientID: {"foo"}, consts.FormParameterState: {"some-state"}, consts.FormParameterScope: {"foo openid"}, consts.FormParameterRequestURI: {root.JoinPath("request-object", "valid", "none.jwk").String()}, "foo": {"bar"}, "baz": {"baz"}},
		},
		{
			name:     "ShouldPassRequestAlgNoneAllowAny",
			have:     url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow}, consts.FormParameterRequest: {assertionRequestObjectValidNone}},
			client:   &DefaultOpenIDConnectClient{JSONWebKeysURI: root.JoinPath("jwks.json").String()},
			expected: url.Values{consts.FormParameterState: {"some-state"}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow}, consts.FormParameterScope: {"foo openid"}, consts.FormParameterRequest: {assertionRequestObjectValidNone}, "foo": {"bar"}, "baz": {"baz"}},
		},
		{
			name:     "ShouldPassRequestURIAlgNoneAllowAny",
			have:     url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeImplicitFlowToken}, consts.FormParameterRequestURI: {root.JoinPath("request-object", "valid", "none.jwk").String()}},
			client:   &DefaultOpenIDConnectClient{JSONWebKeysURI: root.JoinPath("jwks.json").String(), RequestObjectSigningAlg: "", RequestURIs: []string{root.JoinPath("request-object", "valid", "none.jwk").String()}, DefaultClient: &DefaultClient{ID: "foo"}},
			expected: url.Values{consts.FormParameterResponseType: {"token"}, consts.FormParameterClientID: {"foo"}, consts.FormParameterState: {"some-state"}, consts.FormParameterScope: {"foo openid"}, consts.FormParameterRequestURI: {root.JoinPath("request-object", "valid", "none.jwk").String()}, "foo": {"bar"}, "baz": {"baz"}},
		},
		{
			name:      "ShouldFailRequestBadAudience",
			have:      url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow}, consts.FormParameterRequest: {assertionRequestObjectInvalidAudience}},
			client:    &DefaultOpenIDConnectClient{JSONWebKeysURI: root.JoinPath("jwks.json").String(), RequestObjectSigningAlg: "RS256", DefaultClient: &DefaultClient{ID: "foo"}},
			expected:  url.Values{consts.FormParameterState: {"some-state"}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow}, consts.FormParameterScope: {"foo openid"}, consts.FormParameterRequest: {assertionRequestObjectValidNone}, "foo": {"bar"}, "baz": {"baz"}},
			err:       ErrInvalidRequestObject,
			errString: "The request parameter contains an invalid Request Object. OpenID Connect 1.0 request object's `aud' claim must be the Authorization Server's issuer when using signed or encrypted request objects. The OAuth 2.0 client with id 'foo' included a 'aud' claim with the values 'https://auth.not-example.com' in the request object which must match the issuer 'https://auth.example.com'.",
		},
		{
			name:      "ShouldFailRequestURIBadAudience",
			have:      url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeImplicitFlowToken}, consts.FormParameterRequestURI: {root.JoinPath("request-object", "invalid", "audience.jwk").String()}},
			client:    &DefaultOpenIDConnectClient{JSONWebKeysURI: root.JoinPath("jwks.json").String(), RequestObjectSigningAlg: "RS256", RequestURIs: []string{root.JoinPath("request-object", "invalid", "audience.jwk").String()}, DefaultClient: &DefaultClient{ID: "foo"}},
			expected:  url.Values{consts.FormParameterResponseType: {"token"}, consts.FormParameterClientID: {"foo"}, consts.FormParameterState: {"some-state"}, consts.FormParameterScope: {"foo openid"}, consts.FormParameterRequestURI: {root.JoinPath("request-object", "invalid", "audience.jwk").String()}, "foo": {"bar"}, "baz": {"baz"}},
			err:       ErrInvalidRequestObject,
			errString: "The request parameter contains an invalid Request Object. OpenID Connect 1.0 request object's `response_type' claim if provided must match the values provided in the standard OAuth 2.0 request syntax. The OAuth 2.0 client with id 'foo' included a 'response_type' claim with a value of 'code' in the request object which when provided is required to match the value in the OAuth 2.0 request syntax but the value 'token' was included instead.",
		},
		{
			name:      "ShouldFailRequestBadIssuer",
			have:      url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow}, consts.FormParameterRequest: {assertionRequestObjectInvalidIssuer}},
			client:    &DefaultOpenIDConnectClient{JSONWebKeysURI: root.JoinPath("jwks.json").String(), RequestObjectSigningAlg: "RS256", DefaultClient: &DefaultClient{ID: "foo"}},
			expected:  url.Values{consts.FormParameterState: {"some-state"}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow}, consts.FormParameterScope: {"foo openid"}, consts.FormParameterRequest: {assertionRequestObjectValidNone}, "foo": {"bar"}, "baz": {"baz"}},
			err:       ErrInvalidRequestObject,
			errString: "The request parameter contains an invalid Request Object. OpenID Connect 1.0 request object's `iss' claim must contain the `client_id` when using signed or encrypted request objects. The OAuth 2.0 client with id 'foo' made the Authorization Request.",
		},
		{
			name:      "ShouldFailRequestURIBadIssuer",
			have:      url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeImplicitFlowToken}, consts.FormParameterRequestURI: {root.JoinPath("request-object", "invalid", "issuer.jwk").String()}},
			client:    &DefaultOpenIDConnectClient{JSONWebKeysURI: root.JoinPath("jwks.json").String(), RequestObjectSigningAlg: "RS256", RequestURIs: []string{root.JoinPath("request-object", "invalid", "issuer.jwk").String()}, DefaultClient: &DefaultClient{ID: "foo"}},
			expected:  url.Values{consts.FormParameterResponseType: {"token"}, consts.FormParameterClientID: {"foo"}, consts.FormParameterState: {"some-state"}, consts.FormParameterScope: {"foo openid"}, consts.FormParameterRequestURI: {root.JoinPath("request-object", "invalid", "issuer.jwk").String()}, "foo": {"bar"}, "baz": {"baz"}},
			err:       ErrInvalidRequestObject,
			errString: "The request parameter contains an invalid Request Object. OpenID Connect 1.0 request object's `response_type' claim if provided must match the values provided in the standard OAuth 2.0 request syntax. The OAuth 2.0 client with id 'foo' included a 'response_type' claim with a value of 'code' in the request object which when provided is required to match the value in the OAuth 2.0 request syntax but the value 'token' was included instead.",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r := &AuthorizeRequest{
				Request: Request{
					Client: tc.client,
					Form:   tc.have,
				},
			}

			provider := &Fosite{Config: &Config{JWKSFetcherStrategy: NewDefaultJWKSFetcherStrategy(), IDTokenIssuer: "https://auth.example.com"}}

			err = provider.authorizeRequestParametersFromOpenIDConnectRequestObject(context.Background(), r, tc.par)
			if tc.err != nil {
				assert.EqualError(t, err, tc.err.Error())
				if tc.errString != "" {
					assert.EqualError(t, ErrorToDebugRFC6749Error(err), tc.errString)
				}

				if tc.errRegex != nil {
					assert.Regexp(t, tc.errRegex, ErrorToDebugRFC6749Error(err).Error())
				}
			} else {
				assert.NoError(t, ErrorToDebugRFC6749Error(err))

				assert.Equal(t, len(tc.expected), len(r.Form))
				for k, v := range tc.expected {
					assert.EqualValues(t, v, r.Form[k], fmt.Sprintf("Parameter %s did not match", k))
				}
			}
		})
	}
}

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
