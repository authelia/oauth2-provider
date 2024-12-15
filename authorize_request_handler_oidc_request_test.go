// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestAuthorizeRequestParametersFromOpenIDConnectRequestObject(t *testing.T) {
	keyRSA, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	keyECDSA, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	jwkNone := &jose.JSONWebKey{
		Key: jwt.UnsafeAllowNoneSignatureType,
	}

	rawClientSecret := "aaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbcccccccccccccccccccccddddddddddddddddddddddd"

	clientSecretHS256 := NewPlainTextClientSecret(rawClientSecret)

	jwkEncAES256, err := jwt.NewClientSecretJWK(context.TODO(), []byte(rawClientSecret), "", string(jose.A256GCMKW), "", consts.JSONWebTokenUseEncryption)
	require.NoError(t, err)

	jwkSigHS := &jose.JSONWebKey{
		Key:       []byte(rawClientSecret),
		KeyID:     "hs256-sig",
		Algorithm: string(jose.HS256),
		Use:       consts.JSONWebTokenUseSignature,
	}

	jwkPublicSigRSA := &jose.JSONWebKey{
		Key:       keyRSA.Public(),
		KeyID:     "rs256-sig",
		Algorithm: string(jose.RS256),
		Use:       consts.JSONWebTokenUseSignature,
	}

	jwkPrivateSigRSA := &jose.JSONWebKey{
		Key:       keyRSA,
		KeyID:     "rs256-sig",
		Algorithm: string(jose.RS256),
		Use:       consts.JSONWebTokenUseSignature,
	}

	jwkPublicSigRSA384 := &jose.JSONWebKey{
		Key:       keyRSA.Public(),
		KeyID:     "rs384-sig",
		Algorithm: string(jose.RS384),
		Use:       consts.JSONWebTokenUseSignature,
	}

	jwkPrivateSigRSA384 := &jose.JSONWebKey{
		Key:       keyRSA,
		KeyID:     "rs384-sig",
		Algorithm: string(jose.RS384),
		Use:       consts.JSONWebTokenUseSignature,
	}

	jwkPublicSigECDSA := &jose.JSONWebKey{
		Key:       keyECDSA.Public(),
		KeyID:     "es256-sig",
		Algorithm: string(jose.ES256),
		Use:       consts.JSONWebTokenUseSignature,
	}

	jwkPrivateSigECDSA := &jose.JSONWebKey{
		Key:       keyECDSA,
		KeyID:     "es256-sig",
		Algorithm: string(jose.ES256),
		Use:       consts.JSONWebTokenUseSignature,
	}

	jwkPublicEncECDSA := &jose.JSONWebKey{
		Key:       keyECDSA.Public(),
		KeyID:     "es256-enc",
		Algorithm: string(jose.ECDH_ES_A128KW),
		Use:       consts.JSONWebTokenUseEncryption,
	}

	jwkPrivateEncECDSA := &jose.JSONWebKey{
		Key:       keyECDSA,
		KeyID:     "es256-enc",
		Algorithm: string(jose.ECDH_ES_A128KW),
		Use:       consts.JSONWebTokenUseEncryption,
	}

	jwksPrivate := &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			*jwkPrivateSigRSA,
			*jwkPrivateSigECDSA,
			*jwkPrivateEncECDSA,
		},
	}

	jwksPublic := &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			*jwkPublicSigRSA,
			*jwkPublicSigRSA384,
			*jwkPublicSigECDSA,
			*jwkPublicEncECDSA,
		},
	}

	assertionRequestObjectValid := mustGenerateRequestObjectJWS(t, jwt.MapClaims{consts.ClaimIssuer: "foo", consts.ClaimClientIdentifier: "foo", consts.ClaimAudience: []string{"https://auth.example.com"}, consts.FormParameterScope: "foo", "foo": "bar", "baz": "baz", consts.FormParameterResponseType: consts.ResponseTypeImplicitFlowToken, consts.FormParameterResponseMode: consts.ResponseModeFormPost}, nil, jwkPrivateSigRSA)
	assertionRequestObjectInvalidExpired := mustGenerateRequestObjectJWS(t, jwt.MapClaims{consts.ClaimIssuer: "foo", consts.ClaimExpirationTime: time.Now().Add(-time.Hour).UTC().Unix(), consts.ClaimClientIdentifier: "foo", consts.ClaimAudience: []string{"https://auth.example.com"}, consts.FormParameterScope: "foo", "foo": "bar", "baz": "baz", consts.FormParameterResponseType: consts.ResponseTypeImplicitFlowToken, consts.FormParameterResponseMode: consts.ResponseModeFormPost}, nil, jwkPrivateSigRSA)
	assertionRequestObjectInvalidFuture := mustGenerateRequestObjectJWS(t, jwt.MapClaims{consts.ClaimIssuer: "foo", consts.ClaimIssuedAt: time.Now().Add(time.Hour).UTC().Unix(), consts.ClaimClientIdentifier: "foo", consts.ClaimAudience: []string{"https://auth.example.com"}, consts.FormParameterScope: "foo", "foo": "bar", "baz": "baz", consts.FormParameterResponseType: consts.ResponseTypeImplicitFlowToken, consts.FormParameterResponseMode: consts.ResponseModeFormPost}, nil, jwkPrivateSigRSA)
	assertionRequestObjectInvalidNotValidYet := mustGenerateRequestObjectJWS(t, jwt.MapClaims{consts.ClaimIssuer: "foo", consts.ClaimNotBefore: time.Now().Add(time.Hour).UTC().Unix(), consts.ClaimClientIdentifier: "foo", consts.ClaimAudience: []string{"https://auth.example.com"}, consts.FormParameterScope: "foo", "foo": "bar", "baz": "baz", consts.FormParameterResponseType: consts.ResponseTypeImplicitFlowToken, consts.FormParameterResponseMode: consts.ResponseModeFormPost}, nil, jwkPrivateSigRSA)
	assertionRequestObjectInvalidSignature := mangleSig(assertionRequestObjectValid)
	assertionRequestObjectInvalidKID := mustGenerateRequestObjectJWS(t, jwt.MapClaims{consts.ClaimIssuer: "foo", consts.ClaimClientIdentifier: "foo", consts.ClaimAudience: []string{"https://auth.example.com"}, consts.FormParameterScope: "foo", "foo": "bar", "baz": "baz", consts.FormParameterResponseType: consts.ResponseTypeImplicitFlowToken, consts.FormParameterResponseMode: consts.ResponseModeFormPost}, nil, jwkPrivateSigRSA384)
	assertionRequestObjectInvalidTyp := mustGenerateRequestObjectJWS(t, jwt.MapClaims{consts.ClaimIssuer: "foo", consts.ClaimClientIdentifier: "foo", consts.ClaimAudience: []string{"https://auth.example.com"}, consts.FormParameterScope: "foo", "foo": "bar", "baz": "baz", consts.FormParameterResponseType: consts.ResponseTypeImplicitFlowToken, consts.FormParameterResponseMode: consts.ResponseModeFormPost}, &jwt.Headers{Extra: map[string]any{consts.JSONWebTokenHeaderType: "abc"}}, jwkPrivateSigRSA)
	assertionRequestObjectInvalidJWEContentType := mustGenerateRequestObjectJWE(t, jwt.MapClaims{consts.ClaimIssuer: "foo", consts.ClaimClientIdentifier: "foo", consts.ClaimAudience: []string{"https://auth.example.com"}, consts.FormParameterScope: "foo", "foo": "bar", "baz": "baz", consts.FormParameterResponseType: consts.ResponseTypeImplicitFlowToken, consts.FormParameterResponseMode: consts.ResponseModeFormPost}, nil, &jwt.Headers{Extra: map[string]any{consts.JSONWebTokenHeaderContentType: "at+jwt"}}, jwkPrivateSigRSA, jwkEncAES256, jose.A256GCM)
	assertionRequestObjectInvalidJWEType := mustGenerateRequestObjectJWE(t, jwt.MapClaims{consts.ClaimIssuer: "foo", consts.ClaimClientIdentifier: "foo", consts.ClaimAudience: []string{"https://auth.example.com"}, consts.FormParameterScope: "foo", "foo": "bar", "baz": "baz", consts.FormParameterResponseType: consts.ResponseTypeImplicitFlowToken, consts.FormParameterResponseMode: consts.ResponseModeFormPost}, nil, &jwt.Headers{Extra: map[string]any{consts.JSONWebTokenHeaderType: "at+jwt"}}, jwkPrivateSigRSA, jwkEncAES256, jose.A256GCM)
	assertionRequestObjectValidJWE := mustGenerateRequestObjectJWE(t, jwt.MapClaims{consts.ClaimIssuer: "foo", consts.ClaimClientIdentifier: "foo", consts.ClaimAudience: []string{"https://auth.example.com"}, consts.FormParameterScope: "foo", "foo": "bar", "baz": "baz", consts.FormParameterResponseType: consts.ResponseTypeImplicitFlowToken, consts.FormParameterResponseMode: consts.ResponseModeFormPost}, nil, nil, jwkPrivateSigRSA, jwkEncAES256, jose.A256GCM)
	assertionRequestObjectValidAssymetricJWE := mustGenerateRequestObjectJWE(t, jwt.MapClaims{consts.ClaimIssuer: "foo", consts.ClaimClientIdentifier: "foo", consts.ClaimAudience: []string{"https://auth.example.com"}, consts.FormParameterScope: "foo", "foo": "bar", "baz": "baz", consts.FormParameterResponseType: consts.ResponseTypeImplicitFlowToken, consts.FormParameterResponseMode: consts.ResponseModeFormPost}, nil, nil, jwkPrivateSigECDSA, jwkPublicEncECDSA, jose.A128GCM)
	assertionRequestObjectEmptyHS256 := mustGenerateRequestObjectJWS(t, jwt.MapClaims{}, nil, jwkSigHS)
	assertionRequestObjectInvalidRequestInRequest := mustGenerateRequestObjectJWS(t, jwt.MapClaims{consts.ClaimIssuer: "foo", consts.FormParameterRequest: "abc", consts.ClaimClientIdentifier: "foo", consts.ClaimAudience: []string{"https://auth.example.com"}, consts.FormParameterScope: "foo", "foo": "bar", "baz": "baz", consts.FormParameterResponseType: consts.ResponseTypeImplicitFlowToken, consts.FormParameterResponseMode: consts.ResponseModeFormPost}, nil, jwkPrivateSigRSA)
	assertionRequestObjectInvalidRequestURIInRequest := mustGenerateRequestObjectJWS(t, jwt.MapClaims{consts.ClaimIssuer: "foo", consts.FormParameterRequestURI: "https://auth.example.com", consts.ClaimClientIdentifier: "foo", consts.ClaimAudience: []string{"https://auth.example.com"}, consts.FormParameterScope: "foo", "foo": "bar", "baz": "baz", consts.FormParameterResponseType: consts.ResponseTypeImplicitFlowToken, consts.FormParameterResponseMode: consts.ResponseModeFormPost}, nil, jwkPrivateSigRSA)
	assertionRequestObjectInvalidClientIDValue := mustGenerateRequestObjectJWS(t, jwt.MapClaims{consts.ClaimIssuer: "foo", consts.ClaimClientIdentifier: 100, consts.ClaimAudience: []string{"https://auth.example.com"}, consts.FormParameterScope: "foo", "foo": "bar", "baz": "baz", consts.FormParameterResponseType: consts.ResponseTypeImplicitFlowToken, consts.FormParameterResponseMode: consts.ResponseModeFormPost}, nil, jwkPrivateSigRSA)
	assertionRequestObjectInvalidResponseTypeValue := mustGenerateRequestObjectJWS(t, jwt.MapClaims{consts.ClaimIssuer: "foo", consts.ClaimAudience: []string{"https://auth.example.com"}, consts.FormParameterScope: "foo", "foo": "bar", "baz": "baz", consts.FormParameterResponseType: 100, consts.FormParameterResponseMode: consts.ResponseModeFormPost}, nil, jwkPrivateSigRSA)
	assertionRequestObjectInvalidAudience := mustGenerateRequestObjectJWS(t, jwt.MapClaims{consts.ClaimIssuer: "foo", consts.ClaimAudience: []string{"https://auth.not-example.com"}, consts.FormParameterScope: "foo", "foo": "bar", "baz": "baz", consts.FormParameterResponseType: consts.ResponseTypeAuthorizationCodeFlow, consts.FormParameterResponseMode: consts.ResponseModeFormPost}, nil, jwkPrivateSigRSA)
	assertionRequestObjectInvalidIssuer := mustGenerateRequestObjectJWS(t, jwt.MapClaims{consts.ClaimIssuer: "not-foo", consts.ClaimAudience: []string{"https://auth.example.com"}, consts.FormParameterScope: "foo", "foo": "bar", "baz": "baz", consts.FormParameterResponseType: consts.ResponseTypeAuthorizationCodeFlow, consts.FormParameterResponseMode: consts.ResponseModeFormPost}, nil, jwkPrivateSigRSA)
	assertionRequestObjectValidWithoutKID := mustGenerateRequestObjectJWS(t, jwt.MapClaims{consts.ClaimIssuer: "foo", consts.ClaimAudience: []string{"https://auth.example.com"}, consts.FormParameterScope: "foo", "foo": "bar", "baz": "baz"}, nil, &jose.JSONWebKey{Key: keyRSA, Algorithm: string(jose.RS256), Use: consts.JSONWebTokenUseSignature})
	assertionRequestObjectValidNone := mustGenerateRequestObjectJWS(t, jwt.MapClaims{consts.FormParameterScope: "foo", "foo": "bar", "baz": "baz", consts.FormParameterState: "some-state", consts.ClaimIssuer: "foo", consts.ClaimAudience: []string{"https://auth.example.com"}}, nil, jwkNone)
	assertionRequestObjectValidHS256 := mustGenerateRequestObjectJWS(t, jwt.MapClaims{consts.FormParameterScope: "foo", "foo": "bar", "baz": "baz", consts.FormParameterState: "some-state", consts.ClaimIssuer: "foo", consts.ClaimAudience: []string{"https://auth.example.com"}}, nil, jwkSigHS)

	mux := http.NewServeMux()

	var handlerJWKS http.HandlerFunc = func(rw http.ResponseWriter, r *http.Request) {
		require.NoError(t, json.NewEncoder(rw).Encode(jwksPublic))
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
			name:      "ShouldErrorRequestWithRequestObjectNotOpenID",
			have:      url.Values{consts.FormParameterRequest: {"foo"}},
			client:    &DefaultClient{ID: "foo"},
			expected:  url.Values{consts.FormParameterRequest: {"foo"}},
			err:       ErrRequestNotSupported,
			errString: "The authorization server does not support the use of the request parameter. OAuth 2.0 JWT-Secured Authorization Request parameter 'request' was used, but the OAuth 2.0 Client does not implement advanced authorization capabilities. The OAuth 2.0 client with id 'foo' doesn't implement the correct functionality for this request.",
		},
		{
			name:     "ShouldPassRequest",
			have:     url.Values{consts.FormParameterScope: {"foo openid"}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeImplicitFlowToken}, consts.FormParameterRequest: {assertionRequestObjectValid}},
			client:   &DefaultJARClient{JSONWebKeys: jwksPublic, RequestObjectSigningAlg: "RS256", DefaultClient: &DefaultClient{ID: "foo"}},
			expected: url.Values{consts.FormParameterScope: {"foo openid"}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeImplicitFlowToken}, consts.FormParameterResponseMode: {consts.ResponseModeFormPost}, consts.FormParameterRequest: {assertionRequestObjectValid}, "foo": {"bar"}, "baz": {"baz"}},
		},
		{
			name:     "ShouldPassRequestJWE",
			have:     url.Values{consts.FormParameterScope: {"foo openid"}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeImplicitFlowToken}, consts.FormParameterRequest: {assertionRequestObjectValidJWE}},
			client:   &DefaultJARClient{JSONWebKeys: jwksPublic, RequestObjectSigningAlg: "RS256", DefaultClient: &DefaultClient{ID: "foo", ClientSecret: clientSecretHS256}},
			expected: url.Values{consts.FormParameterScope: {"foo openid"}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeImplicitFlowToken}, consts.FormParameterResponseMode: {consts.ResponseModeFormPost}, consts.FormParameterRequest: {assertionRequestObjectValidJWE}, "foo": {"bar"}, "baz": {"baz"}},
		},
		{
			name:     "ShouldPassRequestJWESymmetric",
			have:     url.Values{consts.FormParameterScope: {"foo openid"}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeImplicitFlowToken}, consts.FormParameterRequest: {assertionRequestObjectValidAssymetricJWE}},
			client:   &DefaultJARClient{JSONWebKeys: jwksPublic, RequestObjectSigningAlg: "ES256", RequestObjectSigningKeyID: "es256-sig", RequestObjectEncryptionKeyID: "es256-enc", DefaultClient: &DefaultClient{ID: "foo", ClientSecret: clientSecretHS256}},
			expected: url.Values{consts.FormParameterScope: {"foo openid"}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeImplicitFlowToken}, consts.FormParameterRequest: {assertionRequestObjectValidAssymetricJWE}, "baz": {"baz"}, "foo": {"bar"}, consts.FormParameterResponseMode: {consts.ResponseModeFormPost}},
		},
		{
			name:      "ShouldFailRequestNotOpenIDConnectClient",
			have:      url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterRequest: {"foo"}},
			client:    &DefaultClient{ID: "foo"},
			expected:  url.Values{consts.FormParameterScope: {consts.ScopeOpenID}},
			err:       ErrRequestNotSupported,
			errString: "The authorization server does not support the use of the request parameter. OpenID Connect 1.0 parameter 'request' was used, but the OAuth 2.0 Client does not implement advanced authorization capabilities. The OAuth 2.0 client with id 'foo' doesn't implement the correct functionality for this request.",
		},
		{
			name:      "ShouldFailRequestURINotOpenIDConnectClient",
			have:      url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterRequestURI: {"foo"}},
			client:    &DefaultClient{ID: "foo"},
			expected:  url.Values{consts.FormParameterScope: {consts.ScopeOpenID}},
			err:       ErrRequestURINotSupported,
			errString: "The authorization server does not support the use of the request_uri parameter. OpenID Connect 1.0 parameter 'request_uri' was used, but the OAuth 2.0 Client does not implement advanced authorization capabilities. The OAuth 2.0 client with id 'foo' doesn't implement the correct functionality for this request.",
		},
		{
			name:      "ShouldFailRequestAndRequestURI",
			have:      url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterRequest: {"foo"}, consts.FormParameterRequestURI: {"foo"}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow}},
			client:    &DefaultJARClient{RequestObjectSigningAlg: "", DefaultClient: &DefaultClient{ID: "foo"}},
			par:       true,
			expected:  url.Values{consts.FormParameterRequest: {"foo"}},
			err:       ErrInvalidRequest,
			errString: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. OpenID Connect 1.0 parameters 'request' and 'request_uri' were both used, but only one may be used in any given request.",
		},
		{
			name:      "ShouldFailRequestMissingResponseType",
			have:      url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterRequest: {"foo"}, consts.FormParameterClientID: {"foo"}},
			client:    &DefaultJARClient{RequestObjectSigningAlg: "", DefaultClient: &DefaultClient{ID: "foo"}},
			par:       true,
			expected:  url.Values{consts.FormParameterRequest: {"foo"}},
			err:       ErrInvalidRequest,
			errString: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. OpenID Connect 1.0 parameter 'request' must be accompanied by the 'response_type' parameter in the request syntax. The OAuth 2.0 client with id 'foo' provided the 'request' with value but did not include the 'response_type' parameter.",
		},
		{
			name:      "ShouldFailRequestMissingClientID",
			have:      url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterRequest: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow}},
			client:    &DefaultJARClient{RequestObjectSigningAlg: "", DefaultClient: &DefaultClient{ID: "foo"}},
			par:       true,
			expected:  url.Values{consts.FormParameterRequest: {"foo"}},
			err:       ErrInvalidRequest,
			errString: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. OpenID Connect 1.0 parameter 'request' must be accompanied by the 'client_id' parameter in the request syntax. The OAuth 2.0 client with id 'foo' provided the 'request' with value but did not include the 'client_id' parameter.",
		},
		{
			name:      "ShouldFailRequestURIWithPAR",
			have:      url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterRequestURI: {"foo"}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow}},
			client:    &DefaultJARClient{RequestObjectSigningAlg: "", DefaultClient: &DefaultClient{ID: "foo"}},
			par:       true,
			expected:  url.Values{consts.FormParameterRequest: {"foo"}},
			err:       ErrInvalidRequest,
			errString: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. OpenID Connect 1.0 request failed to fetch request parameters from the provided 'request_uri'. The OAuth 2.0 client with id 'foo' provided the 'request_uri' parameter within a Pushed Authorization Request which is invalid.",
		},
		{
			name:      "ShouldFailRequestClientNoJWKS",
			have:      url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterRequest: {"foo"}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow}},
			client:    &DefaultJARClient{RequestObjectSigningAlg: "RS256", DefaultClient: &DefaultClient{ID: "foo"}},
			expected:  url.Values{consts.FormParameterScope: {consts.ScopeOpenID}},
			err:       ErrInvalidRequest,
			errString: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. OpenID Connect 1.0 parameter 'request' was used, but the OAuth 2.0 Client does not have any JSON Web Keys registered. The OAuth 2.0 client with id 'foo' doesn't have any known JSON Web Keys but requires them when not explicitly registered with a 'request_object_signing_alg' with the value of 'none' or an empty value but it's registered with 'RS256'.",
		},
		{
			name:      "ShouldFailRequestURIClientNoJWKS",
			have:      url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterRequestURI: {"foo"}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow}},
			client:    &DefaultJARClient{RequestObjectSigningAlg: "RS256", DefaultClient: &DefaultClient{ID: "foo"}},
			expected:  url.Values{consts.FormParameterScope: {consts.ScopeOpenID}},
			err:       ErrInvalidRequest,
			errString: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. OpenID Connect 1.0 parameter 'request_uri' was used, but the OAuth 2.0 Client does not have any JSON Web Keys registered. The OAuth 2.0 client with id 'foo' doesn't have any known JSON Web Keys but requires them when not explicitly registered with a 'request_object_signing_alg' with the value of 'none' or an empty value but it's registered with 'RS256'.",
		},
		{
			name:      "ShouldFailInvalidTokenMalformed",
			have:      url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow}, consts.FormParameterRequest: {"bad-token"}},
			client:    &DefaultJARClient{JSONWebKeys: jwksPublic, RequestObjectSigningAlg: "RS256", DefaultClient: &DefaultClient{ID: "foo"}},
			expected:  url.Values{consts.FormParameterScope: {consts.ScopeOpenID}},
			err:       ErrInvalidRequestObject,
			errString: "The request parameter contains an invalid Request Object. OpenID Connect 1.0 request object could not be decoded or validated. OpenID Connect 1.0 client with id 'foo' provided a request object that was malformed. The request object does not appear to be a JWE or JWS compact serialized JWT.",
		},
		{
			name:      "ShouldFailUnknownKID",
			have:      url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow}, consts.FormParameterRequest: {mustGenerateAssertion(t, jwt.MapClaims{}, keyRSA, "does-not-exists")}},
			client:    &DefaultJARClient{JSONWebKeys: jwksPublic, RequestObjectSigningAlg: "RS256", DefaultClient: &DefaultClient{ID: "test"}},
			expected:  url.Values{consts.FormParameterScope: {consts.ScopeOpenID}},
			err:       ErrInvalidRequestObject,
			errString: "The request parameter contains an invalid Request Object. OpenID Connect 1.0 request object could not be decoded or validated. OpenID Connect 1.0 client with id 'test' provided a request object that was not able to be verified. Error occurred retrieving the JSON Web Key. The JSON Web Token uses signing key with kid 'does-not-exists' which was not found.",
		},
		{
			name:      "ShouldFailBadKID",
			have:      url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow}, consts.FormParameterRequest: {assertionRequestObjectInvalidKID}},
			client:    &DefaultJARClient{JSONWebKeys: jwksPublic, RequestObjectSigningAlg: "RS256", RequestObjectSigningKeyID: "rs256-sig", DefaultClient: &DefaultClient{ID: "test", ClientSecret: clientSecretHS256}},
			expected:  url.Values{consts.FormParameterScope: {consts.ScopeOpenID}},
			err:       ErrInvalidRequestObject,
			errString: "The request parameter contains an invalid Request Object. OpenID Connect 1.0 request object could not be decoded or validated. OpenID Connect 1.0 client with id 'test' expects request objects to be signed with the 'kid' header value 'rs256-sig' due to the client registration 'request_object_signing_key_id' value but the request object was signed with the 'kid' header value 'rs384-sig'.",
		},
		{
			name:      "ShouldFailBadType",
			have:      url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow}, consts.FormParameterRequest: {assertionRequestObjectInvalidTyp}},
			client:    &DefaultJARClient{JSONWebKeys: jwksPublic, RequestObjectSigningAlg: "RS256", RequestObjectSigningKeyID: "rs256-sig", DefaultClient: &DefaultClient{ID: "test", ClientSecret: clientSecretHS256}},
			expected:  url.Values{consts.FormParameterScope: {consts.ScopeOpenID}},
			err:       ErrInvalidRequestObject,
			errString: "The request parameter contains an invalid Request Object. OpenID Connect 1.0 request object could not be decoded or validated. OpenID Connect 1.0 client with id 'test' expects request objects to be signed with the 'typ' header value 'JWT' but the request object was signed with the 'typ' header value 'abc'.",
		},
		{
			name:      "ShouldFailJWEBadContentType",
			have:      url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow}, consts.FormParameterRequest: {assertionRequestObjectInvalidJWEContentType}},
			client:    &DefaultJARClient{JSONWebKeys: jwksPublic, RequestObjectSigningAlg: "RS256", RequestObjectSigningKeyID: "rs256-sig", DefaultClient: &DefaultClient{ID: "test", ClientSecret: clientSecretHS256}},
			expected:  url.Values{consts.FormParameterScope: {consts.ScopeOpenID}},
			err:       ErrInvalidRequestObject,
			errString: "The request parameter contains an invalid Request Object. OpenID Connect 1.0 request object could not be decoded or validated. OpenID Connect 1.0 client with id 'test' expects request objects to be encrypted with a 'cty' header value and signed with a 'typ' value that match but the request object was encrypted with the 'cty' header value 'at+jwt' and signed with the 'typ' header value 'JWT'.",
		},
		{
			name:      "ShouldFailJWEBadType",
			have:      url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow}, consts.FormParameterRequest: {assertionRequestObjectInvalidJWEType}},
			client:    &DefaultJARClient{JSONWebKeys: jwksPublic, RequestObjectSigningAlg: "RS256", RequestObjectSigningKeyID: "rs256-sig", DefaultClient: &DefaultClient{ID: "test", ClientSecret: clientSecretHS256}},
			expected:  url.Values{consts.FormParameterScope: {consts.ScopeOpenID}},
			err:       ErrInvalidRequestObject,
			errString: "The request parameter contains an invalid Request Object. OpenID Connect 1.0 request object could not be decoded or validated. OpenID Connect 1.0 client with id 'test' expects request objects to be encrypted with the 'typ' header value 'JWT' but the request object was encrypted with the 'typ' header value 'at+jwt'.",
		},
		{
			name:      "ShouldFailJWEBadKeyID",
			have:      url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeImplicitFlowToken}, consts.FormParameterRequest: {assertionRequestObjectValidAssymetricJWE}},
			client:    &DefaultJARClient{JSONWebKeys: jwksPublic, RequestObjectSigningAlg: "ES256", RequestObjectSigningKeyID: "es256-sig", RequestObjectEncryptionKeyID: "abc", DefaultClient: &DefaultClient{ID: "foo", ClientSecret: clientSecretHS256}},
			expected:  url.Values{consts.FormParameterScope: {consts.ScopeOpenID}},
			err:       ErrInvalidRequestObject,
			errString: "The request parameter contains an invalid Request Object. OpenID Connect 1.0 request object could not be decoded or validated. OpenID Connect 1.0 client with id 'foo' expects request objects to be encrypted with the 'kid' header value 'abc' due to the client registration 'request_object_encryption_key_id' value but the request object was encrypted with the 'kid' header value 'es256-enc'.",
		},
		{
			name:      "ShouldFailJWEBadAlg",
			have:      url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeImplicitFlowToken}, consts.FormParameterRequest: {assertionRequestObjectValidAssymetricJWE}},
			client:    &DefaultJARClient{JSONWebKeys: jwksPublic, RequestObjectSigningAlg: "ES256", RequestObjectSigningKeyID: "es256-sig", RequestObjectEncryptionAlg: "abc", DefaultClient: &DefaultClient{ID: "foo", ClientSecret: clientSecretHS256}},
			expected:  url.Values{consts.FormParameterScope: {consts.ScopeOpenID}},
			err:       ErrInvalidRequestObject,
			errString: "The request parameter contains an invalid Request Object. OpenID Connect 1.0 request object could not be decoded or validated. OpenID Connect 1.0 client with id 'foo' expects request objects to be encrypted with the 'alg' header value 'abc' due to the client registration 'request_object_encryption_alg' value but the request object was encrypted with the 'alg' header value 'ECDH-ES+A128KW'.",
		},
		{
			name:      "ShouldFailJWEBadEnc",
			have:      url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeImplicitFlowToken}, consts.FormParameterRequest: {assertionRequestObjectValidAssymetricJWE}},
			client:    &DefaultJARClient{JSONWebKeys: jwksPublic, RequestObjectSigningAlg: "ES256", RequestObjectSigningKeyID: "es256-sig", RequestObjectEncryptionEnc: "abc", DefaultClient: &DefaultClient{ID: "foo", ClientSecret: clientSecretHS256}},
			expected:  url.Values{consts.FormParameterScope: {consts.ScopeOpenID}},
			err:       ErrInvalidRequestObject,
			errString: "The request parameter contains an invalid Request Object. OpenID Connect 1.0 request object could not be decoded or validated. OpenID Connect 1.0 client with id 'foo' expects request objects to be encrypted with the 'enc' header value 'abc' due to the client registration 'request_object_encryption_enc' value but the request object was encrypted with the 'enc' header value 'A128GCM'.",
		},
		{
			name:     "ShouldFailExpired",
			have:     url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeImplicitFlowToken}, consts.FormParameterRequest: {assertionRequestObjectInvalidExpired}},
			client:   &DefaultJARClient{JSONWebKeys: jwksPublic, DefaultClient: &DefaultClient{ID: "foo", ClientSecret: clientSecretHS256}},
			expected: url.Values{consts.FormParameterScope: {consts.ScopeOpenID}},
			err:      ErrInvalidRequestObject,
			errRegex: regexp.MustCompile(`^The request parameter contains an invalid Request Object\. OpenID Connect 1\.0 request object could not be decoded or validated\. OpenID Connect 1\.0 client with id 'foo' provided a request object that was expired\. The request object expired at \d+\.`),
		},
		{
			name:     "ShouldFailFuture",
			have:     url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeImplicitFlowToken}, consts.FormParameterRequest: {assertionRequestObjectInvalidFuture}},
			client:   &DefaultJARClient{JSONWebKeys: jwksPublic, DefaultClient: &DefaultClient{ID: "foo", ClientSecret: clientSecretHS256}},
			expected: url.Values{consts.FormParameterScope: {consts.ScopeOpenID}},
			err:      ErrInvalidRequestObject,
			errRegex: regexp.MustCompile(`^The request parameter contains an invalid Request Object. OpenID Connect 1\.0 request object could not be decoded or validated\. OpenID Connect 1\.0 client with id 'foo' provided a request object that was issued in the future\. The request object was issued at \d+\.$`),
		},
		{
			name:     "ShouldFailNotBefore",
			have:     url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeImplicitFlowToken}, consts.FormParameterRequest: {assertionRequestObjectInvalidNotValidYet}},
			client:   &DefaultJARClient{JSONWebKeys: jwksPublic, DefaultClient: &DefaultClient{ID: "foo", ClientSecret: clientSecretHS256}},
			expected: url.Values{consts.FormParameterScope: {consts.ScopeOpenID}},
			err:      ErrInvalidRequestObject,
			errRegex: regexp.MustCompile(`^The request parameter contains an invalid Request Object\. OpenID Connect 1\.0 request object could not be decoded or validated\. OpenID Connect 1\.0 client with id 'foo' provided a request object that was issued in the future\. The request object is not valid before \d+\.`),
		},
		{
			name:      "ShouldFailBadSignature",
			have:      url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow}, consts.FormParameterRequest: {assertionRequestObjectInvalidSignature}},
			client:    &DefaultJARClient{JSONWebKeys: jwksPublic, RequestObjectSigningAlg: "RS256", RequestObjectSigningKeyID: "rs256-sig", DefaultClient: &DefaultClient{ID: "test", ClientSecret: clientSecretHS256}},
			expected:  url.Values{consts.FormParameterScope: {consts.ScopeOpenID}},
			err:       ErrInvalidRequestObject,
			errString: "The request parameter contains an invalid Request Object. OpenID Connect 1.0 request object could not be decoded or validated. OpenID Connect 1.0 client with id 'test' provided a request object that has an invalid signature.",
		},
		{
			name:      "ShouldFailBadAlgRS256",
			have:      url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow}, consts.FormParameterRequest: {assertionRequestObjectEmptyHS256}},
			client:    &DefaultJARClient{JSONWebKeys: jwksPublic, RequestObjectSigningAlg: "RS256", DefaultClient: &DefaultClient{ID: "test", ClientSecret: clientSecretHS256}},
			expected:  url.Values{consts.FormParameterScope: {consts.ScopeOpenID}},
			err:       ErrInvalidRequestObject,
			errString: "The request parameter contains an invalid Request Object. OpenID Connect 1.0 request object could not be decoded or validated. OpenID Connect 1.0 client with id 'test' expects request objects to be signed with the 'alg' header value 'RS256' due to the client registration 'request_object_signing_alg' value but the request object was signed with the 'alg' header value 'HS256'.",
		},
		{
			name:      "ShouldFailMismatchedClientID",
			have:      url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterClientID: {"not-foo"}, consts.FormParameterResponseType: {consts.ResponseTypeImplicitFlowToken}, consts.FormParameterResponseMode: {consts.ResponseModeNone}, consts.FormParameterRequest: {assertionRequestObjectValid}},
			client:    &DefaultJARClient{JSONWebKeys: jwksPublic, RequestObjectSigningAlg: "RS256", DefaultClient: &DefaultClient{ID: "foo"}},
			expected:  url.Values{consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeImplicitFlowToken}, consts.FormParameterResponseMode: {consts.ResponseModeFormPost}, consts.FormParameterScope: {"foo openid"}, consts.FormParameterRequest: {assertionRequestObjectValid}, "foo": {"bar"}, "baz": {"baz"}},
			err:       ErrInvalidRequestObject,
			errString: "The request parameter contains an invalid Request Object. OpenID Connect 1.0 request included a request object which excluded claims that are required or included claims that did not match the OAuth 2.0 request syntax or are generally not permitted. The OAuth 2.0 client with id 'foo' included a request object with a 'client_id' claim with a value of 'foo' which is required to match the value 'not-foo' in the parameter with the same name from the OAuth 2.0 request syntax.",
		},
		{
			name:      "ShouldFailRequestClientIDAssert",
			have:      url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterClientID: {"not-foo"}, consts.FormParameterResponseType: {consts.ResponseTypeImplicitFlowToken}, consts.FormParameterResponseMode: {consts.ResponseModeNone}, consts.FormParameterRequest: {assertionRequestObjectInvalidClientIDValue}},
			client:    &DefaultJARClient{JSONWebKeys: jwksPublic, RequestObjectSigningAlg: "RS256", DefaultClient: &DefaultClient{ID: "foo"}},
			expected:  url.Values{consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeImplicitFlowToken}, consts.FormParameterResponseMode: {consts.ResponseModeFormPost}, consts.FormParameterScope: {"foo openid"}, consts.FormParameterRequest: {assertionRequestObjectInvalidClientIDValue}, "foo": {"bar"}, "baz": {"baz"}},
			err:       ErrInvalidRequestObject,
			errString: "The request parameter contains an invalid Request Object. OpenID Connect 1.0 request included a request object which excluded claims that are required or included claims that did not match the OAuth 2.0 request syntax or are generally not permitted. The OAuth 2.0 client with id 'foo' included a request object with a 'client_id' claim with a value of '100' which is required to match the value 'not-foo' in the parameter with the same name from the OAuth 2.0 request syntax but instead of a string it had the int64 type.",
		},
		{
			name:      "ShouldFailRequestWithRequest",
			have:      url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeImplicitFlowToken}, consts.FormParameterResponseMode: {consts.ResponseModeNone}, consts.FormParameterRequest: {assertionRequestObjectInvalidRequestInRequest}},
			client:    &DefaultJARClient{JSONWebKeys: jwksPublic, RequestObjectSigningAlg: "RS256", DefaultClient: &DefaultClient{ID: "foo"}},
			expected:  url.Values{consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeImplicitFlowToken}, consts.FormParameterResponseMode: {consts.ResponseModeFormPost}, consts.FormParameterScope: {"foo openid"}, consts.FormParameterRequest: {assertionRequestObjectInvalidRequestInRequest}, "foo": {"bar"}, "baz": {"baz"}},
			err:       ErrInvalidRequestObject,
			errString: "The request parameter contains an invalid Request Object. OpenID Connect 1.0 request included a request object which excluded claims that are required or included claims that did not match the OAuth 2.0 request syntax or are generally not permitted. The OAuth 2.0 client with id 'foo' included a request object which contained the 'request' or 'request_uri' claims but this is not permitted.",
		},
		{
			name:      "ShouldFailRequestWithRequestURI",
			have:      url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeImplicitFlowToken}, consts.FormParameterResponseMode: {consts.ResponseModeNone}, consts.FormParameterRequest: {assertionRequestObjectInvalidRequestURIInRequest}},
			client:    &DefaultJARClient{JSONWebKeys: jwksPublic, RequestObjectSigningAlg: "RS256", DefaultClient: &DefaultClient{ID: "foo"}},
			expected:  url.Values{consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeImplicitFlowToken}, consts.FormParameterResponseMode: {consts.ResponseModeFormPost}, consts.FormParameterScope: {"foo openid"}, consts.FormParameterRequest: {assertionRequestObjectInvalidRequestURIInRequest}, "foo": {"bar"}, "baz": {"baz"}},
			err:       ErrInvalidRequestObject,
			errString: "The request parameter contains an invalid Request Object. OpenID Connect 1.0 request included a request object which excluded claims that are required or included claims that did not match the OAuth 2.0 request syntax or are generally not permitted. The OAuth 2.0 client with id 'foo' included a request object which contained the 'request' or 'request_uri' claims but this is not permitted.",
		},
		{
			name:      "ShouldFailMismatchedResponseType",
			have:      url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow}, consts.FormParameterResponseMode: {consts.ResponseModeNone}, consts.FormParameterRequest: {assertionRequestObjectValid}},
			client:    &DefaultJARClient{JSONWebKeys: jwksPublic, RequestObjectSigningAlg: "RS256", DefaultClient: &DefaultClient{ID: "foo"}},
			expected:  url.Values{consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeImplicitFlowToken}, consts.FormParameterResponseMode: {consts.ResponseModeFormPost}, consts.FormParameterScope: {"foo openid"}, consts.FormParameterRequest: {assertionRequestObjectValid}, "foo": {"bar"}, "baz": {"baz"}},
			err:       ErrInvalidRequestObject,
			errString: "The request parameter contains an invalid Request Object. OpenID Connect 1.0 request included a request object which excluded claims that are required or included claims that did not match the OAuth 2.0 request syntax or are generally not permitted. The OAuth 2.0 client with id 'foo' included a request object with a 'response_type' claim with a value of 'token' which is required to match the value 'code' in the parameter with the same name from the OAuth 2.0 request syntax.",
		},
		{
			name:      "ShouldFailMismatchedResponseTypeAsserted",
			have:      url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow}, consts.FormParameterResponseMode: {consts.ResponseModeNone}, consts.FormParameterRequest: {assertionRequestObjectInvalidResponseTypeValue}},
			client:    &DefaultJARClient{JSONWebKeys: jwksPublic, RequestObjectSigningAlg: "RS256", DefaultClient: &DefaultClient{ID: "foo"}},
			expected:  url.Values{consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeImplicitFlowToken}, consts.FormParameterResponseMode: {consts.ResponseModeFormPost}, consts.FormParameterScope: {"foo openid"}, consts.FormParameterRequest: {assertionRequestObjectInvalidResponseTypeValue}, "foo": {"bar"}, "baz": {"baz"}},
			err:       ErrInvalidRequestObject,
			errString: "The request parameter contains an invalid Request Object. OpenID Connect 1.0 request included a request object which excluded claims that are required or included claims that did not match the OAuth 2.0 request syntax or are generally not permitted. The OAuth 2.0 client with id 'foo' included a request object with a 'response_type' claim with a value of '100' which is required to match the value 'code' in the parameter with the same name from the OAuth 2.0 request syntax but instead of a string it had the int64 type.",
		},
		{
			name:     "ShouldPassWithoutKID",
			have:     url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow}, consts.FormParameterRequest: {assertionRequestObjectValidWithoutKID}},
			client:   &DefaultJARClient{JSONWebKeys: jwksPublic, RequestObjectSigningAlg: "RS256", DefaultClient: &DefaultClient{ID: "foo"}},
			expected: url.Values{consts.FormParameterScope: {"foo openid"}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow}, consts.FormParameterRequest: {assertionRequestObjectValidWithoutKID}, "foo": {"bar"}, "baz": {"baz"}},
		},
		{
			name:     "ShouldFailRequestURINotWhiteListed",
			have:     url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow}, consts.FormParameterRequestURI: {root.JoinPath("request-object", "valid", "standard.jwk").String()}},
			client:   &DefaultJARClient{JSONWebKeys: jwksPublic, RequestObjectSigningAlg: "RS256", DefaultClient: &DefaultClient{ID: "foo"}},
			expected: url.Values{consts.FormParameterScope: {"foo openid"}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow}, consts.FormParameterRequest: {assertionRequestObjectValidWithoutKID}, "foo": {"bar"}, "baz": {"baz"}},
			err:      ErrInvalidRequestURI,
			errRegex: regexp.MustCompile(`^The request_uri in the authorization request returns an error or contains invalid data\. OpenID Connect 1\.0 request failed to fetch request parameters from the provided 'request_uri'\. The OAuth 2\.0 client with id 'foo' provided the 'request_uri' parameter with value 'http://127.0.0.1:\d+/request-object/valid/standard\.jwk' which is not whitelisted.$`),
		},
		{
			name:     "ShouldPassRequestURIFetch",
			have:     url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeImplicitFlowToken}, consts.FormParameterRequestURI: {root.JoinPath("request-object", "valid", "standard.jwk").String()}},
			client:   &DefaultJARClient{JSONWebKeysURI: root.JoinPath("jwks.json").String(), RequestObjectSigningAlg: "RS256", RequestURIs: []string{root.JoinPath("request-object", "valid", "standard.jwk").String()}, DefaultClient: &DefaultClient{ID: "foo"}},
			expected: url.Values{consts.FormParameterResponseType: {"token"}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseMode: {consts.ResponseModeFormPost}, consts.FormParameterScope: {"foo openid"}, consts.FormParameterRequestURI: {root.JoinPath("request-object", "valid", "standard.jwk").String()}, "foo": {"bar"}, "baz": {"baz"}},
		},
		{
			name:      "ShouldFailRequestAlgNone",
			have:      url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow}, consts.FormParameterRequest: {assertionRequestObjectValidNone}},
			client:    &DefaultJARClient{JSONWebKeysURI: root.JoinPath("jwks.json").String(), RequestObjectSigningAlg: "RS256", DefaultClient: &DefaultClient{ID: "foo"}},
			expected:  url.Values{consts.FormParameterState: {"some-state"}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow}, consts.FormParameterScope: {"foo openid"}, consts.FormParameterRequest: {assertionRequestObjectValidNone}, "foo": {"bar"}, "baz": {"baz"}},
			err:       ErrInvalidRequestObject,
			errString: "The request parameter contains an invalid Request Object. OpenID Connect 1.0 request object could not be decoded or validated. OpenID Connect 1.0 client with id 'foo' expects request objects to be signed with the 'alg' header value 'RS256' due to the client registration 'request_object_signing_alg' value but the request object was signed with the 'alg' header value 'none'.",
		},
		{
			name:      "ShouldFailRequestURIAlgNone",
			have:      url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeImplicitFlowToken}, consts.FormParameterRequestURI: {root.JoinPath("request-object", "valid", "none.jwk").String()}},
			client:    &DefaultJARClient{JSONWebKeysURI: root.JoinPath("jwks.json").String(), RequestObjectSigningAlg: "RS256", RequestURIs: []string{root.JoinPath("request-object", "valid", "none.jwk").String()}, DefaultClient: &DefaultClient{ID: "foo"}},
			expected:  url.Values{consts.FormParameterResponseType: {"token"}, consts.FormParameterClientID: {"foo"}, consts.FormParameterState: {"some-state"}, consts.FormParameterScope: {"foo openid"}, consts.FormParameterRequestURI: {root.JoinPath("request-object", "valid", "none.jwk").String()}, "foo": {"bar"}, "baz": {"baz"}},
			err:       ErrInvalidRequestObject,
			errString: "The request parameter contains an invalid Request Object. OpenID Connect 1.0 request object could not be decoded or validated. OpenID Connect 1.0 client with id 'foo' expects request objects to be signed with the 'alg' header value 'RS256' due to the client registration 'request_object_signing_alg' value but the request object was signed with the 'alg' header value 'none'.",
		},
		{
			name:      "ShouldFailRequestRS256",
			have:      url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow}, consts.FormParameterRequest: {assertionRequestObjectValid}},
			client:    &DefaultJARClient{JSONWebKeysURI: root.JoinPath("jwks.json").String(), RequestObjectSigningAlg: consts.JSONWebTokenAlgNone, DefaultClient: &DefaultClient{ID: "foo"}},
			expected:  url.Values{consts.FormParameterState: {"some-state"}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow}, consts.FormParameterScope: {"foo openid"}, consts.FormParameterRequest: {assertionRequestObjectValid}, "foo": {"bar"}, "baz": {"baz"}},
			err:       ErrInvalidRequestObject,
			errString: "The request parameter contains an invalid Request Object. OpenID Connect 1.0 request object could not be decoded or validated. OpenID Connect 1.0 client with id 'foo' expects request objects to be signed with the 'alg' header value 'none' due to the client registration 'request_object_signing_alg' value but the request object was signed with the 'alg' header value 'RS256'.",
		},
		{
			name:      "ShouldFailRequestURIRS256",
			have:      url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeImplicitFlowToken}, consts.FormParameterRequestURI: {root.JoinPath("request-object", "valid", "standard.jwk").String()}},
			client:    &DefaultJARClient{JSONWebKeysURI: root.JoinPath("jwks.json").String(), RequestObjectSigningAlg: consts.JSONWebTokenAlgNone, RequestURIs: []string{root.JoinPath("request-object", "valid", "standard.jwk").String()}, DefaultClient: &DefaultClient{ID: "foo"}},
			expected:  url.Values{consts.FormParameterResponseType: {"token"}, consts.FormParameterClientID: {"foo"}, consts.FormParameterState: {"some-state"}, consts.FormParameterScope: {"foo openid"}, consts.FormParameterRequestURI: {root.JoinPath("request-object", "valid", "standard.jwk").String()}, "foo": {"bar"}, "baz": {"baz"}},
			err:       ErrInvalidRequestObject,
			errString: "The request parameter contains an invalid Request Object. OpenID Connect 1.0 request object could not be decoded or validated. OpenID Connect 1.0 client with id 'foo' expects request objects to be signed with the 'alg' header value 'none' due to the client registration 'request_object_signing_alg' value but the request object was signed with the 'alg' header value 'RS256'.",
		},
		{
			name:     "ShouldPassRequestAlgNone",
			have:     url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow}, consts.FormParameterRequest: {assertionRequestObjectValidNone}},
			client:   &DefaultJARClient{JSONWebKeysURI: root.JoinPath("jwks.json").String(), RequestObjectSigningAlg: consts.JSONWebTokenAlgNone, DefaultClient: &DefaultClient{ID: "foo"}},
			expected: url.Values{consts.FormParameterState: {"some-state"}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow}, consts.FormParameterScope: {"foo openid"}, consts.FormParameterRequest: {assertionRequestObjectValidNone}, "foo": {"bar"}, "baz": {"baz"}},
		},
		{
			name:     "ShouldPassRequestURIAlgNone",
			have:     url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeImplicitFlowToken}, consts.FormParameterRequestURI: {root.JoinPath("request-object", "valid", "none.jwk").String()}},
			client:   &DefaultJARClient{JSONWebKeysURI: root.JoinPath("jwks.json").String(), RequestObjectSigningAlg: consts.JSONWebTokenAlgNone, RequestURIs: []string{root.JoinPath("request-object", "valid", "none.jwk").String()}, DefaultClient: &DefaultClient{ID: "foo"}},
			expected: url.Values{consts.FormParameterResponseType: {"token"}, consts.FormParameterClientID: {"foo"}, consts.FormParameterState: {"some-state"}, consts.FormParameterScope: {"foo openid"}, consts.FormParameterRequestURI: {root.JoinPath("request-object", "valid", "none.jwk").String()}, "foo": {"bar"}, "baz": {"baz"}},
		},
		{
			name:     "ShouldPassRequestAlgHS256",
			have:     url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow}, consts.FormParameterRequest: {assertionRequestObjectValidHS256}},
			client:   &DefaultJARClient{JSONWebKeysURI: root.JoinPath("jwks.json").String(), RequestObjectSigningAlg: string(jose.HS256), DefaultClient: &DefaultClient{ID: "foo", ClientSecret: clientSecretHS256}},
			expected: url.Values{consts.FormParameterState: {"some-state"}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow}, consts.FormParameterScope: {"foo openid"}, consts.FormParameterRequest: {assertionRequestObjectValidHS256}, "foo": {"bar"}, "baz": {"baz"}},
		},
		{
			name:      "ShouldPassRequestAlgNoneAllowAny",
			have:      url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow}, consts.FormParameterRequest: {assertionRequestObjectValidNone}},
			client:    &DefaultJARClient{JSONWebKeysURI: root.JoinPath("jwks.json").String(), DefaultClient: &DefaultClient{ID: "foo"}},
			expected:  url.Values{consts.FormParameterState: {"some-state"}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow}, consts.FormParameterScope: {"foo openid"}, consts.FormParameterRequest: {assertionRequestObjectValidNone}, "foo": {"bar"}, "baz": {"baz"}},
			err:       ErrInvalidRequestObject,
			errString: "The request parameter contains an invalid Request Object. OpenID Connect 1.0 client provided a request object that has an invalid 'kid' or 'alg' header value. OpenID Connect 1.0 client with id 'foo' was not explicitly registered with a 'request_object_signing_alg' value of 'none' but the request object had the 'alg' value 'none' in the header.",
		},
		{
			name:      "ShouldPassRequestURIAlgNoneAllowAny",
			have:      url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeImplicitFlowToken}, consts.FormParameterRequestURI: {root.JoinPath("request-object", "valid", "none.jwk").String()}},
			client:    &DefaultJARClient{JSONWebKeysURI: root.JoinPath("jwks.json").String(), RequestObjectSigningAlg: "", RequestURIs: []string{root.JoinPath("request-object", "valid", "none.jwk").String()}, DefaultClient: &DefaultClient{ID: "foo"}},
			expected:  url.Values{consts.FormParameterResponseType: {"token"}, consts.FormParameterClientID: {"foo"}, consts.FormParameterState: {"some-state"}, consts.FormParameterScope: {"foo openid"}, consts.FormParameterRequestURI: {root.JoinPath("request-object", "valid", "none.jwk").String()}, "foo": {"bar"}, "baz": {"baz"}},
			err:       ErrInvalidRequestObject,
			errString: "The request parameter contains an invalid Request Object. OpenID Connect 1.0 client provided a request object that has an invalid 'kid' or 'alg' header value. OpenID Connect 1.0 client with id 'foo' was not explicitly registered with a 'request_object_signing_alg' value of 'none' but the request object had the 'alg' value 'none' in the header.",
		},
		{
			name:      "ShouldFailRequestBadAudience",
			have:      url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow}, consts.FormParameterRequest: {assertionRequestObjectInvalidAudience}},
			client:    &DefaultJARClient{JSONWebKeysURI: root.JoinPath("jwks.json").String(), RequestObjectSigningAlg: "RS256", DefaultClient: &DefaultClient{ID: "foo"}},
			expected:  url.Values{consts.FormParameterState: {"some-state"}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow}, consts.FormParameterScope: {"foo openid"}, consts.FormParameterRequest: {assertionRequestObjectValidNone}, "foo": {"bar"}, "baz": {"baz"}},
			err:       ErrInvalidRequestObject,
			errString: "The request parameter contains an invalid Request Object. OpenID Connect 1.0 request object could not be decoded or validated. OpenID Connect 1.0 client with id 'foo' provided a request object that has an invalid audience. The request object was expected to have an 'aud' claim which matches the issuer value of 'https://auth.example.com' but the 'aud' claim had the values 'https://auth.not-example.com'.",
		},
		{
			name:      "ShouldFailRequestURIBadAudience",
			have:      url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeImplicitFlowToken}, consts.FormParameterRequestURI: {root.JoinPath("request-object", "invalid", "audience.jwk").String()}},
			client:    &DefaultJARClient{JSONWebKeysURI: root.JoinPath("jwks.json").String(), RequestObjectSigningAlg: "RS256", RequestURIs: []string{root.JoinPath("request-object", "invalid", "audience.jwk").String()}, DefaultClient: &DefaultClient{ID: "foo"}},
			expected:  url.Values{consts.FormParameterResponseType: {"token"}, consts.FormParameterClientID: {"foo"}, consts.FormParameterState: {"some-state"}, consts.FormParameterScope: {"foo openid"}, consts.FormParameterRequestURI: {root.JoinPath("request-object", "invalid", "audience.jwk").String()}, "foo": {"bar"}, "baz": {"baz"}},
			err:       ErrInvalidRequestObject,
			errString: "The request parameter contains an invalid Request Object. OpenID Connect 1.0 request included a request object which excluded claims that are required or included claims that did not match the OAuth 2.0 request syntax or are generally not permitted. The OAuth 2.0 client with id 'foo' included a request object with a 'response_type' claim with a value of 'code' which is required to match the value 'token' in the parameter with the same name from the OAuth 2.0 request syntax.",
		},
		{
			name:      "ShouldFailRequestBadIssuer",
			have:      url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow}, consts.FormParameterRequest: {assertionRequestObjectInvalidIssuer}},
			client:    &DefaultJARClient{JSONWebKeysURI: root.JoinPath("jwks.json").String(), RequestObjectSigningAlg: "RS256", DefaultClient: &DefaultClient{ID: "foo"}},
			expected:  url.Values{consts.FormParameterState: {"some-state"}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow}, consts.FormParameterScope: {"foo openid"}, consts.FormParameterRequest: {assertionRequestObjectValidNone}, "foo": {"bar"}, "baz": {"baz"}},
			err:       ErrInvalidRequestObject,
			errString: "The request parameter contains an invalid Request Object. OpenID Connect 1.0 request object could not be decoded or validated. OpenID Connect 1.0 client with id 'foo' provided a request object that has an invalid issuer. The request object was expected to have an 'iss' claim which matches the value 'foo' but the 'iss' claim had the value 'not-foo'.",
		},
		{
			name:      "ShouldFailRequestURIBadIssuer",
			have:      url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterClientID: {"foo"}, consts.FormParameterResponseType: {consts.ResponseTypeImplicitFlowToken}, consts.FormParameterRequestURI: {root.JoinPath("request-object", "invalid", "issuer.jwk").String()}},
			client:    &DefaultJARClient{JSONWebKeysURI: root.JoinPath("jwks.json").String(), RequestObjectSigningAlg: "RS256", RequestURIs: []string{root.JoinPath("request-object", "invalid", "issuer.jwk").String()}, DefaultClient: &DefaultClient{ID: "foo"}},
			expected:  url.Values{consts.FormParameterResponseType: {"token"}, consts.FormParameterClientID: {"foo"}, consts.FormParameterState: {"some-state"}, consts.FormParameterScope: {"foo openid"}, consts.FormParameterRequestURI: {root.JoinPath("request-object", "invalid", "issuer.jwk").String()}, "foo": {"bar"}, "baz": {"baz"}},
			err:       ErrInvalidRequestObject,
			errString: "The request parameter contains an invalid Request Object. OpenID Connect 1.0 request included a request object which excluded claims that are required or included claims that did not match the OAuth 2.0 request syntax or are generally not permitted. The OAuth 2.0 client with id 'foo' included a request object with a 'response_type' claim with a value of 'code' which is required to match the value 'token' in the parameter with the same name from the OAuth 2.0 request syntax.",
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

			config := &Config{JWKSFetcherStrategy: NewDefaultJWKSFetcherStrategy(), IDTokenIssuer: "https://auth.example.com"}

			strategy := &jwt.DefaultStrategy{
				Config: config,
				Issuer: jwt.NewDefaultIssuerUnverifiedFromJWKS(jwksPrivate),
			}

			provider := &Fosite{Config: &Config{JWKSFetcherStrategy: NewDefaultJWKSFetcherStrategy(), IDTokenIssuer: "https://auth.example.com", JWTStrategy: strategy}}

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
	tokenString, err := token.CompactSignedString(key)
	require.NoError(t, err)
	return tokenString
}

func mustGenerateHSAssertion(t *testing.T, claims jwt.MapClaims) string {
	token := jwt.NewWithClaims(jose.HS256, claims)
	tokenString, err := token.CompactSignedString([]byte("aaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbcccccccccccccccccccccddddddddddddddddddddddd"))
	require.NoError(t, err)
	return tokenString
}

func mangleSig(tokenString string) string {
	parts := strings.Split(tokenString, ".")
	raw, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		panic(err)
	}

	raw = append(raw, []byte("abc")...)

	parts[2] = base64.RawURLEncoding.EncodeToString(raw)

	return strings.Join(parts, ".")
}

func mustGenerateRequestObjectJWS(t *testing.T, claims jwt.MapClaims, headers jwt.Mapper, key *jose.JSONWebKey) string {
	token, _, err := jwt.EncodeCompactSigned(context.TODO(), claims, headers, key)
	require.NoError(t, err)

	return token
}

func mustGenerateRequestObjectJWE(t *testing.T, claims jwt.MapClaims, headers, headersJWE jwt.Mapper, key *jose.JSONWebKey, keyEnc *jose.JSONWebKey, enc jose.ContentEncryption) string {
	token, _, err := jwt.EncodeNestedCompactEncrypted(context.TODO(), claims, headers, headersJWE, key, keyEnc, enc)
	require.NoError(t, err)

	return token
}
