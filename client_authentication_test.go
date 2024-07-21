// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestAuthenticateClient(t *testing.T) {
	keyRSA := gen.MustRSAKey()
	jwksRSA := &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				KeyID: "kid-foo",
				Use:   "sig",
				Key:   &keyRSA.PublicKey,
			},
		},
	}

	keyECDSA := gen.MustES256Key()
	jwksECDSA := &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				KeyID: "kid-foo",
				Use:   "sig",
				Key:   &keyECDSA.PublicKey,
			},
		},
	}

	complexSecretRaw := "foo %66%6F%6F@$<§!✓" //nolint:gosec

	testCases := []struct {
		name          string
		client        func(ts *httptest.Server) Client
		assertionType string
		assertion     string
		r             *http.Request
		form          url.Values
		err           string
		expectErr     error
	}{
		{
			name: "ShouldFailBecauseAuthenticationCanNotBeDetermined",
			client: func(ts *httptest.Server) Client {
				return &DefaultJARClient{DefaultClient: &DefaultClient{ID: "foo"}, TokenEndpointAuthMethod: "client_secret_basic"}
			},
			form: url.Values{},
			r:    new(http.Request),
			err:  "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Client Credentials missing or malformed. The Client ID was missing from the request but it is required when there is no client assertion.",
		},
		{
			name: "ShouldFailBecauseClientDoesNotExist",
			client: func(ts *httptest.Server) Client {
				return &DefaultJARClient{DefaultClient: &DefaultClient{ID: "foo", Public: true}, TokenEndpointAuthMethod: "none"}
			},
			form: url.Values{"client_id": []string{"bar"}},
			r:    new(http.Request),
			err:  "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). Could not find the requested resource(s).",
		},
		{
			name: "ShouldPassBecauseClientIsPublicAndAuthenticationRequirementsAreMet",
			client: func(ts *httptest.Server) Client {
				return &DefaultJARClient{DefaultClient: &DefaultClient{ID: "foo", Public: true}, TokenEndpointAuthMethod: "none"}
			},
			form: url.Values{"client_id": []string{"foo"}},
			r:    new(http.Request),
		},
		{
			name: "ShouldPassBecauseClientIsPublicAndClientSecretIsEmptyInQueryParam",
			client: func(ts *httptest.Server) Client {
				return &DefaultJARClient{DefaultClient: &DefaultClient{ID: "foo", Public: true}, TokenEndpointAuthMethod: "none"}
			},
			form: url.Values{"client_id": []string{"foo"}, "client_secret": []string{""}},
			r:    new(http.Request),
		},
		{
			name: "ShouldPassBecauseClientIsPublicAndClientSecretIsEmptyInBasicAuthHeader",
			client: func(ts *httptest.Server) Client {
				return &DefaultJARClient{DefaultClient: &DefaultClient{ID: "foo", Public: true}, TokenEndpointAuthMethod: "none"}
			},
			form: url.Values{},
			r:    &http.Request{Header: clientBasicAuthHeader("foo", "")},
		},
		{
			name: "ShouldFailBecauseClientRequiresBasicAuthAndClientSecretIsEmptyInBasicAuthHeader",
			client: func(ts *httptest.Server) Client {
				return &DefaultJARClient{DefaultClient: &DefaultClient{ID: "foo", Public: true}, TokenEndpointAuthMethod: "client_secret_basic"}
			},
			form: url.Values{},
			r:    &http.Request{Header: clientBasicAuthHeader("foo", "")},
			err:  "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). The request was determined to be using 'token_endpoint_auth_method' method 'none', however the OAuth 2.0 client registration does not allow this method. The registered client with id 'foo' is configured to only support 'token_endpoint_auth_method' method 'client_secret_basic'. Either the Authorization Server client registration will need to have the 'token_endpoint_auth_method' updated to 'none' or the Relying Party will need to be configured to use 'client_secret_basic'.",
		},
		{
			name: "ShouldPassWithClientCredentialsContainingSpecialCharacters",
			client: func(ts *httptest.Server) Client {
				return &DefaultJARClient{DefaultClient: &DefaultClient{ID: "!foo%20bar", ClientSecret: testClientSecretComplex}, TokenEndpointAuthMethod: "client_secret_post"}
			},
			form: url.Values{"client_id": []string{"!foo%20bar"}, "client_secret": []string{complexSecretRaw}},
			r:    new(http.Request),
		},
		{
			name: "ShouldFailWithMultipleAuthenticationMethodsClientMethodBasic",
			client: func(ts *httptest.Server) Client {
				return &DefaultJARClient{DefaultClient: &DefaultClient{ID: "abc", ClientSecret: testClientSecretComplex}, TokenEndpointAuthMethod: "client_secret_basic"}
			},
			form: url.Values{"client_id": []string{"abc"}, "client_secret": []string{complexSecretRaw}},
			r:    &http.Request{Header: clientBasicAuthHeader("abc", complexSecretRaw)},
			err:  "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Client Authentication failed with more than one known authentication method included in the request which is not permitted. The registered client with id 'abc' and the authorization server policy does not permit this malformed request. The `token_endpoint_auth_method` methods determined to be used were 'client_secret_basic', 'client_secret_post'.",
		},
		{
			name: "ShouldFailWithMultipleAuthenticationMethodsClientMethodPost",
			client: func(ts *httptest.Server) Client {
				return &DefaultJARClient{DefaultClient: &DefaultClient{ID: "abc", ClientSecret: testClientSecretComplex}, TokenEndpointAuthMethod: "client_secret_post"}
			},
			form: url.Values{"client_id": []string{"abc"}, "client_secret": []string{complexSecretRaw}},
			r:    &http.Request{Header: clientBasicAuthHeader("abc", complexSecretRaw)},
			err:  "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Client Authentication failed with more than one known authentication method included in the request which is not permitted. The registered client with id 'abc' and the authorization server policy does not permit this malformed request. The `token_endpoint_auth_method` methods determined to be used were 'client_secret_basic', 'client_secret_post'.",
		},
		{
			name: "ShouldPassWithMultipleAuthenticationMethods",
			client: func(ts *httptest.Server) Client {
				return &TestClientAuthenticationPolicyClient{
					&DefaultJARClient{DefaultClient: &DefaultClient{ID: "abc", ClientSecret: testClientSecretComplex}, TokenEndpointAuthMethod: "client_secret_basic"},
					true,
				}
			},
			form: url.Values{"client_id": []string{"abc"}, "client_secret": []string{complexSecretRaw}},
			r:    &http.Request{Header: clientBasicAuthHeader("abc", complexSecretRaw)},
		},
		{
			name: "ShouldFailBecauseAuthMethodIsNotNone",
			client: func(ts *httptest.Server) Client {
				return &DefaultJARClient{DefaultClient: &DefaultClient{ID: "foo", Public: true}, TokenEndpointAuthMethod: "client_secret_basic"}
			}, form: url.Values{"client_id": []string{"foo"}},
			r:         new(http.Request),
			err:       "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). The request was determined to be using 'token_endpoint_auth_method' method 'none', however the OAuth 2.0 client registration does not allow this method. The registered client with id 'foo' is configured to only support 'token_endpoint_auth_method' method 'client_secret_basic'. Either the Authorization Server client registration will need to have the 'token_endpoint_auth_method' updated to 'none' or the Relying Party will need to be configured to use 'client_secret_basic'.",
			expectErr: ErrInvalidClient,
		},
		{
			name: "ShouldPassBecauseClientIsConfidentialAndIdAndSecretMatchInPostBody",
			client: func(ts *httptest.Server) Client {
				return &DefaultJARClient{DefaultClient: &DefaultClient{ID: "foo", ClientSecret: testClientSecretBar, RotatedClientSecrets: []ClientSecret{testClientSecretBar}}, TokenEndpointAuthMethod: "client_secret_post"}
			}, form: url.Values{"client_id": []string{"foo"}, "client_secret": []string{"bar"}},
			r: new(http.Request),
		},
		{
			name: "ShouldPassBecauseClientIsConfidentialAndIdAndRotatedSecretMatchInPostBody",
			client: func(ts *httptest.Server) Client {
				return &DefaultJARClient{DefaultClient: &DefaultClient{ID: "foo", ClientSecret: testClientSecretBar}, TokenEndpointAuthMethod: "client_secret_post"}
			}, form: url.Values{"client_id": []string{"foo"}, "client_secret": []string{"bar"}},
			r: new(http.Request),
		},
		{
			name: "ShouldFailBecauseClientIsConfidentialAndSecretDoesNotMatchInPostBody",
			client: func(ts *httptest.Server) Client {
				return &DefaultJARClient{DefaultClient: &DefaultClient{ID: "foo", ClientSecret: testClientSecretBar}, TokenEndpointAuthMethod: "client_secret_post"}
			}, form: url.Values{"client_id": []string{"foo"}, "client_secret": []string{"baz"}},
			r:         new(http.Request),
			expectErr: ErrInvalidClient,
		},
		{
			name: "ShouldFailBecauseClientIsConfidentialAndIdDoesNotExistInPostBody",
			client: func(ts *httptest.Server) Client {
				return &DefaultJARClient{DefaultClient: &DefaultClient{ID: "bar", ClientSecret: testClientSecretBar}, TokenEndpointAuthMethod: "client_secret_post"}
			}, form: url.Values{"client_id": []string{"foo"}, "client_secret": []string{"bar"}},
			r:         new(http.Request),
			expectErr: ErrInvalidClient,
		},
		{
			name: "ShouldPassBecauseClientIsConfidentialAndIdAndSecretMatchInHeader",
			client: func(ts *httptest.Server) Client {
				return &DefaultJARClient{DefaultClient: &DefaultClient{ID: "foo", ClientSecret: testClientSecretBar}, TokenEndpointAuthMethod: "client_secret_basic"}
			}, form: url.Values{},
			r: &http.Request{Header: clientBasicAuthHeader("foo", "bar")},
		},
		{
			name: "ShouldFailBecauseClientIsConfidentialAndIdAndSecretInHeaderIsNotRegistered",
			client: func(ts *httptest.Server) Client {
				return &DefaultJARClient{DefaultClient: &DefaultClient{ID: "foo", ClientSecret: &BCryptClientSecret{}}, TokenEndpointAuthMethod: "client_secret_basic"}
			}, form: url.Values{},
			r:         &http.Request{Header: clientBasicAuthHeader("foo", "bar")},
			err:       "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). The request was determined to be using 'token_endpoint_auth_method' method 'client_secret_basic', however the OAuth 2.0 client registration does not allow this method. The registered client with id 'foo' has no 'client_secret' however this is required to process the particular request.",
			expectErr: ErrInvalidClient,
		},
		{
			name: "ShouldPassEscapedClientCredentials",
			client: func(ts *httptest.Server) Client {
				return &DefaultJARClient{DefaultClient: &DefaultClient{ID: "foo", ClientSecret: testClientSecretComplex}, TokenEndpointAuthMethod: "client_secret_basic"}
			}, form: url.Values{},
			r: &http.Request{Header: clientBasicAuthHeader("foo", "foo %66%6F%6F@$<§!✓")},
		},
		{
			name: "ShouldPassBecauseClientIsConfidentialAndIdAndRotatedSecretMatchInHeader",
			client: func(ts *httptest.Server) Client {
				return &DefaultJARClient{DefaultClient: &DefaultClient{ID: "foo", ClientSecret: testClientSecretFoo, RotatedClientSecrets: []ClientSecret{testClientSecretBar}}, TokenEndpointAuthMethod: "client_secret_basic"}
			}, form: url.Values{},
			r: &http.Request{Header: clientBasicAuthHeader("foo", "bar")},
		},
		{
			name: "ShouldFailBecauseAuthMethodIsNotClientSecretBasic",
			client: func(ts *httptest.Server) Client {
				return &DefaultJARClient{DefaultClient: &DefaultClient{ID: "foo", ClientSecret: testClientSecretBar}, TokenEndpointAuthMethod: "client_secret_post"}
			}, form: url.Values{},
			r:         &http.Request{Header: clientBasicAuthHeader("foo", "bar")},
			expectErr: ErrInvalidClient,
		},
		{
			name: "ShouldFailBecauseClientIsConfidentialAndSecretDoesNotMatchInHeader",
			client: func(ts *httptest.Server) Client {
				return &DefaultJARClient{DefaultClient: &DefaultClient{ID: "foo", ClientSecret: testClientSecretFoo}, TokenEndpointAuthMethod: "client_secret_basic"}
			}, form: url.Values{},
			r:         &http.Request{Header: clientBasicAuthHeader("foo", "baz")},
			expectErr: ErrInvalidClient,
		},
		{
			name: "ShouldFailBecauseClientIsConfidentialAndNeitherSecretNorRotatedDoesMatchInHeader",
			client: func(ts *httptest.Server) Client {
				return &DefaultJARClient{DefaultClient: &DefaultClient{ID: "foo", ClientSecret: testClientSecretFoo, RotatedClientSecrets: []ClientSecret{testClientSecretFoo}}, TokenEndpointAuthMethod: "client_secret_basic"}
			}, form: url.Values{},
			r:         &http.Request{Header: clientBasicAuthHeader("foo", "baz")},
			expectErr: ErrInvalidClient,
			err:       "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). crypto/bcrypt: hashedPassword is not the hash of the given password",
		},
		{
			name: "ShouldFailBecauseClientIdIsNotValid",
			client: func(ts *httptest.Server) Client {
				return &DefaultJARClient{DefaultClient: &DefaultClient{ID: "foo", ClientSecret: testClientSecretBar}, TokenEndpointAuthMethod: "client_secret_basic"}
			}, form: url.Values{},
			r:         &http.Request{Header: http.Header{consts.HeaderAuthorization: {prefixSchemeBasic + base64.StdEncoding.EncodeToString([]byte("%%%%%%:foo"))}}},
			err:       "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The client credentials in the HTTP authorization header could not be parsed. Either the scheme was missing, the scheme was invalid, or the value had malformed data. The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The client id in the HTTP authorization header could not be decoded from 'application/x-www-form-urlencoded'. invalid URL escape '%%%'",
			expectErr: ErrInvalidRequest,
		},
		{
			name: "ShouldFailBecauseClientSecretIsNotValid",
			client: func(ts *httptest.Server) Client {
				return &DefaultJARClient{DefaultClient: &DefaultClient{ID: "foo", ClientSecret: testClientSecretBar}, TokenEndpointAuthMethod: "client_secret_basic"}
			}, form: url.Values{},
			r:         &http.Request{Header: http.Header{consts.HeaderAuthorization: {prefixSchemeBasic + base64.StdEncoding.EncodeToString([]byte("foo:%%%%%%%"))}}},
			err:       "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The client credentials in the HTTP authorization header could not be parsed. Either the scheme was missing, the scheme was invalid, or the value had malformed data. The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The client secret in the HTTP authorization header could not be decoded from 'application/x-www-form-urlencoded'. invalid URL escape '%%%'",
			expectErr: ErrInvalidRequest,
		},
		{
			name: "ShouldFailBecauseBasicValueIsNotValid",
			client: func(ts *httptest.Server) Client {
				return &DefaultJARClient{DefaultClient: &DefaultClient{ID: "foo", ClientSecret: testClientSecretBar}, TokenEndpointAuthMethod: "client_secret_basic"}
			}, form: url.Values{},
			r:         &http.Request{Header: http.Header{consts.HeaderAuthorization: {prefixSchemeBasic + base64.StdEncoding.EncodeToString([]byte("foo"))}}},
			err:       "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The client credentials in the HTTP authorization header could not be parsed. Either the scheme was missing, the scheme was invalid, or the value had malformed data. The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The client credentials from the HTTP authorization header could not be parsed. The basic scheme value was not separated by a colon.",
			expectErr: ErrInvalidRequest,
		},
		{
			name: "ShouldFailBecauseSchemeIsNotValid",
			client: func(ts *httptest.Server) Client {
				return &DefaultJARClient{DefaultClient: &DefaultClient{ID: "foo", ClientSecret: testClientSecretBar}, TokenEndpointAuthMethod: "client_secret_basic"}
			}, form: url.Values{},
			r:         &http.Request{Header: http.Header{consts.HeaderAuthorization: {"NotBasic " + base64.StdEncoding.EncodeToString([]byte("foo:bar"))}}},
			err:       "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The client credentials in the HTTP authorization header could not be parsed. Either the scheme was missing, the scheme was invalid, or the value had malformed data. The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The client credentials from the HTTP authorization header had an unknown scheme. The scheme 'NotBasic' is not known for client authentication.",
			expectErr: ErrInvalidRequest,
		},
		{
			name: "ShouldFailBecauseHeaderIsNotEncoded",
			client: func(ts *httptest.Server) Client {
				return &DefaultJARClient{DefaultClient: &DefaultClient{ID: "foo", ClientSecret: testClientSecretBar}, TokenEndpointAuthMethod: "client_secret_basic"}
			}, form: url.Values{},
			r:         &http.Request{Header: http.Header{consts.HeaderAuthorization: {prefixSchemeBasic + "foo:bar"}}},
			err:       "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The client credentials in the HTTP authorization header could not be parsed. Either the scheme was missing, the scheme was invalid, or the value had malformed data. The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The client credentials from the HTTP authorization header could not be parsed. Error occurred performing a base64 decode: illegal base64 data at input byte 3.",
			expectErr: ErrInvalidRequest,
		},
		{
			name: "ShouldFailBecauseAuthorizationHeaderIsNotValid",
			client: func(ts *httptest.Server) Client {
				return &DefaultJARClient{DefaultClient: &DefaultClient{ID: "foo", ClientSecret: testClientSecretBar}, TokenEndpointAuthMethod: "client_secret_basic"}
			}, form: url.Values{},
			r:         &http.Request{Header: http.Header{consts.HeaderAuthorization: {"Basic" + base64.StdEncoding.EncodeToString([]byte("foo:bar"))}}},
			err:       "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The client credentials in the HTTP authorization header could not be parsed. Either the scheme was missing, the scheme was invalid, or the value had malformed data. The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The client credentials from the HTTP authorization header could not be parsed. The header value is either missing a scheme, value, or the separator between them.",
			expectErr: ErrInvalidRequest,
		},
		{
			name: "ShouldFailBecauseNonVSCHARClientID",
			client: func(ts *httptest.Server) Client {
				return &DefaultJARClient{DefaultClient: &DefaultClient{ID: "foo", ClientSecret: testClientSecretBar}, TokenEndpointAuthMethod: "client_secret_basic"}
			}, form: url.Values{},
			r:         &http.Request{Header: clientBasicAuthHeader("\x19foo", "bar")},
			err:       "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The client credentials in the HTTP authorization header could not be parsed. Either the scheme was missing, the scheme was invalid, or the value had malformed data. The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The client id in the HTTP request had an invalid character.",
			expectErr: ErrInvalidRequest,
		},
		{
			name: "ShouldFailBecauseNonVSCHARClientSecret",
			client: func(ts *httptest.Server) Client {
				return &DefaultJARClient{DefaultClient: &DefaultClient{ID: "foo", ClientSecret: testClientSecretBar}, TokenEndpointAuthMethod: "client_secret_basic"}
			}, form: url.Values{},
			r:         &http.Request{Header: clientBasicAuthHeader("foo", "\x19bar")},
			err:       "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The client credentials in the HTTP authorization header could not be parsed. Either the scheme was missing, the scheme was invalid, or the value had malformed data. The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The client secret in the HTTP request had an invalid character.",
			expectErr: ErrInvalidRequest,
		},
		{
			name: "ShouldFailBecauseClientIsConfidentialAndIdDoesNotExistInHeader",
			client: func(ts *httptest.Server) Client {
				return &DefaultJARClient{DefaultClient: &DefaultClient{ID: "bar", ClientSecret: testClientSecretBar}, TokenEndpointAuthMethod: "client_secret_basic"}
			}, form: url.Values{},
			r:         &http.Request{Header: http.Header{consts.HeaderAuthorization: {prefixSchemeBasic + base64.StdEncoding.EncodeToString([]byte("foo:bar"))}}},
			expectErr: ErrInvalidClient,
			err:       "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). Could not find the requested resource(s).",
		},
		{
			name: "ShouldFailBecauseClientAssertionButClientAssertionIsMissing",
			client: func(ts *httptest.Server) Client {
				return &DefaultJARClient{DefaultClient: &DefaultClient{ID: "foo", ClientSecret: testClientSecretBar}, TokenEndpointAuthMethod: "private_key_jwt"}
			}, form: url.Values{"client_id": []string{"foo"}, "client_assertion_type": []string{consts.ClientAssertionTypeJWTBearer}},
			r:         new(http.Request),
			expectErr: ErrInvalidRequest,
			err:       "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The request parameter 'client_assertion' must be set when using 'client_assertion_type' of 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'.",
		},
		{
			name: "ShouldFailBecauseClientAssertionTypeIsUnknown",
			client: func(ts *httptest.Server) Client {
				return &DefaultJARClient{DefaultClient: &DefaultClient{ID: "foo", ClientSecret: testClientSecretBar}, TokenEndpointAuthMethod: "private_key_jwt"}
			}, form: url.Values{"client_id": []string{"foo"}, "client_assertion_type": []string{"foobar"}},
			r:         new(http.Request),
			expectErr: ErrInvalidRequest,
			err:       "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Unknown client_assertion_type 'foobar'.",
		},
		{
			name: "ShouldPassWithProperRSAAssertionWhenJWKsAreSetWithinTheClientAndClientIdIsNotSetInTheRequest",
			client: func(ts *httptest.Server) Client {
				return &DefaultJARClient{DefaultClient: &DefaultClient{ID: "bar", ClientSecret: testClientSecretBar}, JSONWebKeys: jwksRSA, TokenEndpointAuthMethod: "private_key_jwt"}
			}, form: url.Values{"client_assertion": {mustGenerateRSAAssertion(t, jwt.MapClaims{
				consts.ClaimSubject:        "bar",
				consts.ClaimExpirationTime: time.Now().Add(time.Hour).Unix(),
				consts.ClaimIssuer:         "bar",
				consts.ClaimJWTID:          "12345",
				consts.ClaimAudience:       "token-url",
			}, keyRSA, "kid-foo")}, "client_assertion_type": []string{consts.ClientAssertionTypeJWTBearer}},
			r: new(http.Request),
		},
		{
			name: "ShouldPassWithProperECDSAAssertionWhenJWKsAreSetWithinTheClientAndClientIdIsNotSetInTheRequest",
			client: func(ts *httptest.Server) Client {
				return &DefaultJARClient{DefaultClient: &DefaultClient{ID: "bar", ClientSecret: testClientSecretBar}, JSONWebKeys: jwksECDSA, TokenEndpointAuthMethod: "private_key_jwt", TokenEndpointAuthSigningAlg: "ES256"}
			}, form: url.Values{"client_assertion": {mustGenerateECDSAAssertion(t, jwt.MapClaims{
				consts.ClaimSubject:        "bar",
				consts.ClaimExpirationTime: time.Now().Add(time.Hour).Unix(),
				consts.ClaimIssuer:         "bar",
				consts.ClaimJWTID:          "12345",
				consts.ClaimAudience:       "token-url",
			}, keyECDSA, "kid-foo")}, "client_assertion_type": []string{consts.ClientAssertionTypeJWTBearer}},
			r: new(http.Request),
		},
		{
			name: "ShouldFailBecauseRSAAssertionIsUsedButECDSAAssertionIsRequired",
			client: func(ts *httptest.Server) Client {
				return &DefaultJARClient{DefaultClient: &DefaultClient{ID: "bar", ClientSecret: testClientSecretBar}, JSONWebKeys: jwksECDSA, TokenEndpointAuthMethod: "private_key_jwt", TokenEndpointAuthSigningAlg: "ES256"}
			}, form: url.Values{"client_assertion": {mustGenerateRSAAssertion(t, jwt.MapClaims{
				consts.ClaimSubject:        "bar",
				consts.ClaimExpirationTime: time.Now().Add(time.Hour).Unix(),
				consts.ClaimIssuer:         "bar",
				consts.ClaimJWTID:          "12345",
				consts.ClaimAudience:       "token-url",
			}, keyRSA, "kid-foo")}, "client_assertion_type": []string{consts.ClientAssertionTypeJWTBearer}},
			r:         new(http.Request),
			expectErr: ErrInvalidClient,
			err:       "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). The requested OAuth 2.0 client does not support the 'token_endpoint_auth_signing_alg' value 'RS256'. The registered OAuth 2.0 client with id 'bar' only supports the 'ES256' algorithm.",
		},
		{
			name: "ShouldFailBecauseMalformedAssertionUsed",
			client: func(ts *httptest.Server) Client {
				return &DefaultJARClient{DefaultClient: &DefaultClient{ID: "bar", ClientSecret: testClientSecretBar}, JSONWebKeys: jwksECDSA, TokenEndpointAuthMethod: "private_key_jwt", TokenEndpointAuthSigningAlg: "ES256"}
			}, form: url.Values{"client_assertion": []string{"bad.assertion"}, "client_assertion_type": []string{consts.ClientAssertionTypeJWTBearer}},
			r:         new(http.Request),
			expectErr: ErrInvalidClient,
			err:       "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). Unable to decode the 'client_assertion' value as it is malformed or incomplete. token is malformed: token contains an invalid number of segments",
		},
		{
			name: "ShouldFailBecauseExpired",
			client: func(ts *httptest.Server) Client {
				return &DefaultJARClient{DefaultClient: &DefaultClient{ID: "bar", ClientSecret: testClientSecretBar}, JSONWebKeys: jwksECDSA, TokenEndpointAuthMethod: "private_key_jwt", TokenEndpointAuthSigningAlg: "ES256"}
			}, form: url.Values{"client_assertion": {mustGenerateECDSAAssertion(t, jwt.MapClaims{
				consts.ClaimSubject:        "bar",
				consts.ClaimExpirationTime: time.Now().Add(-time.Hour).Unix(),
				consts.ClaimIssuer:         "bar",
				consts.ClaimJWTID:          "12345",
				consts.ClaimAudience:       "token-url",
			}, keyECDSA, "kid-foo")}, "client_assertion_type": []string{consts.ClientAssertionTypeJWTBearer}},
			r:         new(http.Request),
			expectErr: ErrInvalidClient,
			err:       "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). Unable to verify the integrity of the 'client_assertion' value. It may have been used before it was issued, may have been used before it's allowed to be used, may have been used after it's expired, or otherwise doesn't meet a particular validation constraint. token has invalid claims: token is expired",
		},
		{
			name: "ShouldFailBecauseNotBefore",
			client: func(ts *httptest.Server) Client {
				return &DefaultJARClient{DefaultClient: &DefaultClient{ID: "bar", ClientSecret: testClientSecretBar}, JSONWebKeys: jwksECDSA, TokenEndpointAuthMethod: "private_key_jwt", TokenEndpointAuthSigningAlg: "ES256"}
			}, form: url.Values{"client_assertion": {mustGenerateECDSAAssertion(t, jwt.MapClaims{
				consts.ClaimSubject:        "bar",
				consts.ClaimExpirationTime: time.Now().Add(time.Hour).Unix(),
				consts.ClaimNotBefore:      time.Now().Add(time.Minute).Unix(),
				consts.ClaimIssuer:         "bar",
				consts.ClaimJWTID:          "12345",
				consts.ClaimAudience:       "token-url",
			}, keyECDSA, "kid-foo")}, "client_assertion_type": []string{consts.ClientAssertionTypeJWTBearer}},
			r:         new(http.Request),
			expectErr: ErrInvalidClient,
			err:       "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). Unable to verify the integrity of the 'client_assertion' value. It may have been used before it was issued, may have been used before it's allowed to be used, may have been used after it's expired, or otherwise doesn't meet a particular validation constraint. token has invalid claims: token is not valid yet",
		},
		{
			name: "ShouldFailBecauseIssuedInFuture",
			client: func(ts *httptest.Server) Client {
				return &DefaultJARClient{DefaultClient: &DefaultClient{ID: "bar", ClientSecret: testClientSecretBar}, JSONWebKeys: jwksECDSA, TokenEndpointAuthMethod: "private_key_jwt", TokenEndpointAuthSigningAlg: "ES256"}
			}, form: url.Values{"client_assertion": {mustGenerateECDSAAssertion(t, jwt.MapClaims{
				consts.ClaimSubject:        "bar",
				consts.ClaimExpirationTime: time.Now().Add(time.Hour).Unix(),
				consts.ClaimIssuedAt:       time.Now().Add(time.Minute).Unix(),
				consts.ClaimIssuer:         "bar",
				consts.ClaimJWTID:          "12345",
				consts.ClaimAudience:       "token-url",
			}, keyECDSA, "kid-foo")}, "client_assertion_type": []string{consts.ClientAssertionTypeJWTBearer}},
			r:         new(http.Request),
			expectErr: ErrInvalidClient,
			err:       "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). Unable to verify the integrity of the 'client_assertion' value. It may have been used before it was issued, may have been used before it's allowed to be used, may have been used after it's expired, or otherwise doesn't meet a particular validation constraint. token has invalid claims: token used before issued",
		},
		{
			name: "ShouldFailBecauseNoKeys",
			client: func(ts *httptest.Server) Client {
				return &DefaultJARClient{DefaultClient: &DefaultClient{ID: "bar", ClientSecret: testClientSecretBar}, JSONWebKeys: nil, TokenEndpointAuthMethod: "private_key_jwt", TokenEndpointAuthSigningAlg: "ES256"}
			}, form: url.Values{"client_assertion": {mustGenerateECDSAAssertion(t, jwt.MapClaims{
				consts.ClaimSubject:        "bar",
				consts.ClaimExpirationTime: time.Now().Add(time.Hour).Unix(),
				consts.ClaimIssuer:         "bar",
				consts.ClaimJWTID:          "12345",
				consts.ClaimAudience:       "token-url",
			}, keyECDSA, "kid-foo")}, "client_assertion_type": []string{consts.ClientAssertionTypeJWTBearer}},
			r:         new(http.Request),
			expectErr: ErrInvalidClient,
			err:       "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). The OAuth 2.0 Client has no JSON Web Keys set registered, but they are needed to complete the request.",
		},
		{
			name: "ShouldFailBecauseNotBefore",
			client: func(ts *httptest.Server) Client {
				return &DefaultJARClient{DefaultClient: &DefaultClient{ID: "bar", ClientSecret: testClientSecretBar}, JSONWebKeys: jwksECDSA, TokenEndpointAuthMethod: "private_key_jwt", TokenEndpointAuthSigningAlg: "ES256"}
			}, form: url.Values{"client_assertion": {mustGenerateECDSAAssertion(t, jwt.MapClaims{
				consts.ClaimSubject:        "bar",
				consts.ClaimExpirationTime: time.Now().Add(time.Hour).Unix(),
				consts.ClaimNotBefore:      time.Now().Add(time.Minute).Unix(),
				consts.ClaimIssuer:         "bar",
				consts.ClaimJWTID:          "12345",
				consts.ClaimAudience:       "token-url",
			}, keyECDSA, "kid-foo")}, "client_assertion_type": []string{consts.ClientAssertionTypeJWTBearer}},
			r:         new(http.Request),
			expectErr: ErrInvalidClient,
			err:       "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). Unable to verify the integrity of the 'client_assertion' value. It may have been used before it was issued, may have been used before it's allowed to be used, may have been used after it's expired, or otherwise doesn't meet a particular validation constraint. token has invalid claims: token is not valid yet",
		},
		{
			name: "ShouldFailBecauseTokenAuthMethodIsNotPrivateKeyJwtButClientSecretJwt",
			client: func(ts *httptest.Server) Client {
				return &DefaultJARClient{DefaultClient: &DefaultClient{ID: "bar", ClientSecret: testClientSecretBar}, JSONWebKeys: jwksRSA, TokenEndpointAuthMethod: "client_secret_jwt"}
			}, form: url.Values{"client_assertion": {mustGenerateRSAAssertion(t, jwt.MapClaims{
				consts.ClaimSubject:        "bar",
				consts.ClaimExpirationTime: time.Now().Add(time.Hour).Unix(),
				consts.ClaimIssuer:         "bar",
				consts.ClaimJWTID:          "12345",
				consts.ClaimAudience:       "token-url",
			}, keyRSA, "kid-foo")}, "client_assertion_type": []string{consts.ClientAssertionTypeJWTBearer}},
			r:         new(http.Request),
			expectErr: ErrInvalidClient,
			err:       "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). The requested OAuth 2.0 client does not support the 'token_endpoint_auth_signing_alg' value 'RS256'.",
		},
		{
			name: "ShouldFailBecauseTokenAuthMethodIsNotPrivateKeyJwtButNone",
			client: func(ts *httptest.Server) Client {
				return &DefaultJARClient{DefaultClient: &DefaultClient{ID: "bar", ClientSecret: testClientSecretBar}, JSONWebKeys: jwksRSA, TokenEndpointAuthMethod: "none"}
			}, form: url.Values{"client_assertion": {mustGenerateRSAAssertion(t, jwt.MapClaims{
				consts.ClaimSubject:        "bar",
				consts.ClaimExpirationTime: time.Now().Add(time.Hour).Unix(),
				consts.ClaimIssuer:         "bar",
				consts.ClaimJWTID:          "12345",
				consts.ClaimAudience:       "token-url",
			}, keyRSA, "kid-foo")}, "client_assertion_type": []string{consts.ClientAssertionTypeJWTBearer}},
			r:         new(http.Request),
			expectErr: ErrInvalidClient,
			err:       "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). This requested OAuth 2.0 client does not support client authentication, however 'client_assertion' was provided in the request.",
		},
		{
			name: "ShouldFailBecauseTokenAuthMethodIsNotPrivateKeyJwtButClientSecretPost",
			client: func(ts *httptest.Server) Client {
				return &DefaultJARClient{DefaultClient: &DefaultClient{ID: "bar", ClientSecret: testClientSecretBar}, JSONWebKeys: jwksRSA, TokenEndpointAuthMethod: "client_secret_post"}
			}, form: url.Values{"client_assertion": {mustGenerateRSAAssertion(t, jwt.MapClaims{
				consts.ClaimSubject:        "bar",
				consts.ClaimExpirationTime: time.Now().Add(time.Hour).Unix(),
				consts.ClaimIssuer:         "bar",
				consts.ClaimJWTID:          "12345",
				consts.ClaimAudience:       "token-url",
			}, keyRSA, "kid-foo")}, "client_assertion_type": []string{consts.ClientAssertionTypeJWTBearer}},
			r:         new(http.Request),
			expectErr: ErrInvalidClient,
			err:       "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). This requested OAuth 2.0 client only supports client authentication method 'client_secret_post', however 'client_assertion' was provided in the request.",
		},
		{
			name: "ShouldFailBecauseTokenAuthMethodIsNotPrivateKeyJwtButClientSecretBasic",
			client: func(ts *httptest.Server) Client {
				return &DefaultJARClient{DefaultClient: &DefaultClient{ID: "bar", ClientSecret: testClientSecretBar}, JSONWebKeys: jwksRSA, TokenEndpointAuthMethod: "client_secret_basic"}
			}, form: url.Values{"client_assertion": {mustGenerateRSAAssertion(t, jwt.MapClaims{
				consts.ClaimSubject:        "bar",
				consts.ClaimExpirationTime: time.Now().Add(time.Hour).Unix(),
				consts.ClaimIssuer:         "bar",
				consts.ClaimJWTID:          "12345",
				consts.ClaimAudience:       "token-url",
			}, keyRSA, "kid-foo")}, "client_assertion_type": []string{consts.ClientAssertionTypeJWTBearer}},
			r:         new(http.Request),
			expectErr: ErrInvalidClient,
			err:       "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). This requested OAuth 2.0 client only supports client authentication method 'client_secret_basic', however 'client_assertion' was provided in the request.",
		},
		{
			name: "ShouldFailBecauseTokenAuthMethodIsNotPrivateKeyJwtButFoobar",
			client: func(ts *httptest.Server) Client {
				return &DefaultJARClient{DefaultClient: &DefaultClient{ID: "bar", ClientSecret: testClientSecretBar}, JSONWebKeys: jwksRSA, TokenEndpointAuthMethod: "foobar"}
			}, form: url.Values{"client_assertion": {mustGenerateRSAAssertion(t, jwt.MapClaims{
				consts.ClaimSubject:        "bar",
				consts.ClaimExpirationTime: time.Now().Add(time.Hour).Unix(),
				consts.ClaimIssuer:         "bar",
				consts.ClaimJWTID:          "12345",
				consts.ClaimAudience:       "token-url",
			}, keyRSA, "kid-foo")}, "client_assertion_type": []string{consts.ClientAssertionTypeJWTBearer}},
			r:         new(http.Request),
			expectErr: ErrInvalidClient,
		},
		{
			name: "ShouldPassWithProperAssertionWhenJWKsAreSetWithinTheClientAndClientIdIsNotSetInTheRequest (aud is array)",
			client: func(ts *httptest.Server) Client {
				return &DefaultJARClient{DefaultClient: &DefaultClient{ID: "bar", ClientSecret: testClientSecretBar}, JSONWebKeys: jwksRSA, TokenEndpointAuthMethod: "private_key_jwt"}
			}, form: url.Values{"client_assertion": {mustGenerateRSAAssertion(t, jwt.MapClaims{
				consts.ClaimSubject:        "bar",
				consts.ClaimExpirationTime: time.Now().Add(time.Hour).Unix(),
				consts.ClaimIssuer:         "bar",
				consts.ClaimJWTID:          "12345",
				consts.ClaimAudience:       []string{"token-url-2", "token-url"},
			}, keyRSA, "kid-foo")}, "client_assertion_type": []string{consts.ClientAssertionTypeJWTBearer}},
			r: new(http.Request),
		},
		{
			name: "ShouldFailBecauseAudienceDoesNotMatchTokenURL",
			client: func(ts *httptest.Server) Client {
				return &DefaultJARClient{DefaultClient: &DefaultClient{ID: "bar", ClientSecret: testClientSecretBar}, JSONWebKeys: jwksRSA, TokenEndpointAuthMethod: "private_key_jwt"}
			}, form: url.Values{"client_assertion": {mustGenerateRSAAssertion(t, jwt.MapClaims{
				consts.ClaimSubject:        "bar",
				consts.ClaimExpirationTime: time.Now().Add(time.Hour).Unix(),
				consts.ClaimIssuer:         "bar",
				consts.ClaimJWTID:          "12345",
				consts.ClaimAudience:       []string{"token-url-1", "token-url-2"},
			}, keyRSA, "kid-foo")}, "client_assertion_type": []string{consts.ClientAssertionTypeJWTBearer}},
			r:         new(http.Request),
			expectErr: ErrInvalidClient,
			err:       "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). Unable to decode 'client_assertion' value for an unknown reason. token has invalid claims: token has invalid audience",
		},
		{
			name: "ShouldPassWithProperAssertionWhenJWKsAreSetWithinTheClient",
			client: func(ts *httptest.Server) Client {
				return &DefaultJARClient{DefaultClient: &DefaultClient{ID: "bar", ClientSecret: testClientSecretBar}, JSONWebKeys: jwksRSA, TokenEndpointAuthMethod: "private_key_jwt"}
			}, form: url.Values{"client_id": []string{"bar"}, "client_assertion": {mustGenerateRSAAssertion(t, jwt.MapClaims{
				consts.ClaimSubject:        "bar",
				consts.ClaimExpirationTime: time.Now().Add(time.Hour).Unix(),
				consts.ClaimIssuer:         "bar",
				consts.ClaimJWTID:          "12345",
				consts.ClaimAudience:       "token-url",
			}, keyRSA, "kid-foo")}, "client_assertion_type": []string{consts.ClientAssertionTypeJWTBearer}},
			r: new(http.Request),
		},
		{
			name: "ShouldFailBecauseJWTAlgorithmIsHS256",
			client: func(ts *httptest.Server) Client {
				return &DefaultJARClient{DefaultClient: &DefaultClient{ID: "bar", ClientSecret: testClientSecretBar}, JSONWebKeys: jwksRSA, TokenEndpointAuthMethod: "private_key_jwt"}
			}, form: url.Values{"client_id": []string{"bar"}, "client_assertion": {mustGenerateHSAssertion(t, jwt.MapClaims{
				consts.ClaimSubject:        "bar",
				consts.ClaimExpirationTime: time.Now().Add(time.Hour).Unix(),
				consts.ClaimIssuer:         "bar",
				consts.ClaimJWTID:          "12345",
				consts.ClaimAudience:       "token-url",
			}, keyRSA, "kid-foo")}, "client_assertion_type": []string{consts.ClientAssertionTypeJWTBearer}},
			r:         new(http.Request),
			expectErr: ErrInvalidClient,
		},
		{
			name: "ShouldFailBecauseJWTAlgorithmIsNone",
			client: func(ts *httptest.Server) Client {
				return &DefaultJARClient{DefaultClient: &DefaultClient{ID: "bar", ClientSecret: testClientSecretBar}, JSONWebKeys: jwksRSA, TokenEndpointAuthMethod: "private_key_jwt"}
			}, form: url.Values{"client_id": []string{"bar"}, "client_assertion": {mustGenerateNoneAssertion(t, jwt.MapClaims{
				consts.ClaimSubject:        "bar",
				consts.ClaimExpirationTime: time.Now().Add(time.Hour).Unix(),
				consts.ClaimIssuer:         "bar",
				consts.ClaimJWTID:          "12345",
				consts.ClaimAudience:       "token-url",
			}, keyRSA, "kid-foo")}, "client_assertion_type": []string{consts.ClientAssertionTypeJWTBearer}},
			r:         new(http.Request),
			expectErr: ErrInvalidClient,
			err:       "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). The requested OAuth 2.0 client does not support the 'token_endpoint_auth_signing_alg' value 'none'. The registered OAuth 2.0 client with id 'bar' only supports the 'RS256' algorithm.",
		},
		{
			name: "ShouldPassWithProperAssertionWhenJWKsURIIsSet",
			client: func(ts *httptest.Server) Client {
				return &DefaultJARClient{DefaultClient: &DefaultClient{ID: "bar", ClientSecret: testClientSecretBar}, JSONWebKeysURI: ts.URL, TokenEndpointAuthMethod: "private_key_jwt"}
			}, form: url.Values{"client_id": []string{"bar"}, "client_assertion": {mustGenerateRSAAssertion(t, jwt.MapClaims{
				consts.ClaimSubject:        "bar",
				consts.ClaimExpirationTime: time.Now().Add(time.Hour).Unix(),
				consts.ClaimIssuer:         "bar",
				consts.ClaimJWTID:          "12345",
				consts.ClaimAudience:       "token-url",
			}, keyRSA, "kid-foo")}, "client_assertion_type": []string{consts.ClientAssertionTypeJWTBearer}},
			r: new(http.Request),
		},
		{
			name: "ShouldFailBecauseClientAssertionSubDoesNotMatchClient",
			client: func(ts *httptest.Server) Client {
				return &DefaultJARClient{DefaultClient: &DefaultClient{ID: "bar", ClientSecret: testClientSecretBar}, JSONWebKeys: jwksRSA, TokenEndpointAuthMethod: "private_key_jwt"}
			}, form: url.Values{"client_id": []string{"bar"}, "client_assertion": {mustGenerateRSAAssertion(t, jwt.MapClaims{
				consts.ClaimSubject:        "not-bar",
				consts.ClaimExpirationTime: time.Now().Add(time.Hour).Unix(),
				consts.ClaimIssuer:         "bar",
				consts.ClaimJWTID:          "12345",
				consts.ClaimAudience:       "token-url",
			}, keyRSA, "kid-foo")}, "client_assertion_type": []string{consts.ClientAssertionTypeJWTBearer}},
			r:         new(http.Request),
			expectErr: ErrInvalidClient,
			err:       "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). The supplied 'client_id' did not match the 'sub' claim of the 'client_assertion'.",
		},
		{
			name: "ShouldFailBecauseClientAssertionIssDoesNotMatchClient",
			client: func(ts *httptest.Server) Client {
				return &DefaultJARClient{DefaultClient: &DefaultClient{ID: "bar", ClientSecret: testClientSecretBar}, JSONWebKeys: jwksRSA, TokenEndpointAuthMethod: "private_key_jwt"}
			}, form: url.Values{"client_id": []string{"bar"}, "client_assertion": {mustGenerateRSAAssertion(t, jwt.MapClaims{
				consts.ClaimSubject:        "bar",
				consts.ClaimExpirationTime: time.Now().Add(time.Hour).Unix(),
				consts.ClaimIssuer:         "not-bar",
				consts.ClaimJWTID:          "12345",
				consts.ClaimAudience:       "token-url",
			}, keyRSA, "kid-foo")}, "client_assertion_type": []string{consts.ClientAssertionTypeJWTBearer}},
			r:         new(http.Request),
			expectErr: ErrInvalidClient,
			err:       "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). Claim 'iss' from 'client_assertion' must match the 'client_id' of the OAuth 2.0 Client.",
		},
		{
			name: "ShouldFailBecauseClientAssertionJtiIsNotSet",
			client: func(ts *httptest.Server) Client {
				return &DefaultJARClient{DefaultClient: &DefaultClient{ID: "bar", ClientSecret: testClientSecretBar}, JSONWebKeys: jwksRSA, TokenEndpointAuthMethod: "private_key_jwt"}
			}, form: url.Values{"client_id": []string{"bar"}, "client_assertion": {mustGenerateRSAAssertion(t, jwt.MapClaims{
				consts.ClaimSubject:        "bar",
				consts.ClaimExpirationTime: time.Now().Add(time.Hour).Unix(),
				consts.ClaimIssuer:         "bar",
				consts.ClaimAudience:       "token-url",
			}, keyRSA, "kid-foo")}, "client_assertion_type": []string{consts.ClientAssertionTypeJWTBearer}},
			r:         new(http.Request),
			expectErr: ErrInvalidClient,
			err:       "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). Claim 'jti' from 'client_assertion' must be set but is not.",
		},
		{
			name: "ShouldFailBecauseClientAssertionAudIsNotSet",
			client: func(ts *httptest.Server) Client {
				return &DefaultJARClient{DefaultClient: &DefaultClient{ID: "bar", ClientSecret: testClientSecretBar}, JSONWebKeys: jwksRSA, TokenEndpointAuthMethod: "private_key_jwt"}
			},
			form: url.Values{
				"client_id": []string{"bar"},
				"client_assertion": {
					mustGenerateRSAAssertion(t, jwt.MapClaims{
						consts.ClaimSubject:        "bar",
						consts.ClaimExpirationTime: time.Now().Add(time.Hour).Unix(),
						consts.ClaimIssuer:         "bar",
						consts.ClaimJWTID:          "12345",
						consts.ClaimAudience:       "not-token-url",
					}, keyRSA, "kid-foo")}, "client_assertion_type": []string{consts.ClientAssertionTypeJWTBearer}},
			r:         new(http.Request),
			expectErr: ErrInvalidClient,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider := &Fosite{
				Store: storage.NewMemoryStore(),
				Config: &Config{
					JWKSFetcherStrategy: NewDefaultJWKSFetcherStrategy(),
					TokenURL:            "token-url",
					HTTPClient:          retryablehttp.NewClient(),
				},
			}

			var h http.HandlerFunc = func(w http.ResponseWriter, r *http.Request) {
				require.NoError(t, json.NewEncoder(w).Encode(jwksRSA))
			}

			ts := httptest.NewServer(h)

			defer ts.Close()

			store := storage.NewMemoryStore()

			client := tc.client(ts)

			store.Clients[client.GetID()] = client
			provider.Store = store

			c, _, err := provider.AuthenticateClient(context.Background(), tc.r, tc.form)

			if len(tc.err) != 0 {
				require.EqualError(t, ErrorToDebugRFC6749Error(err), tc.err)
			}

			if len(tc.err) == 0 && tc.expectErr == nil {
				require.NoError(t, ErrorToDebugRFC6749Error(err))
				assert.EqualValues(t, client, c)
			} else {
				if len(tc.err) != 0 {
					assert.EqualError(t, ErrorToDebugRFC6749Error(err), tc.err)
				}

				if tc.expectErr != nil {
					assert.EqualError(t, err, tc.expectErr.Error())
				}
			}
		})
	}
}

func TestAuthenticateClientTwice(t *testing.T) {
	key := gen.MustRSAKey()
	client := &DefaultJARClient{
		DefaultClient: &DefaultClient{
			ID:           "bar",
			ClientSecret: testClientSecretFoo,
		},
		JSONWebKeys: &jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{
				{
					KeyID: "kid-foo",
					Use:   consts.JSONWebTokenUseSignature,
					Key:   &key.PublicKey,
				},
			},
		},
		TokenEndpointAuthMethod: consts.ClientAuthMethodPrivateKeyJWT,
	}
	store := storage.NewMemoryStore()
	store.Clients[client.ID] = client

	provider := &Fosite{
		Store: store,
		Config: &Config{
			JWKSFetcherStrategy: NewDefaultJWKSFetcherStrategy(),
			TokenURL:            "token-url",
		},
	}

	formValues := url.Values{"client_id": []string{"bar"}, "client_assertion": {mustGenerateRSAAssertion(t, jwt.MapClaims{
		consts.ClaimSubject:        "bar",
		consts.ClaimExpirationTime: time.Now().Add(time.Hour).Unix(),
		consts.ClaimIssuer:         "bar",
		consts.ClaimJWTID:          "12345",
		consts.ClaimAudience:       "token-url",
	}, key, "kid-foo")}, consts.FormParameterClientAssertionType: []string{consts.ClientAssertionTypeJWTBearer}}

	c, _, err := provider.AuthenticateClient(context.TODO(), new(http.Request), formValues)
	require.NoError(t, err, "%#v", err)
	assert.Equal(t, client, c)

	// replay the request and expect it to fail
	c, _, err = provider.AuthenticateClient(context.TODO(), new(http.Request), formValues)
	require.Error(t, err)
	assert.EqualError(t, err, ErrJTIKnown.Error())
	assert.Nil(t, c)
}

//nolint:unparam
func mustGenerateRSAAssertion(t *testing.T, claims jwt.MapClaims, key *rsa.PrivateKey, kid string) string {
	token := jwt.NewWithClaims(jose.RS256, claims)
	token.Header["kid"] = kid
	tokenString, err := token.CompactSigned(key)
	require.NoError(t, err)
	return tokenString
}

func mustGenerateECDSAAssertion(t *testing.T, claims jwt.MapClaims, key *ecdsa.PrivateKey, kid string) string {
	token := jwt.NewWithClaims(jose.ES256, claims)
	token.Header["kid"] = kid
	tokenString, err := token.CompactSigned(key)
	require.NoError(t, err)
	return tokenString
}

//nolint:unparam
func mustGenerateHSAssertion(t *testing.T, claims jwt.MapClaims, key *rsa.PrivateKey, kid string) string {
	token := jwt.NewWithClaims(jose.HS256, claims)
	tokenString, err := token.CompactSigned([]byte("aaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbcccccccccccccccccccccddddddddddddddddddddddd"))
	require.NoError(t, err)
	return tokenString
}

//nolint:unparam
func mustGenerateNoneAssertion(t *testing.T, claims jwt.MapClaims, key *rsa.PrivateKey, kid string) string {
	token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	tokenString, err := token.CompactSigned(jwt.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)
	return tokenString
}

// returns an http basic authorization header, encoded using application/x-www-form-urlencoded
func clientBasicAuthHeader(clientID, clientSecret string) http.Header {
	creds := url.QueryEscape(clientID) + ":" + url.QueryEscape(clientSecret)
	return http.Header{
		consts.HeaderAuthorization: {
			prefixSchemeBasic + base64.StdEncoding.EncodeToString([]byte(creds)),
		},
	}
}

type TestClientAuthenticationPolicyClient struct {
	*DefaultJARClient

	AllowMultipleAuthenticationMethods bool
}

func (c *TestClientAuthenticationPolicyClient) GetAllowMultipleAuthenticationMethods() bool {
	return c.AllowMultipleAuthenticationMethods
}

func mustNewBCryptClientSecretPlain(rawSecret string) *BCryptClientSecret {
	if secret, err := NewBCryptClientSecretPlain(rawSecret, 4); err != nil {
		panic(err)
	} else {
		return secret
	}
}

var (
	testClientSecretFoo     = mustNewBCryptClientSecretPlain("foo")
	testClientSecretBar     = mustNewBCryptClientSecretPlain("bar")
	testClientSecret1234    = mustNewBCryptClientSecretPlain("1234")
	testClientSecretComplex = mustNewBCryptClientSecretPlain("foo %66%6F%6F@$<§!✓") // "foo %66%6F%6F@$<§!✓"
)
