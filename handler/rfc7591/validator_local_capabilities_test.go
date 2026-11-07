// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7591

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestLocalValidatorCapabilities(t *testing.T) {
	testCases := []struct {
		name     string
		setup    func(config *oauth2.Config)
		metadata func(metadata *oauth2.ClientRegistrationMetadata)
		err      string
	}{
		{
			name: "ShouldRejectGrantTypeWithoutHandler",
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.GrantTypes = []string{consts.GrantTypeResourceOwnerPasswordCredentials}
				metadata.ResponseTypes = nil
			},
			err: "The 'grant_types' value 'password' is not supported by this authorization server.",
		},
		{
			name: "ShouldRejectGrantTypeOutsideRegistrationPolicy",
			setup: func(config *oauth2.Config) {
				config.TokenEndpointHandlers.Append(&hoauth2.ClientCredentialsGrantHandler{})
				config.RFC7591ClientRegistrationGrantTypes = []string{consts.GrantTypeAuthorizationCode}
			},
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.GrantTypes = []string{consts.GrantTypeClientCredentials}
				metadata.ResponseTypes = nil
			},
			err: "The 'grant_types' value 'client_credentials' is not permitted for registration.",
		},
		{
			name: "ShouldRejectOmittedGrantTypesWhenAuthorizationCodeUnsupported",
			setup: func(config *oauth2.Config) {
				config.AuthorizeEndpointHandlers = nil
				config.TokenEndpointHandlers = nil
				config.TokenEndpointHandlers.Append(&hoauth2.ClientCredentialsGrantHandler{})
			},
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.GrantTypes = nil
				metadata.ResponseTypes = nil
			},
			err: "The 'grant_types' value 'authorization_code', which applies by default when 'grant_types' is omitted, is not supported by this authorization server.",
		},
		{
			name: "ShouldRejectOmittedGrantTypesOutsideRegistrationPolicy",
			setup: func(config *oauth2.Config) {
				config.TokenEndpointHandlers.Append(&hoauth2.ClientCredentialsGrantHandler{})
				config.RFC7591ClientRegistrationGrantTypes = []string{consts.GrantTypeClientCredentials}
			},
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.GrantTypes = nil
				metadata.ResponseTypes = nil
			},
			err: "The 'grant_types' value 'authorization_code', which applies by default when 'grant_types' is omitted, is not permitted for registration.",
		},
		{
			name: "ShouldRejectOmittedResponseTypesWithAuthorizationCodeWhenCodeUnsupported",
			setup: func(config *oauth2.Config) {
				config.AuthorizeEndpointHandlers = nil
			},
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.GrantTypes = []string{consts.GrantTypeAuthorizationCode}
				metadata.ResponseTypes = nil
			},
			err: "The 'response_types' value 'code', which applies by default when 'response_types' is omitted, is not supported by this authorization server.",
		},
		{
			name: "ShouldAcceptOmittedResponseTypesWithGrantTypesNotUsingAuthorizationEndpoint",
			setup: func(config *oauth2.Config) {
				config.AuthorizeEndpointHandlers = nil
				config.TokenEndpointHandlers = nil
				config.TokenEndpointHandlers.Append(&hoauth2.ClientCredentialsGrantHandler{})
			},
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.GrantTypes = []string{consts.GrantTypeClientCredentials}
				metadata.ResponseTypes = nil
			},
		},
		{
			name: "ShouldAcceptResponseTypeInAnyOrder",
			setup: func(config *oauth2.Config) {
				config.AuthorizeEndpointHandlers.Append(&openid.OpenIDConnectHybridHandler{})
			},
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.GrantTypes = []string{consts.GrantTypeAuthorizationCode, consts.GrantTypeImplicit}
				metadata.ResponseTypes = []string{"id_token code"}
			},
		},
		{
			name: "ShouldRejectResponseTypeWithoutHybridHandler",
			setup: func(config *oauth2.Config) {
				config.AuthorizeEndpointHandlers.Append(&hoauth2.AuthorizeImplicitGrantTypeHandler{})
			},
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.GrantTypes = []string{consts.GrantTypeAuthorizationCode, consts.GrantTypeImplicit}
				metadata.ResponseTypes = []string{"code token"}
			},
			err: "The 'response_types' value 'code token' is not supported by this authorization server.",
		},
		{
			name: "ShouldRejectResponseModeNotAdvertised",
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.ResponseModes = []string{"query.jwt"}
			},
			err: "The 'response_modes' value 'query.jwt' is not supported by this authorization server.",
		},
		{
			name: "ShouldRejectIDTokenAlgWithECOnlyKeys",
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.IDTokenSignedResponseAlg = "RS256"
			},
			err: "The 'id_token_signed_response_alg' value 'RS256' is not supported by this authorization server.",
		},
		{
			name: "ShouldAcceptIDTokenAlgClientSecret",
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.IDTokenSignedResponseAlg = "HS256"
			},
		},
		{
			name: "ShouldAcceptIDTokenAlgFromKeys",
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.IDTokenSignedResponseAlg = "ES256"
			},
		},
		{
			name: "ShouldRejectIDTokenAlgWithoutKeys",
			setup: func(config *oauth2.Config) {
				config.JWTStrategy = &jwt.DefaultStrategy{Config: config}
			},
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.IDTokenSignedResponseAlg = "HS256"
			},
			err: "The 'id_token_signed_response_alg' value 'HS256' is not supported by this authorization server.",
		},
		{
			name: "ShouldAcceptUserinfoAlgNone",
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.UserinfoSignedResponseAlg = consts.JSONWebTokenAlgNone
			},
		},
		{
			name: "ShouldAcceptUserinfoClientSecretAlgWithoutKeys",
			setup: func(config *oauth2.Config) {
				config.JWTStrategy = &jwt.DefaultStrategy{Config: config}
			},
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.UserinfoSignedResponseAlg = "HS256"
			},
		},
		{
			name: "ShouldRejectUserinfoAlgWithoutKeys",
			setup: func(config *oauth2.Config) {
				config.JWTStrategy = &jwt.DefaultStrategy{Config: config}
			},
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.UserinfoSignedResponseAlg = "ES256"
			},
			err: "The 'userinfo_signed_response_alg' value 'ES256' is not supported by this authorization server.",
		},
		{
			name: "ShouldRejectAuthorizationAlgWithoutJARM",
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.AuthorizationSignedResponseAlg = "HS256"
			},
			err: "The 'authorization_signed_response_alg' value 'HS256' is not supported by this authorization server.",
		},
		{
			name: "ShouldRejectIntrospectionAlgNoneWithoutStrategy",
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.IntrospectionSignedResponseAlg = consts.JSONWebTokenAlgNone
			},
			err: "The 'introspection_signed_response_alg' value must not be 'none'.",
		},
		{
			name: "ShouldRejectIntrospectionAlgWithoutStrategy",
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.IntrospectionSignedResponseAlg = "ES256"
			},
			err: "The 'introspection_signed_response_alg' value 'ES256' is not supported by this authorization server.",
		},
		{
			name: "ShouldRejectAccessTokenAlgWithECOnlyKeys",
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.AccessTokenSignedResponseAlg = "RS256"
			},
			err: "The 'access_token_signed_response_alg' value 'RS256' is not supported by this authorization server.",
		},
		{
			name: "ShouldRejectSubjectTypeNotAdvertised",
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.SubjectType = consts.SubjectTypePairwise
			},
			err: "The 'subject_type' value 'pairwise' is not supported by this authorization server.",
		},
		{
			name: "ShouldAcceptSubjectTypeAdvertised",
			setup: func(config *oauth2.Config) {
				config.SubjectTypesSupported = []string{consts.SubjectTypePublic, consts.SubjectTypePairwise}
			},
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.SubjectType = consts.SubjectTypePairwise
			},
		},
		{
			name: "ShouldRejectTokenEndpointAuthMethodNotAdvertised",
			setup: func(config *oauth2.Config) {
				config.TokenEndpointAuthMethods = []string{consts.ClientAuthMethodPrivateKeyJWT}
			},
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.TokenEndpointAuthMethod = consts.ClientAuthMethodClientSecretBasic
			},
			err: "The 'token_endpoint_auth_method' value 'client_secret_basic' is not supported by this authorization server.",
		},
		{
			name: "ShouldRejectOmittedTokenEndpointAuthMethodWhenDefaultNotAdvertised",
			setup: func(config *oauth2.Config) {
				config.TokenEndpointAuthMethods = []string{consts.ClientAuthMethodClientSecretPost}
			},
			err: "The 'token_endpoint_auth_method' value 'client_secret_basic', which applies by default when 'token_endpoint_auth_method' is omitted, is not supported by this authorization server.",
		},
		{
			name: "ShouldRejectOmittedRevocationEndpointAuthMethodWhenTokenMethodNotConfigured",
			setup: func(config *oauth2.Config) {
				config.RevocationEndpointAuthMethods = []string{consts.ClientAuthMethodClientSecretPost}
			},
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.TokenEndpointAuthMethod = consts.ClientAuthMethodClientSecretBasic
			},
			err: "The 'revocation_endpoint_auth_method' value 'client_secret_basic', which applies by default when 'revocation_endpoint_auth_method' is omitted, is not supported by this authorization server.",
		},
		{
			name: "ShouldRejectOmittedIntrospectionEndpointAuthMethodWhenTokenMethodNotConfigured",
			setup: func(config *oauth2.Config) {
				config.IntrospectionEndpointAuthMethods = []string{consts.ClientAuthMethodClientSecretPost}
			},
			err: "The 'introspection_endpoint_auth_method' value 'client_secret_basic', which applies by default when 'introspection_endpoint_auth_method' is omitted, is not supported by this authorization server.",
		},
		{
			name: "ShouldAcceptOmittedIntrospectionEndpointAuthMethodWithOnlyAccessTokenTypes",
			setup: func(config *oauth2.Config) {
				config.IntrospectionEndpointAuthMethods = []string{consts.AuthSchemeBearer, consts.AuthSchemeDPoP}
			},
		},
		{
			name: "ShouldRejectOmittedIntrospectionEndpointAuthMethodNotInAMixedList",
			setup: func(config *oauth2.Config) {
				config.IntrospectionEndpointAuthMethods = []string{consts.AuthSchemeBearer, consts.ClientAuthMethodPrivateKeyJWT}
			},
			err: "The 'introspection_endpoint_auth_method' value 'client_secret_basic', which applies by default when 'introspection_endpoint_auth_method' is omitted, is not supported by this authorization server.",
		},
		{
			name: "ShouldAcceptIntrospectionEndpointAuthMethodInAMixedList",
			setup: func(config *oauth2.Config) {
				config.IntrospectionEndpointAuthMethods = []string{consts.AuthSchemeBearer, consts.ClientAuthMethodPrivateKeyJWT}
			},
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.IntrospectionEndpointAuthMethod = consts.ClientAuthMethodPrivateKeyJWT
			},
		},
		{
			name: "ShouldRejectAnAccessTokenTypeAsTheIntrospectionEndpointAuthMethod",
			setup: func(config *oauth2.Config) {
				config.IntrospectionEndpointAuthMethods = []string{consts.AuthSchemeBearer, consts.ClientAuthMethodPrivateKeyJWT}
			},
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.IntrospectionEndpointAuthMethod = consts.AuthSchemeBearer
			},
			err: "The 'introspection_endpoint_auth_method' value 'Bearer' is not supported by this authorization server.",
		},
		{
			name: "ShouldRejectAnAccessTokenTypeAsTheIntrospectionEndpointAuthMethodWithOnlyAccessTokenTypes",
			setup: func(config *oauth2.Config) {
				config.IntrospectionEndpointAuthMethods = []string{consts.AuthSchemeBearer}
			},
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.IntrospectionEndpointAuthMethod = consts.AuthSchemeBearer
			},
			err: "The 'introspection_endpoint_auth_method' value 'Bearer' is not supported by this authorization server.",
		},
		{
			name: "ShouldNotRestrictRevocationEndpointAuthMethodByTokenEndpointList",
			setup: func(config *oauth2.Config) {
				config.TokenEndpointAuthMethods = []string{consts.ClientAuthMethodClientSecretPost}
			},
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.TokenEndpointAuthMethod = consts.ClientAuthMethodClientSecretPost
				metadata.RevocationEndpointAuthMethod = consts.ClientAuthMethodClientSecretBasic
				metadata.IntrospectionEndpointAuthMethod = consts.ClientAuthMethodClientSecretBasic
			},
		},
		{
			name: "ShouldRejectAConfiguredTokenEndpointAuthMethodUnsupportedByStrategy",
			setup: func(config *oauth2.Config) {
				config.TokenEndpointAuthMethods = []string{consts.ClientAuthMethodClientSecretBasic, "private_key_jw"}
			},
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.TokenEndpointAuthMethod = "private_key_jw"
			},
			err: "The 'token_endpoint_auth_method' value 'private_key_jw' is not supported by this authorization server.",
		},
		{
			name: "ShouldRejectRevocationEndpointAuthMethodUnsupportedByStrategy",
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.RevocationEndpointAuthMethod = "client_secret_unknown"
			},
			err: "The 'revocation_endpoint_auth_method' value 'client_secret_unknown' is not supported by this authorization server.",
		},
		{
			name: "ShouldRejectIntrospectionEndpointAuthMethodNotConfigured",
			setup: func(config *oauth2.Config) {
				config.IntrospectionEndpointAuthMethods = []string{consts.ClientAuthMethodPrivateKeyJWT}
			},
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.IntrospectionEndpointAuthMethod = consts.ClientAuthMethodClientSecretPost
			},
			err: "The 'introspection_endpoint_auth_method' value 'client_secret_post' is not supported by this authorization server.",
		},
		{
			name: "ShouldAcceptIntrospectionEndpointAuthMethodWithoutList",
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.IntrospectionEndpointAuthMethod = consts.ClientAuthMethodClientSecretPost
			},
		},
		{
			name: "ShouldAcceptIntrospectionEndpointAuthMethodWithEmptyList",
			setup: func(config *oauth2.Config) {
				config.IntrospectionEndpointAuthMethods = []string{}
			},
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.IntrospectionEndpointAuthMethod = consts.ClientAuthMethodClientSecretPost
			},
		},
		{
			name: "ShouldAcceptRevocationEndpointAuthMethodWithEmptyList",
			setup: func(config *oauth2.Config) {
				config.RevocationEndpointAuthMethods = []string{}
			},
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.RevocationEndpointAuthMethod = consts.ClientAuthMethodClientSecretPost
			},
		},
		{
			name: "ShouldRejectRevocationEndpointAuthMethodNotConfigured",
			setup: func(config *oauth2.Config) {
				config.RevocationEndpointAuthMethods = []string{consts.ClientAuthMethodPrivateKeyJWT}
			},
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.RevocationEndpointAuthMethod = consts.ClientAuthMethodClientSecretPost
			},
			err: "The 'revocation_endpoint_auth_method' value 'client_secret_post' is not supported by this authorization server.",
		},
		{
			name: "ShouldRejectTokenEndpointAuthSigningAlgNotAdvertised",
			setup: func(config *oauth2.Config) {
				config.ClientAssertionSigningAlgValues = []string{"ES256"}
			},
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.TokenEndpointAuthSigningAlg = "RS256"
			},
			err: "The 'token_endpoint_auth_signing_alg' value 'RS256' is not supported by this authorization server.",
		},
		{
			name: "ShouldRejectTokenEndpointAuthSigningAlgNoneWhenListed",
			setup: func(config *oauth2.Config) {
				config.ClientAssertionSigningAlgValues = []string{"ES256", consts.JSONWebTokenAlgNone}
			},
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.TokenEndpointAuthSigningAlg = consts.JSONWebTokenAlgNone
			},
			err: "The 'token_endpoint_auth_signing_alg' value must not be 'none'.",
		},
		{
			name: "ShouldRejectRevocationEndpointAuthSigningAlgNotInEndpointList",
			setup: func(config *oauth2.Config) {
				config.ClientAssertionSigningAlgValues = []string{"PS256"}
				config.RevocationEndpointAuthSigningAlgValues = []string{"ES256"}
			},
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.RevocationEndpointAuthSigningAlg = "PS256"
			},
			err: "The 'revocation_endpoint_auth_signing_alg' value 'PS256' is not supported by this authorization server.",
		},
		{
			name: "ShouldAcceptRevocationEndpointAuthSigningAlgFromClientAssertionFallback",
			setup: func(config *oauth2.Config) {
				config.ClientAssertionSigningAlgValues = []string{"ES256"}
			},
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.RevocationEndpointAuthSigningAlg = "ES256"
			},
		},
		{
			name: "ShouldRejectIntrospectionEndpointAuthSigningAlgNotInClientAssertionFallback",
			setup: func(config *oauth2.Config) {
				config.ClientAssertionSigningAlgValues = []string{"ES256"}
			},
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.IntrospectionEndpointAuthSigningAlg = "RS256"
			},
			err: "The 'introspection_endpoint_auth_signing_alg' value 'RS256' is not supported by this authorization server.",
		},
		{
			name: "ShouldAcceptIntrospectionEndpointAuthSigningAlgFromEndpointList",
			setup: func(config *oauth2.Config) {
				config.ClientAssertionSigningAlgValues = []string{"ES256"}
				config.IntrospectionEndpointAuthSigningAlgValues = []string{"PS256"}
			},
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.IntrospectionEndpointAuthSigningAlg = "PS256"
			},
		},
		{
			name: "ShouldRejectRequestObjectSigningAlgNoneWhenSignedRequired",
			setup: func(config *oauth2.Config) {
				config.RequestObjectSigningAlgValues = []string{"ES256", consts.JSONWebTokenAlgNone}
				config.RequireSignedRequestObject = true
			},
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.RequestObjectSigningAlg = consts.JSONWebTokenAlgNone
			},
			err: "The 'request_object_signing_alg' value 'none' is not supported by this authorization server.",
		},
		{
			name: "ShouldAcceptRequestObjectSigningAlgNoneWhenSignedNotRequired",
			setup: func(config *oauth2.Config) {
				config.RequestObjectSigningAlgValues = []string{"ES256", consts.JSONWebTokenAlgNone}
			},
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.RequestObjectSigningAlg = consts.JSONWebTokenAlgNone
			},
		},
		{
			name: "ShouldRejectRequestObjectSigningAlgNotAdvertised",
			setup: func(config *oauth2.Config) {
				config.RequestObjectSigningAlgValues = []string{"ES256"}
			},
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.RequestObjectSigningAlg = "RS256"
			},
			err: "The 'request_object_signing_alg' value 'RS256' is not supported by this authorization server.",
		},
		{
			name: "ShouldRejectRequestObjectEncryptionEncNotAdvertised",
			setup: func(config *oauth2.Config) {
				config.RequestObjectEncryptionEncValues = []string{"A256GCM"}
			},
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.RequestObjectEncryptionEnc = "A128GCM"
			},
			err: "The 'request_object_encryption_enc' value 'A128GCM' is not supported by this authorization server.",
		},
		{
			name: "ShouldRejectAccessTokenEncryptionAlgNotAdvertised",
			setup: func(config *oauth2.Config) {
				config.ResponseEncryptionAlgValues = map[oauth2.ResponseEncryptionTarget][]string{oauth2.ResponseEncryptionTargetAccessToken: {"RSA-OAEP-256"}}
			},
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.AccessTokenEncryptedResponseAlg = "RSA1_5"
			},
			err: "The 'access_token_encrypted_response_alg' value 'RSA1_5' is not supported by this authorization server.",
		},
		{
			name: "ShouldAcceptAccessTokenEncryptionAlgNone",
			setup: func(config *oauth2.Config) {
				config.ResponseEncryptionAlgValues = map[oauth2.ResponseEncryptionTarget][]string{oauth2.ResponseEncryptionTargetAccessToken: {"RSA-OAEP-256"}}
			},
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.AccessTokenEncryptedResponseAlg = consts.JSONWebTokenAlgNone
			},
		},
		{
			name: "ShouldRejectIDTokenEncryptionEncNotAdvertised",
			setup: func(config *oauth2.Config) {
				config.ResponseEncryptionEncValues = map[oauth2.ResponseEncryptionTarget][]string{oauth2.ResponseEncryptionTargetIDToken: {"A256GCM"}}
			},
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.IDTokenEncryptedResponseEnc = "A128GCM"
			},
			err: "The 'id_token_encrypted_response_enc' value 'A128GCM' is not supported by this authorization server.",
		},
	}

	stores := map[string]func() Storage{
		"MemoryStore":          func() Storage { return storage.NewMemoryStore() },
		"HydratingMemoryStore": func() Storage { return storage.NewHydratingMemoryStore() },
	}

	for storeName, factory := range stores {
		for _, tc := range testCases {
			t.Run(storeName+"/Registration/"+tc.name, func(t *testing.T) {
				ctx := context.Background()
				registration, _, config, store := newCapabilitiesFixture(t, factory)

				if tc.setup != nil {
					tc.setup(config)
				}

				requester := oauth2.NewClientRegistrationRequest()
				requester.Metadata = capabilitiesMetadata(tc.metadata)

				responder := oauth2.NewClientRegistrationResponse()

				err := registration.HandleRFC7591ClientRegistrationEndpointRequest(ctx, requester, responder)

				if tc.err == "" {
					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

					_, err = store.GetClient(ctx, responder.ClientID)
					require.NoError(t, err)

					return
				}

				require.ErrorIs(t, err, oauth2.ErrInvalidClientMetadata)
				assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The value of one of the client metadata fields is invalid and the server has rejected this request. "+tc.err)
			})

			t.Run(storeName+"/Configuration/"+tc.name, func(t *testing.T) {
				ctx := context.Background()
				registration, configuration, config, store := newCapabilitiesFixture(t, factory)

				created := registerClient(t, ctx, registration)
				id := created["client_id"].(string)

				if tc.setup != nil {
					tc.setup(config)
				}

				requester := oauth2.NewClientConfigurationRequest()
				requester.Method = http.MethodPut
				requester.ClientID = id
				requester.Signature = configuration.Strategy.ClientRegistrationTokenSignature(ctx, created["registration_access_token"].(string))
				requester.Metadata = capabilitiesMetadata(tc.metadata)

				err := configuration.HandleRFC7592ClientConfigurationEndpointRequest(ctx, requester, oauth2.NewClientRegistrationResponse())

				client, gerr := store.GetClient(ctx, id)
				require.NoError(t, gerr)

				if tc.err == "" {
					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
					assert.Equal(t, []string{capabilitiesRedirectURI}, client.GetRedirectURIs())

					return
				}

				require.ErrorIs(t, err, oauth2.ErrInvalidClientMetadata)
				assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The value of one of the client metadata fields is invalid and the server has rejected this request. "+tc.err)
				assert.Equal(t, []string{"https://example.com/cb"}, client.GetRedirectURIs())
			})
		}
	}
}

const capabilitiesRedirectURI = "https://example.com/capabilities"

func capabilitiesMetadata(mutate func(metadata *oauth2.ClientRegistrationMetadata)) *oauth2.ClientRegistrationMetadata {
	metadata := &oauth2.ClientRegistrationMetadata{
		RedirectURIs:  []string{capabilitiesRedirectURI},
		GrantTypes:    []string{consts.GrantTypeAuthorizationCode},
		ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow},
	}

	if mutate != nil {
		mutate(metadata)
	}

	return metadata
}

func newCapabilitiesFixture(t *testing.T, factory func() Storage) (*ClientRegistrationHandler, *ClientConfigurationHandler, *oauth2.Config, Storage) {
	t.Helper()

	config := &oauth2.Config{
		GlobalSecret:                          []byte("super-duper-secret-that-is-at-least-32-bytes"),
		RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b"),
		EndpointURLs:                          oauth2.EndpointURLs{Registration: testEndpoint},
		RFC7591ClientRegistrationStrategy:     NewDefaultClientRegistrationStrategy(),
		TokenEntropy:                          32,
	}

	config.JWTStrategy = &jwt.DefaultStrategy{
		Config: config,
		Issuer: jwt.NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: gen.MustES256Key(), KeyID: "es256", Algorithm: string(jose.ES256), Use: consts.JSONWebTokenUseSignature},
		}}),
	}

	explicit := &hoauth2.AuthorizeExplicitGrantHandler{}

	config.AuthorizeEndpointHandlers.Append(explicit)
	config.TokenEndpointHandlers.Append(explicit)

	store := factory()
	tokens := hoauth2.NewHMACCoreStrategy(config, "authelia_%s_")

	return &ClientRegistrationHandler{Store: store, Strategy: tokens, Config: config},
		&ClientConfigurationHandler{Store: store, Strategy: tokens, Config: config},
		config, store
}
