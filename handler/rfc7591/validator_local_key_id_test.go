// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7591

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestLocalValidatorSigningKeyIDs(t *testing.T) {
	const (
		unknown      = "Error occurred retrieving the JSON Web Key. The JSON Web Token uses signing key with kid '%s' which was not found"
		mismatched   = "Error occurred retrieving the JSON Web Key. Unable to find JSON web key with kid '%s', use 'sig', and alg '%s' in JSON Web Key Set"
		unverifiable = "The '%s' value '%s' is not supported as it cannot be validated by this authorization server."
	)

	testCases := []struct {
		name     string
		setup    func(config *oauth2.Config)
		metadata func(metadata *oauth2.ClientRegistrationMetadata)
		err      string
	}{
		{
			name: "ShouldAcceptIDTokenKeyID",
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.IDTokenSignedResponseAlg = "ES256"
				metadata.IDTokenSignedResponseKeyID = "es256"
			},
		},
		{
			name: "ShouldAcceptIDTokenKeyIDWithOmittedAlg",
			setup: func(config *oauth2.Config) {
				config.JWTStrategy = newSigningKeyIDStrategy(config, signingKeyIDES256, signingKeyIDRS256)
			},
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.IDTokenSignedResponseKeyID = "rs256"
			},
		},
		{
			name: "ShouldRejectIDTokenKeyIDUnknown",
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.IDTokenSignedResponseAlg = "ES256"
				metadata.IDTokenSignedResponseKeyID = "missing"
			},
			err: "The 'id_token_signed_response_kid' value 'missing' does not identify a signing key of this authorization server for the 'id_token_signed_response_alg' value 'ES256'. " + fmt.Sprintf(unknown, "missing"),
		},
		{
			name: "ShouldRejectIDTokenKeyIDWithMismatchedAlg",
			setup: func(config *oauth2.Config) {
				config.JWTStrategy = newSigningKeyIDStrategy(config, signingKeyIDES256, signingKeyIDRS256)
			},
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.IDTokenSignedResponseAlg = "ES256"
				metadata.IDTokenSignedResponseKeyID = "rs256"
			},
			err: "The 'id_token_signed_response_kid' value 'rs256' does not identify a signing key of this authorization server for the 'id_token_signed_response_alg' value 'ES256'. " + fmt.Sprintf(mismatched, "rs256", "ES256"),
		},
		{
			name: "ShouldRejectIDTokenKeyIDWithMismatchedOmittedAlg",
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.IDTokenSignedResponseKeyID = "es256"
			},
			err: "The 'id_token_signed_response_kid' value 'es256' does not identify a signing key of this authorization server for the 'id_token_signed_response_alg' value 'RS256', which applies by default when 'id_token_signed_response_alg' is omitted. " + fmt.Sprintf(mismatched, "es256", "RS256"),
		},
		{
			name: "ShouldRejectIDTokenKeyIDWithClientSecretAlg",
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.IDTokenSignedResponseAlg = "HS256"
				metadata.IDTokenSignedResponseKeyID = "es256"
			},
			err: "The 'id_token_signed_response_kid' value 'es256' does not identify a signing key of this authorization server for the 'id_token_signed_response_alg' value 'HS256'. " + fmt.Sprintf(mismatched, "es256", "HS256"),
		},
		{
			name: "ShouldRejectIDTokenKeyIDVerificationOnly",
			setup: func(config *oauth2.Config) {
				config.JWTStrategy = &jwt.DefaultStrategy{
					Config: config,
					Issuer: jwt.NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{signingKeyIDES256()}}).WithVerificationOnlyKeys(
						jose.JSONWebKey{Key: gen.MustES256Key(), KeyID: "retired", Algorithm: string(jose.ES256), Use: consts.JSONWebTokenUseSignature},
					),
				}
			},
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.IDTokenSignedResponseAlg = "ES256"
				metadata.IDTokenSignedResponseKeyID = "retired"
			},
			err: "The 'id_token_signed_response_kid' value 'retired' does not identify a signing key of this authorization server for the 'id_token_signed_response_alg' value 'ES256'. " + fmt.Sprintf(unknown, "retired"),
		},
		{
			name: "ShouldRejectIDTokenKeyIDWithoutStrategySupport",
			setup: func(config *oauth2.Config) {
				config.JWTStrategy = signingAlgValuesStrategy{Strategy: config.JWTStrategy, algs: []string{"ES256"}}
			},
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.IDTokenSignedResponseAlg = "ES256"
				metadata.IDTokenSignedResponseKeyID = "es256"
			},
			err: fmt.Sprintf(unverifiable, "id_token_signed_response_kid", "es256"),
		},
		{
			name: "ShouldAcceptUserinfoKeyID",
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.UserinfoSignedResponseAlg = "ES256"
				metadata.UserinfoSignedResponseKeyID = "es256"
			},
		},
		{
			name: "ShouldRejectUserinfoKeyIDWithOmittedAlg",
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.UserinfoSignedResponseKeyID = "es256"
			},
			err: "The 'userinfo_signed_response_kid' value 'es256' requires a signed response, but the 'userinfo_signed_response_alg' value is omitted or 'none'.",
		},
		{
			name: "ShouldRejectUserinfoKeyIDWithNoneAlg",
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.UserinfoSignedResponseAlg = consts.JSONWebTokenAlgNone
				metadata.UserinfoSignedResponseKeyID = "es256"
			},
			err: "The 'userinfo_signed_response_kid' value 'es256' requires a signed response, but the 'userinfo_signed_response_alg' value is omitted or 'none'.",
		},
		{
			name: "ShouldRejectUserinfoKeyIDUnknown",
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.UserinfoSignedResponseAlg = "ES256"
				metadata.UserinfoSignedResponseKeyID = "missing"
			},
			err: "The 'userinfo_signed_response_kid' value 'missing' does not identify a signing key of this authorization server for the 'userinfo_signed_response_alg' value 'ES256'. " + fmt.Sprintf(unknown, "missing"),
		},
		{
			name: "ShouldAcceptAccessTokenKeyID",
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.AccessTokenSignedResponseAlg = "ES256"
				metadata.AccessTokenSignedResponseKeyID = "es256"
			},
		},
		{
			name: "ShouldRejectAccessTokenKeyIDWithMismatchedOmittedAlg",
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.AccessTokenSignedResponseKeyID = "es256"
			},
			err: "The 'access_token_signed_response_kid' value 'es256' does not identify a signing key of this authorization server for the 'access_token_signed_response_alg' value 'RS256', which applies by default when 'access_token_signed_response_alg' is omitted. " + fmt.Sprintf(mismatched, "es256", "RS256"),
		},
		{
			name: "ShouldAcceptAuthorizationKeyID",
			setup: func(config *oauth2.Config) {
				config.JWTSecuredAuthorizeResponseModeStrategy = newSigningKeyIDStrategy(config, signingKeyIDES256)
			},
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.AuthorizationSignedResponseAlg = "ES256"
				metadata.AuthorizationSignedResponseKeyID = "es256"
			},
		},
		{
			name: "ShouldAcceptAuthorizationKeyIDWithOmittedAlgAndPermittedAlgs",
			setup: func(config *oauth2.Config) {
				config.JWTSecuredAuthorizeResponseModeStrategy = newSigningKeyIDStrategy(config, signingKeyIDES256)
				config.AuthorizationSignedResponseAlgValues = []string{"PS256", "ES256"}
			},
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.AuthorizationSignedResponseKeyID = "es256"
			},
		},
		{
			name: "ShouldRejectAuthorizationKeyIDWithMismatchedOmittedAlg",
			setup: func(config *oauth2.Config) {
				config.JWTSecuredAuthorizeResponseModeStrategy = newSigningKeyIDStrategy(config, signingKeyIDES256)
			},
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.AuthorizationSignedResponseKeyID = "es256"
			},
			err: "The 'authorization_signed_response_kid' value 'es256' does not identify a signing key of this authorization server for the 'authorization_signed_response_alg' value 'RS256', which applies by default when 'authorization_signed_response_alg' is omitted. " + fmt.Sprintf(mismatched, "es256", "RS256"),
		},
		{
			name: "ShouldRejectAuthorizationKeyIDOfAnotherStrategy",
			setup: func(config *oauth2.Config) {
				config.JWTSecuredAuthorizeResponseModeStrategy = newSigningKeyIDStrategy(config, func() jose.JSONWebKey {
					return jose.JSONWebKey{Key: gen.MustES256Key(), KeyID: "jarm", Algorithm: string(jose.ES256), Use: consts.JSONWebTokenUseSignature}
				})
			},
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.AuthorizationSignedResponseAlg = "ES256"
				metadata.AuthorizationSignedResponseKeyID = "es256"
			},
			err: "The 'authorization_signed_response_kid' value 'es256' does not identify a signing key of this authorization server for the 'authorization_signed_response_alg' value 'ES256'. " + fmt.Sprintf(unknown, "es256"),
		},
		{
			name: "ShouldRejectAuthorizationKeyIDWithoutStrategy",
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.AuthorizationSignedResponseKeyID = "es256"
			},
			err: fmt.Sprintf(unverifiable, "authorization_signed_response_kid", "es256"),
		},
		{
			name: "ShouldAcceptIntrospectionKeyID",
			setup: func(config *oauth2.Config) {
				config.IntrospectionJWTResponseStrategy = newSigningKeyIDStrategy(config, signingKeyIDES256)
			},
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.IntrospectionSignedResponseAlg = "ES256"
				metadata.IntrospectionSignedResponseKeyID = "es256"
			},
		},
		{
			name: "ShouldAcceptIntrospectionKeyIDWithOmittedAlg",
			setup: func(config *oauth2.Config) {
				config.IntrospectionJWTResponseStrategy = newSigningKeyIDStrategy(config, signingKeyIDES256, signingKeyIDRS256)
			},
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.IntrospectionSignedResponseKeyID = "rs256"
			},
		},
		{
			name: "ShouldAcceptIntrospectionKeyIDWithOmittedAlgAndPermittedAlgs",
			setup: func(config *oauth2.Config) {
				config.IntrospectionJWTResponseStrategy = newSigningKeyIDStrategy(config, signingKeyIDES256)
				config.IntrospectionSignedResponseAlgValues = []string{"RS256", "ES256"}
			},
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.IntrospectionSignedResponseKeyID = "es256"
			},
		},
		{
			name: "ShouldRejectIntrospectionKeyIDWithOmittedAlgPreferringRS256",
			setup: func(config *oauth2.Config) {
				config.IntrospectionJWTResponseStrategy = newSigningKeyIDStrategy(config, signingKeyIDES256, signingKeyIDRS256)
				config.IntrospectionSignedResponseAlgValues = []string{"ES256", "RS256"}
			},
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.IntrospectionSignedResponseKeyID = "es256"
			},
			err: "The 'introspection_signed_response_kid' value 'es256' does not identify a signing key of this authorization server for the 'introspection_signed_response_alg' value 'RS256', which applies by default when 'introspection_signed_response_alg' is omitted. " + fmt.Sprintf(mismatched, "es256", "RS256"),
		},
		{
			name: "ShouldRejectIntrospectionKeyIDWithoutStrategy",
			metadata: func(metadata *oauth2.ClientRegistrationMetadata) {
				metadata.IntrospectionSignedResponseKeyID = "es256"
			},
			err: fmt.Sprintf(unverifiable, "introspection_signed_response_kid", "es256"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, config, _ := newCapabilitiesFixture(t, func() Storage { return storage.NewMemoryStore() })

			if tc.setup != nil {
				tc.setup(config)
			}

			err := NewLocalValidator(config).ValidateClientRegistrationMetadata(t.Context(), nil, capabilitiesMetadata(tc.metadata))

			if tc.err == "" {
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				return
			}

			require.ErrorIs(t, err, oauth2.ErrInvalidClientMetadata)
			assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The value of one of the client metadata fields is invalid and the server has rejected this request. "+tc.err)
		})
	}
}

func signingKeyIDES256() jose.JSONWebKey {
	return jose.JSONWebKey{Key: gen.MustES256Key(), KeyID: "es256", Algorithm: string(jose.ES256), Use: consts.JSONWebTokenUseSignature}
}

func signingKeyIDRS256() jose.JSONWebKey {
	return jose.JSONWebKey{Key: gen.MustRSAKey(), KeyID: "rs256", Algorithm: string(jose.RS256), Use: consts.JSONWebTokenUseSignature}
}

func newSigningKeyIDStrategy(config *oauth2.Config, keys ...func() jose.JSONWebKey) *jwt.DefaultStrategy {
	jwks := &jose.JSONWebKeySet{}

	for _, key := range keys {
		jwks.Keys = append(jwks.Keys, key())
	}

	return &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerUnverifiedFromJWKS(jwks)}
}
