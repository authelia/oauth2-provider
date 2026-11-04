// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693_test

import (
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	. "authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestJWTTypeIssueRole(t *testing.T) {
	t.Run("ShouldRefuseATypeWithoutIssueAsTheRequestedTokenType", func(t *testing.T) {
		config := newSpecConfig(t)
		config.RFC8693TokenTypes["urn:spec:jwt"].(*JWTType).Issue = nil

		err := runGrantHandler(t, config, newSpecRequest(t, newConfidentialClient(), newSpecSession("alice"), url.Values{
			consts.FormParameterRequestedTokenType: {"urn:spec:jwt"},
		}))

		require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
		assert.Contains(t, oauth2.ErrorToDebugRFC6749Error(err).Error(), "not supported as a 'requested_token_type'")
	})

	t.Run("ShouldRefuseATypeWithoutAnIssuerAsTheRequestedTokenType", func(t *testing.T) {
		config := newSpecConfig(t)
		config.RFC8693TokenTypes["urn:spec:jwt"].(*JWTType).Issue.Issuer = ""

		err := runGrantHandler(t, config, newSpecRequest(t, newConfidentialClient(), newSpecSession("alice"), url.Values{
			consts.FormParameterRequestedTokenType: {"urn:spec:jwt"},
		}))

		require.ErrorIs(t, err, oauth2.ErrServerError)
		assert.Contains(t, oauth2.ErrorToDebugRFC6749Error(err).Error(), "has no issuer")
	})

	t.Run("ShouldRefuseToIssueATypeWithoutIssue", func(t *testing.T) {
		config := newSpecConfig(t)
		config.RFC8693TokenTypes["urn:spec:jwt"].(*JWTType).Issue = nil

		response, err := issueRoleJWT(t, config, "")

		require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
		assert.Contains(t, oauth2.ErrorToDebugRFC6749Error(err).Error(), "not supported as a 'requested_token_type'")
		assert.Empty(t, response.AccessToken)
	})

	t.Run("ShouldRefuseToIssueATypeWithoutAnIssuer", func(t *testing.T) {
		config := newSpecConfig(t)
		config.RFC8693TokenTypes["urn:spec:jwt"].(*JWTType).Issue.Issuer = ""

		response, err := issueRoleJWT(t, config, "")

		require.ErrorIs(t, err, oauth2.ErrServerError)
		assert.Empty(t, response.AccessToken)
	})

	t.Run("ShouldIssueWithTheIssueIssuer", func(t *testing.T) {
		config := newSpecConfig(t)
		config.RFC8693TokenTypes["urn:spec:jwt"].(*JWTType).Issue.Issuer = "https://jwt.example.com"
		config.RFC8693TokenTypes["urn:spec:jwt"].(*JWTType).Validate.Issuer = "https://idp.example.com"

		response, err := issueRoleJWT(t, config, "")

		require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
		assert.Equal(t, "https://jwt.example.com", issuedRoleJWTIssuer(t, response))
	})

	t.Run("ShouldIgnoreTheSessionIssuer", func(t *testing.T) {
		config := newSpecConfig(t)
		config.RFC8693TokenTypes["urn:spec:jwt"].(*JWTType).Issue.Issuer = "https://jwt.example.com"

		response, err := issueRoleJWT(t, config, "https://idp.example.com")

		require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
		assert.Equal(t, "https://jwt.example.com", issuedRoleJWTIssuer(t, response))
	})
}

func TestJWTTypeValidateRole(t *testing.T) {
	claims := func(iss string) jwt.MapClaims {
		return jwt.MapClaims{
			consts.ClaimIssuer:         iss,
			consts.ClaimSubject:        "peter",
			consts.ClaimAudience:       []string{"my-client"},
			consts.ClaimExpirationTime: time.Now().Add(time.Minute).Unix(),
		}
	}

	t.Run("ShouldRefuseATypeWithoutValidateAsTheSubjectTokenType", func(t *testing.T) {
		config := newSpecConfig(t)
		config.RFC8693TokenTypes["urn:spec:jwt"].(*JWTType).Validate = nil

		err := runGrantHandler(t, config, newSpecRequest(t, newConfidentialClient(), newSpecSession("alice"), url.Values{
			consts.FormParameterSubjectTokenType: {"urn:spec:jwt"},
		}))

		require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
		assert.Contains(t, oauth2.ErrorToDebugRFC6749Error(err).Error(), "not supported as a 'subject_token_type'")
	})

	t.Run("ShouldRefuseATypeWithoutValidateAsTheActorTokenType", func(t *testing.T) {
		config := newSpecConfig(t)
		config.RFC8693TokenTypes["urn:spec:jwt"].(*JWTType).Validate = nil

		err := runGrantHandler(t, config, newSpecRequest(t, newConfidentialClient(), newSpecSession("alice"), url.Values{
			consts.FormParameterActorToken:     {"opaque-actor-token"},
			consts.FormParameterActorTokenType: {"urn:spec:jwt"},
		}))

		require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
		assert.Contains(t, oauth2.ErrorToDebugRFC6749Error(err).Error(), "not supported as a 'actor_token_type'")
	})

	t.Run("ShouldRefuseATypeWithoutValidateAsTheSubjectToken", func(t *testing.T) {
		config := newSpecConfig(t)
		config.RFC8693TokenTypes["urn:spec:jwt"].(*JWTType).Validate = nil

		err := validateCustomJWTToken(t, config, claims("https://as.example.com"), false)

		require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
		assert.Contains(t, oauth2.ErrorToDebugRFC6749Error(err).Error(), "is not accepted as a subject token")
	})

	t.Run("ShouldRefuseATypeWithoutValidateAsTheActorToken", func(t *testing.T) {
		config := newSpecConfig(t)
		config.RFC8693TokenTypes["urn:spec:jwt"].(*JWTType).Validate = nil

		err := validateCustomJWTToken(t, config, claims("https://as.example.com"), true)

		require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
		assert.Contains(t, oauth2.ErrorToDebugRFC6749Error(err).Error(), "is not accepted as an actor token")
	})

	t.Run("ShouldAcceptTheValidateIssuer", func(t *testing.T) {
		config := newSpecConfig(t)
		config.RFC8693TokenTypes["urn:spec:jwt"].(*JWTType).Issue.Issuer = "https://jwt.example.com"
		config.RFC8693TokenTypes["urn:spec:jwt"].(*JWTType).Validate.Issuer = "https://idp.example.com"

		require.NoError(t, oauth2.ErrorToDebugRFC6749Error(validateCustomJWTToken(t, config, claims("https://idp.example.com"), false)))
	})

	t.Run("ShouldNotTrustTheIssueIssuer", func(t *testing.T) {
		config := newSpecConfig(t)
		config.RFC8693TokenTypes["urn:spec:jwt"].(*JWTType).Issue.Issuer = "https://jwt.example.com"
		config.RFC8693TokenTypes["urn:spec:jwt"].(*JWTType).Validate.Issuer = "https://idp.example.com"

		err := validateCustomJWTToken(t, config, claims("https://jwt.example.com"), false)

		require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
		assert.Contains(t, oauth2.ErrorToDebugRFC6749Error(err).Error(), "Claim 'iss' from token must match the 'https://idp.example.com'")
	})
}

func issueRoleJWT(t *testing.T, config *oauth2.Config, sessionIssuer string) (*oauth2.AccessResponse, error) {
	t.Helper()

	store := storage.NewExampleStore()

	session := &DefaultSession{
		DefaultSession: &openid.DefaultSession{Claims: &jwt.IDTokenClaims{Subject: "alice", Issuer: sessionIssuer}, Headers: &jwt.Headers{}, Subject: "alice"},
		SubjectToken:   map[string]any{consts.ClaimSubject: "alice"},
		Extra:          map[string]any{},
	}

	request := &oauth2.AccessRequest{
		GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthTokenExchange},
		Request: oauth2.Request{
			ID:      uuid.New().String(),
			Client:  store.Clients["my-client"],
			Session: session,
			Form: url.Values{
				consts.FormParameterGrantType:          {consts.GrantTypeOAuthTokenExchange},
				consts.FormParameterRequestedTokenType: {"urn:spec:jwt"},
				consts.FormParameterSubjectToken:       {"opaque-subject-token"},
				consts.FormParameterSubjectTokenType:   {consts.TokenTypeRFC8693AccessToken},
			},
		},
	}

	handler := &CustomJWTTypeHandler{Config: config, Strategy: &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(key)}, Storage: store}

	response := oauth2.NewAccessResponse()

	return response, handler.PopulateTokenEndpointResponse(t.Context(), request, response)
}

func issuedRoleJWTIssuer(t *testing.T, response *oauth2.AccessResponse) string {
	t.Helper()

	var claims map[string]any

	_, err := jwt.UnsafeParseSignedAny(response.AccessToken, &claims)
	require.NoError(t, err)

	iss, _ := claims[consts.ClaimIssuer].(string)

	return iss
}
