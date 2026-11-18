// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7523

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	mrand "math/rand"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"authelia.com/provider/jose"
	"authelia.com/provider/jose/jwt"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/internal"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/testing/mock"
)

func TestHandlerGrantTypesSupported(t *testing.T) {
	h := &Handler{}

	assert.Equal(t, []string{consts.GrantTypeOAuthJWTBearer}, h.GrantTypesSupported(context.Background()))
}

func TestRFC7523RejectsUnadvertisedAlg(t *testing.T) {
	for _, store := range jwtBearerStores {
		t.Run(store.name, func(t *testing.T) {
			f := newJWTBearerFixture(t, store.new())

			f.handler.Config.(*oauth2.Config).RFC7523AssertionSigningAlgValues = []string{"ES256"}

			f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
			f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertion(f.createStandardClaim(), "unadvertised"))

			err := f.handler.HandleTokenEndpointRequest(f.ctx, f.requester)

			require.Error(t, err)
			assert.ErrorIs(t, err, oauth2.ErrInvalidGrant)
			assert.Equal(t, "Unable to parse the JWT authorization grant.", oauth2.ErrorToRFC6749Error(err).HintField)
		})
	}
}

func TestRFC7523AcceptsEdDSA(t *testing.T) {
	const keyID = "eddsa"

	for _, store := range jwtBearerStores {
		t.Run(store.name, func(t *testing.T) {
			for _, alg := range []jose.SignatureAlgorithm{jose.EdDSA, jose.Ed25519} {
				t.Run(string(alg), func(t *testing.T) {
					f := newJWTBearerFixture(t, store.new())

					public, private, err := ed25519.GenerateKey(rand.Reader)
					require.NoError(t, err)

					cl := f.createStandardClaim()

					signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: jose.JSONWebKey{Key: private, KeyID: keyID, Algorithm: string(alg)}}, (&jose.SignerOptions{}).WithType("JWT"))
					require.NoError(t, err)

					assertion, err := jwt.Signed(signer).Claims(cl).Serialize()
					require.NoError(t, err)

					f.trust(func(trusted *oauth2.RFC7523TrustedIssuer) {
						trusted.JSONWebKeys = f.createJWS(jose.JSONWebKey{Key: public, KeyID: keyID, Algorithm: string(alg), Use: consts.JSONWebTokenUseSignature})
						trusted.SigningAlgs = []string{string(alg)}
					})

					f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
					f.requester.Form.Add(consts.FormParameterAssertion, assertion)

					assert.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.handler.HandleTokenEndpointRequest(f.ctx, f.requester)))
				})
			}
		})
	}
}

func TestAuthorizeJWTGrantRequestHandler(t *testing.T) {
	const (
		testClientID          = "my-client"
		testWiderScope        = "wider_scope"
		hintUnparsed          = "Unable to parse the JWT authorization grant."
		hintExpired           = "The JWT authorization grant is expired."
		hintIssuedInTheFuture = "The 'iat' claim of the JWT authorization grant is in the future."
		hintExpiryTooFar      = "The 'exp' claim of the JWT authorization grant is unreasonably far in the future."
	)

	testCases := []struct {
		name     string
		setup    func(f *jwtBearerFixture)
		err      error
		expected string
		hint     string
	}{
		{
			name: "ShouldRejectAnInvalidGrantType",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeAuthorizationCode}
			},
			err:      oauth2.ErrUnknownRequest,
			expected: "The handler is not responsible for this request.",
		},
		{
			name: "ShouldRejectAClientNotRegisteredForTheGrantType",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				f.requester.Client = &oauth2.DefaultClient{GrantTypes: []string{consts.GrantTypeAuthorizationCode}}
				f.handler.Config.(*oauth2.Config).GrantTypeJWTBearerCanSkipClientAuth = false
			},
			err:      oauth2.ErrUnauthorizedClient,
			expected: "The client is not authorized to request a token using this method. The OAuth 2.0 Client is not allowed to use authorization grant 'urn:ietf:params:oauth:grant-type:jwt-bearer'.",
		},
		{
			name: "ShouldRejectAnAuthenticatedClientNotRegisteredForTheGrantTypeWhenClientAuthenticationMayBeSkipped",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				f.requester.Client = &oauth2.DefaultClient{ID: "foo", GrantTypes: []string{consts.GrantTypeAuthorizationCode}}
				f.handler.Config.(*oauth2.Config).GrantTypeJWTBearerCanSkipClientAuth = true
			},
			err:      oauth2.ErrUnauthorizedClient,
			expected: "The client is not authorized to request a token using this method. The OAuth 2.0 Client is not allowed to use authorization grant 'urn:ietf:params:oauth:grant-type:jwt-bearer'.",
		},
		{
			name: "ShouldRejectARequestWithoutAnAssertion",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
			},
			err:      oauth2.ErrInvalidRequest,
			expected: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The assertion request parameter must be set when using grant_type of 'urn:ietf:params:oauth:grant-type:jwt-bearer'.",
		},
		{
			name: "ShouldRejectAMalformedAssertion",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				f.requester.Form.Add(consts.FormParameterAssertion, "fjigjgfkjgkf")
			},
			err:  oauth2.ErrInvalidGrant,
			hint: hintUnparsed,
		},
		{
			name: "ShouldRejectATransactionTokenBeforeAnyKeyLookup",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertionWithType(f.createStandardClaim(), keyID, consts.JSONWebTokenTypeTxnToken))
			},
			err:      oauth2.ErrInvalidGrant,
			expected: "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. The JWT in 'assertion' request parameter is a transaction token, which cannot be used as an assertion.",
		},
		{
			name: "ShouldRejectAnAssertionWithoutAnIssuer",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				cl := f.createStandardClaim()
				cl.Issuer = ""
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertion(cl, keyID))
			},
			err:  oauth2.ErrInvalidGrant,
			hint: "The JWT authorization grant must contain an 'iss' claim.",
		},
		{
			name: "ShouldRejectAnAssertionWithoutASubject",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				cl := f.createStandardClaim()
				cl.Subject = ""
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertion(cl, keyID))
			},
			err:      oauth2.ErrInvalidGrant,
			expected: "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. The JWT in 'assertion' request parameter MUST contain a 'sub' (subject) claim.",
		},
		{
			name: "ShouldRejectWhenThePublicKeyDoesNotVerify",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				keyID := "wrong_key"
				cl := f.createStandardClaim()
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertion(cl, keyID))
				jwk := f.createRandomTestJWK()
				jwk.KeyID = keyID

				f.trust(func(trusted *oauth2.RFC7523TrustedIssuer) { trusted.JSONWebKeys = f.createJWS(jwk) })
			},
			err:  oauth2.ErrInvalidGrant,
			hint: hintAssertionUnverified,
		},
		{
			name: "ShouldRejectWhenNoneOfThePublicKeysVerify",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				keyID := ""
				cl := f.createStandardClaim()
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertion(cl, keyID))
				f.trust(func(trusted *oauth2.RFC7523TrustedIssuer) {
					trusted.JSONWebKeys = f.createJWS(f.createRandomTestJWK(), f.createRandomTestJWK())
				})
			},
			err:  oauth2.ErrInvalidGrant,
			hint: hintAssertionUnverified,
		},
		{
			name: "ShouldRejectAnAssertionWithoutAnAudience",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				cl := f.createStandardClaim()
				cl.Audience = []string{}
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertion(cl, keyID))
			},
			err:      oauth2.ErrInvalidGrant,
			expected: "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. The JWT in 'assertion' request parameter MUST contain an 'aud' (audience) claim.",
		},
		{
			name: "ShouldRejectAnAssertionAudiencedElsewhere",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				cl := f.createStandardClaim()
				cl.Audience = jwt.Audience{"leela", "fry"}
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertion(cl, keyID))
			},
			err:      oauth2.ErrInvalidGrant,
			expected: "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. The JWT in 'assertion' request parameter MUST contain an 'aud' (audience) claim containing a value 'https://www.example.com/token' that identifies the authorization server as an intended audience.",
		},
		{
			name: "ShouldRejectAnAssertionWithoutAnExpiry",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				cl := f.createStandardClaim()
				cl.Expiry = nil
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertion(cl, keyID))
			},
			err:      oauth2.ErrInvalidGrant,
			expected: "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. The JWT in 'assertion' request parameter MUST contain an 'exp' (expiration time) claim.",
		},
		{
			name: "ShouldRejectAnExpiredAssertion",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				cl := f.createStandardClaim()
				cl.Expiry = jwt.NewNumericDate(time.Now().AddDate(0, -1, 0))
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertion(cl, keyID))
			},
			err:  oauth2.ErrInvalidGrant,
			hint: hintExpired,
		},
		{
			name: "ShouldRejectAnAssertionBeforeItsNotBeforeDate",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				nbf := time.Now().AddDate(0, 1, 0)
				cl := f.createStandardClaim()
				cl.NotBefore = jwt.NewNumericDate(nbf)
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertion(cl, keyID))
			},
			err:  oauth2.ErrInvalidGrant,
			hint: "The JWT authorization grant is not yet valid.",
		},
		{
			name: "ShouldRejectAnAssertionWithoutARequiredIssuedAt",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				cl := f.createStandardClaim()
				cl.IssuedAt = nil
				f.handler.Config.(*oauth2.Config).GrantTypeJWTBearerIssuedDateOptional = false
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertion(cl, keyID))
			},
			err:      oauth2.ErrInvalidGrant,
			expected: "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. The JWT in 'assertion' request parameter MUST contain an 'iat' (issued at) claim.",
		},
		{
			name: "ShouldAcceptAnAssertionWithNoTypeHeader",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				cl := f.createStandardClaim()
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertionWithType(cl, keyID, ""))
			},
		},
		{
			name: "ShouldAcceptAnApplicationJWTTypeHeader",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				cl := f.createStandardClaim()
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertionWithType(cl, keyID, "application/jwt"))
			},
		},
		{
			name: "ShouldAcceptALowercaseJWTTypeHeader",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				cl := f.createStandardClaim()
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertionWithType(cl, keyID, "jwt"))
			},
		},
		{
			name: "ShouldRejectANonJWTTypeHeader",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				cl := f.createStandardClaim()
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertionWithType(cl, keyID, consts.JSONWebTokenTypeDPoP))
			},
			err:      oauth2.ErrInvalidGrant,
			expected: "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. The JWT in 'assertion' request parameter has an invalid 'typ' header value 'dpop+jwt'; expected 'JWT'.",
		},
		{
			name: "ShouldRejectAnIssuedAtInTheFuture",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				issuedAt := time.Now().Add(2 * time.Hour)
				cl := f.createStandardClaim()
				cl.IssuedAt = jwt.NewNumericDate(issuedAt)
				cl.Expiry = jwt.NewNumericDate(issuedAt.Add(30 * time.Minute))
				f.handler.Config.(*oauth2.Config).GrantTypeJWTBearerIssuedDateOptional = false
				f.handler.Config.(*oauth2.Config).GrantTypeJWTBearerMaxDuration = time.Hour * 24
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertion(cl, keyID))
			},
			err:  oauth2.ErrInvalidGrant,
			hint: hintIssuedInTheFuture,
		},
		{
			name: "ShouldAcceptAnIssuedAtAndNotBeforeWithinTheClockSkew",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				cl := f.createStandardClaim()
				cl.IssuedAt = jwt.NewNumericDate(time.Now().Add(time.Second * 5))
				cl.NotBefore = jwt.NewNumericDate(time.Now().Add(time.Second * 5))
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertion(cl, keyID))
			},
		},
		{
			name: "ShouldRejectAnIssuedAtInTheNearFutureWhenClockSkewIsDisabled",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				cl := f.createStandardClaim()
				cl.IssuedAt = jwt.NewNumericDate(time.Now().Add(time.Second * 5))
				f.handler.Config.(*oauth2.Config).JWTClockSkew = -1
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertion(cl, keyID))
			},
			err:  oauth2.ErrInvalidGrant,
			hint: hintIssuedInTheFuture,
		},
		{
			name: "ShouldRejectAnIssuedAtFarInThePast",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				issuedAt := time.Now().AddDate(0, 0, -31)
				cl := f.createStandardClaim()
				cl.IssuedAt = jwt.NewNumericDate(issuedAt)
				f.handler.Config.(*oauth2.Config).GrantTypeJWTBearerIssuedDateOptional = false
				f.handler.Config.(*oauth2.Config).GrantTypeJWTBearerMaxDuration = time.Hour * 24 * 30
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertion(cl, keyID))
			},
			err:  oauth2.ErrInvalidGrant,
			hint: hintExpiryTooFar,
		},
		{
			name: "ShouldRejectAnExpiryFarInTheFuture",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				cl := f.createStandardClaim()
				cl.IssuedAt = jwt.NewNumericDate(time.Now().AddDate(0, 0, -15))
				cl.Expiry = jwt.NewNumericDate(time.Now().AddDate(0, 0, 20))
				f.handler.Config.(*oauth2.Config).GrantTypeJWTBearerIssuedDateOptional = false
				f.handler.Config.(*oauth2.Config).GrantTypeJWTBearerMaxDuration = time.Hour * 24 * 30
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertion(cl, keyID))
			},
			err:  oauth2.ErrInvalidGrant,
			hint: hintExpiryTooFar,
		},
		{
			name: "ShouldRejectAnExpiryFarInTheFutureWithNoIssuedAt",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				cl := f.createStandardClaim()
				cl.IssuedAt = nil
				cl.Expiry = jwt.NewNumericDate(time.Now().AddDate(0, 0, 31))
				f.handler.Config.(*oauth2.Config).GrantTypeJWTBearerIssuedDateOptional = true
				f.handler.Config.(*oauth2.Config).GrantTypeJWTBearerMaxDuration = time.Hour * 24 * 30
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertion(cl, keyID))
			},
			err:  oauth2.ErrInvalidGrant,
			hint: hintExpiryTooFar,
		},
		{
			name: "ShouldRejectAnAssertionWithoutARequiredTokenID",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				cl := f.createStandardClaim()
				cl.ID = ""
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertion(cl, keyID))
			},
			err:      oauth2.ErrInvalidGrant,
			expected: "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. The JWT in 'assertion' request parameter MUST contain an 'jti' (JWT ID) claim.",
		},
		{
			name: "ShouldRejectAnAssertionAlreadyUsed",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				cl := f.createStandardClaim()
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertion(cl, keyID))
				require.NoError(f.t, f.store.MarkRFC7523JWTUsedForTime(f.ctx, cl.Issuer, cl.ID, cl.Expiry.Time()))
			},
			err:  oauth2.ErrInvalidGrant,
			hint: hintRedeemed,
		},
		{
			name: "ShouldRejectScopesTheIssuerIsNotGranted",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				cl := f.createStandardClaim()
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertion(cl, keyID))
				f.requester.RequestedScope = []string{"some_scope"}
			},
			err:  oauth2.ErrInvalidScope,
			hint: "The issuer 'trusted_issuer' is not allowed to grant scope 'some_scope'.",
		},
		{
			name: "ShouldAcceptAValidAssertion",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				cl := f.createStandardClaim()
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertion(cl, keyID))
				f.requester.RequestedScope = []string{"valid_scope"}
				f.trust(func(trusted *oauth2.RFC7523TrustedIssuer) {
					trusted.Scopes = []string{"valid_scope", consts.ScopeOpenID}
				})
			},
		},
		{
			name: "ShouldRejectAScopeTheAuthenticatedClientIsNotRegisteredFor",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				f.requester.Client = &oauth2.DefaultClient{ID: testClientID, GrantTypes: []string{consts.GrantTypeOAuthJWTBearer}, Scopes: []string{"valid_scope"}}
				cl := f.createStandardClaim()
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertion(cl, keyID))
				f.requester.RequestedScope = []string{"valid_scope", testWiderScope}
				f.trust(func(trusted *oauth2.RFC7523TrustedIssuer) { trusted.Scopes = []string{"valid_scope", testWiderScope} })
			},
			err:      oauth2.ErrInvalidScope,
			expected: "The requested scope is invalid, unknown, or malformed. The OAuth 2.0 Client is not allowed to request scope 'wider_scope'.",
		},
		{
			name: "ShouldAcceptAScopeTheAuthenticatedClientIsRegisteredFor",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				f.requester.Client = &oauth2.DefaultClient{ID: testClientID, GrantTypes: []string{consts.GrantTypeOAuthJWTBearer}, Scopes: []string{"valid_scope"}}
				cl := f.createStandardClaim()
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertion(cl, keyID))
				f.requester.RequestedScope = []string{"valid_scope"}
				f.trust(func(trusted *oauth2.RFC7523TrustedIssuer) { trusted.Scopes = []string{"valid_scope", testWiderScope} })
			},
		},
		{
			name: "ShouldAcceptAValidAssertionWithNoScopesRequested",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				cl := f.createStandardClaim()
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertion(cl, keyID))
			},
		},
		{
			name: "ShouldAcceptAnAssertionWithoutATokenIDWhenOptional",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				cl := f.createStandardClaim()
				f.handler.Config.(*oauth2.Config).GrantTypeJWTBearerIDOptional = true
				cl.ID = ""
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertion(cl, keyID))
			},
		},
		{
			name: "ShouldAcceptAnAssertionWithoutAnIssuedAtWhenOptional",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				cl := f.createStandardClaim()
				cl.IssuedAt = nil
				f.handler.Config.(*oauth2.Config).GrantTypeJWTBearerIssuedDateOptional = true
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertion(cl, keyID))
			},
		},
		{
			name: "ShouldAcceptWhenClientAuthenticationMayBeSkipped",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				cl := f.createStandardClaim()
				f.requester.Client = &oauth2.DefaultClient{}
				f.handler.Config.(*oauth2.Config).GrantTypeJWTBearerCanSkipClientAuth = true
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertion(cl, keyID))
			},
		},
	}

	for _, store := range jwtBearerStores {
		t.Run(store.name, func(t *testing.T) {
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					f := newJWTBearerFixture(t, store.new())

					tc.setup(f)

					err := f.handler.HandleTokenEndpointRequest(f.ctx, f.requester)

					if tc.err == nil {
						require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
						assert.Equal(t, "local_ro", f.requester.GetSession().GetSubject())

						return
					}

					require.Error(t, err)
					assert.ErrorIs(t, err, tc.err)
					assert.Empty(t, f.requester.GetSession().GetSubject())

					if tc.hint != "" {
						assert.Equal(t, tc.hint, oauth2.ErrorToRFC6749Error(err).HintField)
					}

					if tc.expected != "" {
						assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.expected)
					}
				})
			}
		})
	}
}

func TestAuthorizeJWTGrantPopulateTokenEndpointResponse(t *testing.T) {
	testCases := []struct {
		name     string
		setup    func(f *jwtBearerFixture)
		err      error
		expected string
		hint     string
		check    func(t *testing.T, f *jwtBearerFixture)
	}{
		{
			name: "ShouldRejectAnInvalidGrantType",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeAuthorizationCode}
			},
			err:      oauth2.ErrUnknownRequest,
			expected: "The handler is not responsible for this request.",
		},
		{
			name: "ShouldRejectAClientNotRegisteredForTheGrantType",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				f.requester.Client = &oauth2.DefaultClient{GrantTypes: []string{consts.GrantTypeAuthorizationCode}}
				f.handler.Config.(*oauth2.Config).GrantTypeJWTBearerCanSkipClientAuth = false
			},
			err:      oauth2.ErrUnauthorizedClient,
			expected: "The client is not authorized to request a token using this method. The OAuth 2.0 Client is not allowed to use authorization grant 'urn:ietf:params:oauth:grant-type:jwt-bearer'.",
		},
		{
			name: "ShouldIssueAnAccessTokenWithTheHandlerLifespan",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				cl := f.createStandardClaim()
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertion(cl, keyID))
				f.mockAccessTokenStrategy.EXPECT().GenerateAccessToken(f.ctx, f.requester).Return(token, sig, nil)
			},
			check: func(t *testing.T, f *jwtBearerFixture) {
				assert.Equal(t, token, f.responder.AccessToken)
				assert.Equal(t, oauth2.BearerAccessToken, f.responder.TokenType)
				assert.Equal(t, int64(f.handler.HandleHelper.Config.GetAccessTokenLifespan(f.ctx).Seconds()), f.responder.GetExtra(consts.AccessResponseExpiresIn))
				assert.Nil(t, f.responder.GetExtra(consts.AccessResponseScope))
				assert.Nil(t, f.responder.GetExtra(consts.AccessResponseRefreshToken))
			},
		},
		{
			name: "ShouldIssueAnAccessTokenWithTheClientCustomLifespan",
			setup: func(f *jwtBearerFixture) {
				f.requester.Client = &oauth2.DefaultClientWithCustomTokenLifespans{
					DefaultClient: &oauth2.DefaultClient{
						GrantTypes: []string{consts.GrantTypeOAuthJWTBearer},
					},
					TokenLifespans: &internal.TestLifespans,
				}
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				cl := f.createStandardClaim()
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertion(cl, keyID))
				f.mockAccessTokenStrategy.EXPECT().GenerateAccessToken(f.ctx, f.requester).Return(token, sig, nil)
			},
			check: func(t *testing.T, f *jwtBearerFixture) {
				assert.Equal(t, token, f.responder.AccessToken)
				assert.Equal(t, oauth2.BearerAccessToken, f.responder.TokenType)
				assert.Equal(t, int64(internal.TestLifespans.JwtBearerGrantAccessTokenLifespan.Seconds()), f.responder.GetExtra(consts.AccessResponseExpiresIn))
				assert.Nil(t, f.responder.GetExtra(consts.AccessResponseScope))
				assert.Nil(t, f.responder.GetExtra(consts.AccessResponseRefreshToken))
			},
		},
		{
			name: "ShouldIssueAnAccessTokenWithoutMarkingAnAssertionWithNoJTI",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				cl := f.createStandardClaim()
				cl.ID = ""
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertion(cl, keyID))
				f.mockAccessTokenStrategy.EXPECT().GenerateAccessToken(f.ctx, f.requester).Return(token, sig, nil)
			},
			check: func(t *testing.T, f *jwtBearerFixture) {
				assert.Equal(t, token, f.responder.AccessToken)
			},
		},
		{
			name: "ShouldRejectAnAssertionMarkedUsedByAConcurrentRequest",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				cl := f.createStandardClaim()
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertion(cl, keyID))
				require.NoError(f.t, f.store.MarkRFC7523JWTUsedForTime(f.ctx, cl.Issuer, cl.ID, cl.Expiry.Time()))
			},
			err:  oauth2.ErrInvalidGrant,
			hint: hintRedeemed,
		},
		{
			name: "ShouldRejectAnAssertionThatCanNotBeParsed",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				f.requester.Form.Add(consts.FormParameterAssertion, "not-a-jwt")
			},
			err:  oauth2.ErrInvalidGrant,
			hint: "Unable to parse the JWT authorization grant.",
		},
	}

	for _, store := range jwtBearerStores {
		t.Run(store.name, func(t *testing.T) {
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					f := newJWTBearerFixture(t, store.new())

					tc.setup(f)

					err := f.handler.PopulateTokenEndpointResponse(f.ctx, f.requester, f.responder)

					if tc.err != nil {
						require.Error(t, err)
						assert.ErrorIs(t, err, tc.err)

						if tc.hint != "" {
							assert.Equal(t, tc.hint, oauth2.ErrorToRFC6749Error(err).HintField)
						}

						if tc.expected != "" {
							assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.expected)
						}

						return
					}

					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

					tc.check(t, f)
				})
			}
		})
	}

	t.Run("ShouldRejectWhenMarkingTheJWTUsedFails", func(t *testing.T) {
		f := newJWTBearerMockFixture(t)

		f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
		cl := f.createStandardClaim()
		f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertion(cl, keyID))
		f.mockStore.EXPECT().MarkRFC7523JWTUsedForTime(f.ctx, cl.Issuer, cl.ID, cl.Expiry.Time()).Return(oauth2.ErrServerError)

		assert.ErrorIs(t, f.handler.PopulateTokenEndpointResponse(f.ctx, f.requester, f.responder), oauth2.ErrServerError)
	})
}

func TestAuthorizeJWTGrantAudience(t *testing.T) {
	testCases := []struct {
		name     string
		setup    func(f *jwtBearerFixture)
		issuer   bool
		audience []string
		resource []string
		err      string
	}{
		{
			name:   "ShouldNotGrantTheAssertionAudience",
			issuer: true,
		},
		{
			name:   "ShouldGrantARequestedAudienceTheIssuerHas",
			issuer: true,
			setup: func(f *jwtBearerFixture) {
				f.requester.SetRequestedAudience(oauth2.Arguments{"https://leela.example.com"})
			},
			audience: []string{"https://leela.example.com"},
		},
		{
			name:   "ShouldGrantARequestedResourceTheIssuerHas",
			issuer: true,
			setup: func(f *jwtBearerFixture) {
				f.requester.SetRequestedResource(oauth2.Arguments{"https://leela.example.com"})
			},
			resource: []string{"https://leela.example.com"},
		},
		{
			name:   "ShouldRejectARequestedAudienceTheIssuerDoesNotHave",
			issuer: true,
			setup: func(f *jwtBearerFixture) {
				f.requester.SetRequestedAudience(oauth2.Arguments{"https://fry.example.com"})
			},
			err: "The requested resource is invalid, missing, unknown, or malformed. Ensure the requested resource is an absolute URI without a fragment component that identifies a resource server known to the authorization server and that it is permitted for this client. Requested audience 'https://fry.example.com' has not been whitelisted by the OAuth 2.0 Client.",
		},
		{
			name:   "ShouldRejectARequestedResourceTheIssuerDoesNotHave",
			issuer: true,
			setup: func(f *jwtBearerFixture) {
				f.requester.SetRequestedResource(oauth2.Arguments{"https://fry.example.com"})
			},
			err: "The requested resource is invalid, missing, unknown, or malformed. Ensure the requested resource is an absolute URI without a fragment component that identifies a resource server known to the authorization server and that it is permitted for this client. Requested audience 'https://fry.example.com' has not been whitelisted by the OAuth 2.0 Client.",
		},
		{
			name:   "ShouldRejectARequestedAudienceOnlyTheClientHas",
			issuer: true,
			setup: func(f *jwtBearerFixture) {
				f.requester.Client = &oauth2.DefaultClient{ID: "foo", GrantTypes: []string{consts.GrantTypeOAuthJWTBearer}, Audience: []string{"https://fry.example.com"}}
				f.requester.SetRequestedAudience(oauth2.Arguments{"https://fry.example.com"})
			},
			err: "The requested resource is invalid, missing, unknown, or malformed. Ensure the requested resource is an absolute URI without a fragment component that identifies a resource server known to the authorization server and that it is permitted for this client. Requested audience 'https://fry.example.com' has not been whitelisted by the OAuth 2.0 Client.",
		},
		{
			name:   "ShouldRejectARequestedResourceOnlyALooseResourceStrategyMatches",
			issuer: true,
			setup: func(f *jwtBearerFixture) {
				f.handler.Config.(*oauth2.Config).ResourceStrategy = oauth2.DefaultResourceStrategy
				f.requester.SetRequestedResource(oauth2.Arguments{"https://leela.example.com/admin"})
			},
			err: "The requested resource is invalid, missing, unknown, or malformed. Ensure the requested resource is an absolute URI without a fragment component that identifies a resource server known to the authorization server and that it is permitted for this client. Requested audience 'https://leela.example.com/admin' has not been whitelisted by the OAuth 2.0 Client.",
		},
		{
			name:   "ShouldRejectARequestedAudienceOnlyALooseAudienceStrategyMatches",
			issuer: true,
			setup: func(f *jwtBearerFixture) {
				f.handler.Config.(*oauth2.Config).AudienceStrategy = func(_, _ []string) error { return nil }
				f.requester.SetRequestedAudience(oauth2.Arguments{"https://fry.example.com"})
			},
			err: "The requested resource is invalid, missing, unknown, or malformed. Ensure the requested resource is an absolute URI without a fragment component that identifies a resource server known to the authorization server and that it is permitted for this client. Requested audience 'https://fry.example.com' has not been whitelisted by the OAuth 2.0 Client.",
		},
		{
			name:   "ShouldGrantARegisteredResourceWithALooseResourceStrategy",
			issuer: true,
			setup: func(f *jwtBearerFixture) {
				f.handler.Config.(*oauth2.Config).ResourceStrategy = oauth2.DefaultResourceStrategy
				f.requester.SetRequestedResource(oauth2.Arguments{"https://leela.example.com"})
			},
			resource: []string{"https://leela.example.com"},
		},
		{
			name:   "ShouldRejectARegisteredAudienceTheConfiguredStrategyRejects",
			issuer: true,
			setup: func(f *jwtBearerFixture) {
				f.handler.Config.(*oauth2.Config).AudienceStrategy = func(_, _ []string) error {
					return oauth2.ErrInvalidTarget.WithDebug("The configured strategy rejected the audience.")
				}
				f.requester.SetRequestedAudience(oauth2.Arguments{"https://leela.example.com"})
			},
			err: "The requested resource is invalid, missing, unknown, or malformed. Ensure the requested resource is an absolute URI without a fragment component that identifies a resource server known to the authorization server and that it is permitted for this client. The configured strategy rejected the audience.",
		},
		{
			name: "ShouldRejectARequestedAudienceWhenTheIssuerHasNone",
			setup: func(f *jwtBearerFixture) {
				f.requester.SetRequestedAudience(oauth2.Arguments{"https://leela.example.com"})
			},
			err: "The requested resource is invalid, missing, unknown, or malformed. Ensure the requested resource is an absolute URI without a fragment component that identifies a resource server known to the authorization server and that it is permitted for this client. Requested audience 'https://leela.example.com' has not been whitelisted by the OAuth 2.0 Client.",
		},
	}

	for _, store := range jwtBearerStores {
		t.Run(store.name, func(t *testing.T) {
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					f := newJWTBearerFixture(t, store.new())
					f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}

					if tc.issuer {
						f.trust(func(trusted *oauth2.RFC7523TrustedIssuer) { trusted.Audience = []string{"https://leela.example.com"} })
					}

					if tc.setup != nil {
						tc.setup(f)
					}

					f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertion(f.createStandardClaim(), keyID))

					err := f.handler.HandleTokenEndpointRequest(f.ctx, f.requester)

					if tc.err != "" {
						require.ErrorIs(t, err, oauth2.ErrInvalidTarget)
						assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.err)

						return
					}

					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
					assert.ElementsMatch(t, tc.audience, f.requester.GetGrantedAudience())
					assert.ElementsMatch(t, tc.resource, f.requester.GetGrantedResource())
				})
			}
		})
	}
}

// See: https://datatracker.ietf.org/doc/html/draft-parecki-oauth-jwt-dpop-grant-02#section-5.2
func TestAuthorizeJWTGrantConfirmation(t *testing.T) {
	testCases := []struct {
		name string
		cnf  any
	}{
		{name: "ShouldRejectAJWKThumbprint", cnf: map[string]any{consts.ClaimConfirmationJWKThumbprint: "thumbprint"}},
		{name: "ShouldRejectACertificateThumbprint", cnf: map[string]any{consts.ClaimConfirmationX509SHA256Thumbprint: "certificate"}},
		{name: "ShouldRejectAnUnknownMethod", cnf: map[string]any{"jwk": map[string]any{}}},
		{name: "ShouldRejectAnEmptyConfirmation", cnf: map[string]any{}},
		{name: "ShouldRejectANullConfirmation", cnf: nil},
	}

	for _, store := range jwtBearerStores {
		t.Run(store.name, func(t *testing.T) {
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					f := newJWTBearerFixture(t, store.new())

					f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
					f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertionWithClaims(f.createStandardClaim(), map[string]any{consts.ClaimConfirmation: tc.cnf}, keyID))

					require.ErrorIs(t, f.handler.HandleTokenEndpointRequest(f.ctx, f.requester), oauth2.ErrInvalidGrant)
					assert.Empty(t, f.requester.GetSession().GetSubject())
				})
			}
		})
	}
}

type fixtureStore interface {
	Storage
	hoauth2.AccessTokenStorage
}

var jwtBearerStores = []struct {
	name string
	new  func() fixtureStore
}{
	{name: "MemoryStore", new: func() fixtureStore { return storage.NewMemoryStore() }},
	{name: "HydratingMemoryStore", new: func() fixtureStore { return storage.NewHydratingMemoryStore() }},
}

func newJWTBearerFixture(t *testing.T, store fixtureStore) *jwtBearerFixture {
	t.Helper()

	f := newJWTBearerBaseFixture(t)

	f.store = store

	switch s := store.(type) {
	case *storage.MemoryStore:
		f.memory = s
	case *storage.HydratingMemoryStore:
		f.memory = s.MemoryStore
	default:
		require.FailNow(t, "unsupported store")
	}

	f.memory.RFC7523TrustedIssuers[testTrustedIssuer] = f.createTrustedIssuer()
	f.memory.RFC7523Subjects[storage.RFC7523SubjectKey{Issuer: testTrustedIssuer, Subject: "some_ro"}] = "local_ro"

	f.handler.Storage = store
	f.handler.AccessTokenStorage = store

	return f
}

func newJWTBearerMockFixture(t *testing.T) *jwtBearerFixture {
	t.Helper()

	f := newJWTBearerBaseFixture(t)

	ctrl := gomock.NewController(t)

	f.mockStore = mock.NewMockRFC7523Storage(ctrl)
	f.mockAccessTokenStore = mock.NewMockAccessTokenStorage(ctrl)

	f.handler.Storage = f.mockStore
	f.handler.AccessTokenStorage = f.mockAccessTokenStore

	return f
}

func newJWTBearerBaseFixture(t *testing.T) *jwtBearerFixture {
	t.Helper()

	f := &jwtBearerFixture{
		t:                       t,
		ctx:                     t.Context(),
		privateKey:              jwtBearerKey,
		mockAccessTokenStrategy: mock.NewMockAccessTokenStrategy(gomock.NewController(t)),
		responder:               oauth2.NewAccessResponse(),
	}

	f.requester = oauth2.NewAccessRequest(new(oauth2.DefaultSession))
	f.requester.Form = url.Values{}
	f.requester.Client = &oauth2.DefaultClient{GrantTypes: []string{consts.GrantTypeOAuthJWTBearer}}

	f.handler = &Handler{
		Config: &oauth2.Config{
			ScopeStrategy:                        oauth2.HierarchicScopeStrategy,
			AudienceStrategy:                     oauth2.DefaultAudienceStrategy,
			AllowedJWTAssertionAudiences:         []string{"https://www.example.com/token"},
			GrantTypeJWTBearerCanSkipClientAuth:  false,
			GrantTypeJWTBearerIDOptional:         false,
			GrantTypeJWTBearerIssuedDateOptional: false,
			GrantTypeJWTBearerMaxDuration:        time.Hour * 24 * 30,
		},
		HandleHelper: &hoauth2.HandleHelper{
			AccessTokenStrategy: f.mockAccessTokenStrategy,
			Config: &oauth2.Config{
				AccessTokenLifespan: time.Hour,
			},
		},
	}

	return f
}

type jwtBearerFixture struct {
	t                       *testing.T
	ctx                     context.Context
	privateKey              *rsa.PrivateKey
	store                   fixtureStore
	memory                  *storage.MemoryStore
	mockStore               *mock.MockRFC7523Storage
	mockAccessTokenStrategy *mock.MockAccessTokenStrategy
	mockAccessTokenStore    *mock.MockAccessTokenStorage
	requester               *oauth2.AccessRequest
	responder               *oauth2.AccessResponse
	handler                 *Handler
}

func (f *jwtBearerFixture) createTrustedIssuer() oauth2.RFC7523TrustedIssuer {
	return oauth2.RFC7523TrustedIssuer{
		Issuer:      testTrustedIssuer,
		JSONWebKeys: f.createJWS(f.createJWK(f.privateKey.Public(), keyID)),
		SigningAlgs: []string{string(jose.RS256)},
		Scopes:      []string{"valid_scope"},
	}
}

func (f *jwtBearerFixture) trust(mutate func(trusted *oauth2.RFC7523TrustedIssuer)) {
	trusted := f.memory.RFC7523TrustedIssuers[testTrustedIssuer]

	mutate(&trusted)

	f.memory.RFC7523TrustedIssuers[testTrustedIssuer] = trusted
}

func (f *jwtBearerFixture) createTestAssertion(cl jwt.Claims, keyID string) string {
	return f.createTestAssertionWithType(cl, keyID, "JWT")
}

func (f *jwtBearerFixture) createTestAssertionWithType(cl jwt.Claims, keyID, typ string) string {
	return f.sign(cl, nil, keyID, typ)
}

func (f *jwtBearerFixture) createTestAssertionWithClaims(cl jwt.Claims, extra map[string]any, keyID string) string {
	return f.sign(cl, extra, keyID, "JWT")
}

func (f *jwtBearerFixture) sign(cl jwt.Claims, extra map[string]any, keyID, typ string) string {
	jwk := jose.JSONWebKey{Key: f.privateKey, KeyID: keyID, Algorithm: string(jose.RS256)}

	opts := &jose.SignerOptions{}
	if typ != "" {
		opts = opts.WithType(jose.ContentType(typ))
	}

	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jwk}, opts)
	if err != nil {
		panic(fmt.Sprintf("failed to create signer: %s", err))
	}

	builder := jwt.Signed(sig).Claims(cl)
	if extra != nil {
		builder = builder.Claims(extra)
	}

	raw, err := builder.Serialize()
	if err != nil {
		panic(fmt.Sprintf("failed to sign assertion: %s", err))
	}

	return raw
}

func (f *jwtBearerFixture) createStandardClaim() jwt.Claims {
	return jwt.Claims{
		Issuer:    testTrustedIssuer,
		Subject:   "some_ro",
		Audience:  jwt.Audience{"https://www.example.com/token", "leela", "fry"},
		Expiry:    jwt.NewNumericDate(time.Now().AddDate(0, 0, 10)),
		NotBefore: nil,
		IssuedAt:  jwt.NewNumericDate(time.Now().AddDate(0, 0, -7)),
		ID:        "my_token",
	}
}

func (f *jwtBearerFixture) createRandomTestJWK() jose.JSONWebKey {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(fmt.Sprintf("failed to generate RSA private key: %s", err))
	}

	return f.createJWK(privateKey.Public(), strconv.Itoa(mrand.Int()))
}

func (f *jwtBearerFixture) createJWK(key any, keyID string) jose.JSONWebKey {
	return jose.JSONWebKey{
		Key:       key,
		KeyID:     keyID,
		Algorithm: string(jose.RS256),
		Use:       consts.JSONWebTokenUseSignature,
	}
}

func (f *jwtBearerFixture) createJWS(keys ...jose.JSONWebKey) *jose.JSONWebKeySet {
	return &jose.JSONWebKeySet{Keys: keys}
}

var jwtBearerKey = func() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	return key
}()
