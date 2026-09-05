// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7523

import (
	"context"
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

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/internal"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/testing/mock"
	"authelia.com/provider/oauth2/token/jose"
	"authelia.com/provider/oauth2/token/jose/jwt"
)

func TestAuthorizeJWTGrantRequestHandler(t *testing.T) {
	testCases := []struct {
		name     string
		setup    func(f *jwtBearerFixture)
		err      error
		expected string
		pattern  string
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
			err:      oauth2.ErrInvalidGrant,
			expected: "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. Unable to parse JSON Web Token passed in 'assertion' request parameter. go-jose/go-jose: compact JWS format must have three parts",
		},
		{
			name: "ShouldRejectAnAssertionWithoutAnIssuer",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				cl := f.createStandardClaim()
				cl.Issuer = ""
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertion(cl, keyID))
			},
			err:      oauth2.ErrInvalidGrant,
			expected: "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. The JWT in 'assertion' request parameter MUST contain an 'iss' (issuer) claim.",
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
			name: "ShouldRejectWhenNoPublicKeyIsRegistered",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				cl := f.createStandardClaim()
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertion(cl, keyID))
				f.mockStore.EXPECT().GetRFC7523PublicKey(f.ctx, cl.Issuer, cl.Subject, keyID).Return(nil, oauth2.ErrNotFound)
			},
			err:      oauth2.ErrInvalidGrant,
			expected: "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. No public JWK was registered for issuer 'trusted_issuer' and subject 'some_ro', and public key is required to check signature of JWT in 'assertion' request parameter. Could not find the requested resource(s).",
		},
		{
			name: "ShouldRejectWhenNoPublicKeysAreRegistered",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				keyID := "" // provide no hint of what key was used to sign assertion
				cl := f.createStandardClaim()
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertion(cl, keyID))
				f.mockStore.EXPECT().GetRFC7523PublicKeys(f.ctx, cl.Issuer, cl.Subject).Return(nil, oauth2.ErrNotFound)
			},
			err:      oauth2.ErrInvalidGrant,
			expected: "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. No public JWK was registered for issuer 'trusted_issuer' and subject 'some_ro', and public key is required to check signature of JWT in 'assertion' request parameter. Could not find the requested resource(s).",
		},
		{
			name: "ShouldRejectWhenThePublicKeyDoesNotVerify",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				keyID := "wrong_key"
				cl := f.createStandardClaim()
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertion(cl, keyID))
				jwk := f.createRandomTestJWK()
				f.mockStore.EXPECT().GetRFC7523PublicKey(f.ctx, cl.Issuer, cl.Subject, keyID).Return(&jwk, nil)
			},
			err:      oauth2.ErrInvalidGrant,
			expected: "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. Unable to verify the integrity of the 'assertion' value. go-jose/go-jose: error in cryptographic primitive",
		},
		{
			name: "ShouldRejectWhenNoneOfThePublicKeysVerify",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				keyID := "" // provide no hint of what key was used to sign assertion
				cl := f.createStandardClaim()
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertion(cl, keyID))
				f.mockStore.EXPECT().GetRFC7523PublicKeys(f.ctx, cl.Issuer, cl.Subject).Return(f.createJWS(f.createRandomTestJWK(), f.createRandomTestJWK()), nil)
			},
			err:      oauth2.ErrInvalidGrant,
			expected: "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. No public JWK was registered for issuer 'trusted_issuer' and subject 'some_ro', and public key is required to check signature of JWT in 'assertion' request parameter.",
		},
		{
			name: "ShouldRejectAnAssertionWithoutAnAudience",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				pubKey := f.createJWK(f.privateKey.Public(), keyID)
				cl := f.createStandardClaim()
				cl.Audience = []string{}
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertion(cl, keyID))
				f.mockStore.EXPECT().GetRFC7523PublicKey(f.ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)
			},
			err:      oauth2.ErrInvalidGrant,
			expected: "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. The JWT in 'assertion' request parameter MUST contain an 'aud' (audience) claim.",
		},
		{
			name: "ShouldRejectAnAssertionAudiencedElsewhere",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				pubKey := f.createJWK(f.privateKey.Public(), keyID)
				cl := f.createStandardClaim()
				cl.Audience = jwt.Audience{"leela", "fry"}
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertion(cl, keyID))
				f.mockStore.EXPECT().GetRFC7523PublicKey(f.ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)
			},
			err:      oauth2.ErrInvalidGrant,
			expected: "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. The JWT in 'assertion' request parameter MUST contain an 'aud' (audience) claim containing a value 'https://www.example.com/token' that identifies the authorization server as an intended audience.",
		},
		{
			name: "ShouldRejectAnAssertionWithoutAnExpiry",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				pubKey := f.createJWK(f.privateKey.Public(), keyID)
				cl := f.createStandardClaim()
				cl.Expiry = nil
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertion(cl, keyID))
				f.mockStore.EXPECT().GetRFC7523PublicKey(f.ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)
			},
			err:      oauth2.ErrInvalidGrant,
			expected: "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. The JWT in 'assertion' request parameter MUST contain an 'exp' (expiration time) claim.",
		},
		{
			name: "ShouldRejectAnExpiredAssertion",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				pubKey := f.createJWK(f.privateKey.Public(), keyID)
				cl := f.createStandardClaim()
				cl.Expiry = jwt.NewNumericDate(time.Now().AddDate(0, -1, 0))
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertion(cl, keyID))
				f.mockStore.EXPECT().GetRFC7523PublicKey(f.ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)
			},
			err:      oauth2.ErrInvalidGrant,
			expected: "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. The JWT provided in the 'assertion' request parameter is expired.",
		},
		{
			name: "ShouldRejectAnAssertionBeforeItsNotBeforeDate",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				pubKey := f.createJWK(f.privateKey.Public(), keyID)
				nbf := time.Now().AddDate(0, 1, 0)
				cl := f.createStandardClaim()
				cl.NotBefore = jwt.NewNumericDate(nbf)
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertion(cl, keyID))
				f.mockStore.EXPECT().GetRFC7523PublicKey(f.ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)
			},
			err:     oauth2.ErrInvalidGrant,
			pattern: `^The\ provided\ authorization\ grant\ \(e\.g\.,\ authorization\ code,\ resource\ owner\ credentials\)\ or\ refresh\ token\ is\ invalid,\ expired,\ revoked,\ does\ not\ match\ the\ redirection\ URI\ used\ in\ the\ authorization\ request,\ or\ was\ issued\ to\ another\ client\. The JWT in 'assertion' request parameter contains an 'nbf' \(not before\) claim, that identifies the time '[^']+' before which the token MUST NOT be accepted\.$`,
		},
		{
			name: "ShouldRejectAnAssertionWithoutARequiredIssuedAt",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				pubKey := f.createJWK(f.privateKey.Public(), keyID)
				cl := f.createStandardClaim()
				cl.IssuedAt = nil
				f.handler.Config.(*oauth2.Config).GrantTypeJWTBearerIssuedDateOptional = false
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertion(cl, keyID))
				f.mockStore.EXPECT().GetRFC7523PublicKey(f.ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)
			},
			err:      oauth2.ErrInvalidGrant,
			expected: "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. The JWT in 'assertion' request parameter MUST contain an 'iat' (issued at) claim.",
		},
		{
			name: "ShouldAcceptAnAssertionWithNoTypeHeader",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				pubKey := f.createJWK(f.privateKey.Public(), keyID)
				cl := f.createStandardClaim()
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertionWithType(cl, keyID, ""))
				f.mockStore.EXPECT().GetRFC7523PublicKey(f.ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)
				f.mockStore.EXPECT().IsRFC7523JWTUsed(f.ctx, cl.Issuer, cl.ID).Return(false, nil)
				f.mockStore.EXPECT().GetRFC7523PublicKeyScopes(f.ctx, cl.Issuer, cl.Subject, keyID).Return([]string{"valid_scope"}, nil)
				f.mockStore.EXPECT().MarkRFC7523JWTUsedForTime(f.ctx, cl.Issuer, cl.ID, cl.Expiry.Time()).Return(nil)
			},
		},
		{
			name: "ShouldAcceptAnApplicationJWTTypeHeader",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				pubKey := f.createJWK(f.privateKey.Public(), keyID)
				cl := f.createStandardClaim()
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertionWithType(cl, keyID, "application/jwt"))
				f.mockStore.EXPECT().GetRFC7523PublicKey(f.ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)
				f.mockStore.EXPECT().IsRFC7523JWTUsed(f.ctx, cl.Issuer, cl.ID).Return(false, nil)
				f.mockStore.EXPECT().GetRFC7523PublicKeyScopes(f.ctx, cl.Issuer, cl.Subject, keyID).Return([]string{"valid_scope"}, nil)
				f.mockStore.EXPECT().MarkRFC7523JWTUsedForTime(f.ctx, cl.Issuer, cl.ID, cl.Expiry.Time()).Return(nil)
			},
		},
		{
			name: "ShouldAcceptALowercaseJWTTypeHeader",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				pubKey := f.createJWK(f.privateKey.Public(), keyID)
				cl := f.createStandardClaim()
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertionWithType(cl, keyID, "jwt"))
				f.mockStore.EXPECT().GetRFC7523PublicKey(f.ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)
				f.mockStore.EXPECT().IsRFC7523JWTUsed(f.ctx, cl.Issuer, cl.ID).Return(false, nil)
				f.mockStore.EXPECT().GetRFC7523PublicKeyScopes(f.ctx, cl.Issuer, cl.Subject, keyID).Return([]string{"valid_scope"}, nil)
				f.mockStore.EXPECT().MarkRFC7523JWTUsedForTime(f.ctx, cl.Issuer, cl.ID, cl.Expiry.Time()).Return(nil)
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
				pubKey := f.createJWK(f.privateKey.Public(), keyID)
				issuedAt := time.Now().Add(2 * time.Hour)
				cl := f.createStandardClaim()
				cl.IssuedAt = jwt.NewNumericDate(issuedAt)
				cl.Expiry = jwt.NewNumericDate(issuedAt.Add(30 * time.Minute))
				f.handler.Config.(*oauth2.Config).GrantTypeJWTBearerIssuedDateOptional = false
				f.handler.Config.(*oauth2.Config).GrantTypeJWTBearerMaxDuration = time.Hour * 24
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertion(cl, keyID))
				f.mockStore.EXPECT().GetRFC7523PublicKey(f.ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)
			},
			err:     oauth2.ErrInvalidGrant,
			pattern: `^The\ provided\ authorization\ grant\ \(e\.g\.,\ authorization\ code,\ resource\ owner\ credentials\)\ or\ refresh\ token\ is\ invalid,\ expired,\ revoked,\ does\ not\ match\ the\ redirection\ URI\ used\ in\ the\ authorization\ request,\ or\ was\ issued\ to\ another\ client\. The JWT in 'assertion' request parameter contains an 'iat' \(issued at\) claim, that identifies the time '[^']+' which is after the current time$`,
		},
		{
			name: "ShouldRejectAnIssuedAtFarInThePast",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				pubKey := f.createJWK(f.privateKey.Public(), keyID)
				issuedAt := time.Now().AddDate(0, 0, -31)
				cl := f.createStandardClaim()
				cl.IssuedAt = jwt.NewNumericDate(issuedAt)
				f.handler.Config.(*oauth2.Config).GrantTypeJWTBearerIssuedDateOptional = false
				f.handler.Config.(*oauth2.Config).GrantTypeJWTBearerMaxDuration = time.Hour * 24 * 30
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertion(cl, keyID))
				f.mockStore.EXPECT().GetRFC7523PublicKey(f.ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)
			},
			err:     oauth2.ErrInvalidGrant,
			pattern: `^The\ provided\ authorization\ grant\ \(e\.g\.,\ authorization\ code,\ resource\ owner\ credentials\)\ or\ refresh\ token\ is\ invalid,\ expired,\ revoked,\ does\ not\ match\ the\ redirection\ URI\ used\ in\ the\ authorization\ request,\ or\ was\ issued\ to\ another\ client\. The JWT in 'assertion' request parameter contains an 'exp' \(expiration time\) claim with value '[^']+' that is unreasonably far in the future, considering token issued at '[^']+'\.$`,
		},
		{
			name: "ShouldRejectAnExpiryFarInTheFuture",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				pubKey := f.createJWK(f.privateKey.Public(), keyID)
				cl := f.createStandardClaim()
				cl.IssuedAt = jwt.NewNumericDate(time.Now().AddDate(0, 0, -15))
				cl.Expiry = jwt.NewNumericDate(time.Now().AddDate(0, 0, 20))
				f.handler.Config.(*oauth2.Config).GrantTypeJWTBearerIssuedDateOptional = false
				f.handler.Config.(*oauth2.Config).GrantTypeJWTBearerMaxDuration = time.Hour * 24 * 30
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertion(cl, keyID))
				f.mockStore.EXPECT().GetRFC7523PublicKey(f.ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)
			},
			err:     oauth2.ErrInvalidGrant,
			pattern: `^The\ provided\ authorization\ grant\ \(e\.g\.,\ authorization\ code,\ resource\ owner\ credentials\)\ or\ refresh\ token\ is\ invalid,\ expired,\ revoked,\ does\ not\ match\ the\ redirection\ URI\ used\ in\ the\ authorization\ request,\ or\ was\ issued\ to\ another\ client\. The JWT in 'assertion' request parameter contains an 'exp' \(expiration time\) claim with value '[^']+' that is unreasonably far in the future, considering token issued at '[^']+'\.$`,
		},
		{
			name: "ShouldRejectAnExpiryFarInTheFutureWithNoIssuedAt",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				pubKey := f.createJWK(f.privateKey.Public(), keyID)
				cl := f.createStandardClaim()
				cl.IssuedAt = nil
				cl.Expiry = jwt.NewNumericDate(time.Now().AddDate(0, 0, 31))
				f.handler.Config.(*oauth2.Config).GrantTypeJWTBearerIssuedDateOptional = true
				f.handler.Config.(*oauth2.Config).GrantTypeJWTBearerMaxDuration = time.Hour * 24 * 30
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertion(cl, keyID))
				f.mockStore.EXPECT().GetRFC7523PublicKey(f.ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)
			},
			err:     oauth2.ErrInvalidGrant,
			pattern: `^The provided authorization grant \(e\.g\., authorization code, resource owner credentials\) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client\. The JWT in 'assertion' request parameter contains an 'exp' \(expiration time\) claim with value '[^']+' that is unreasonably far in the future, considering token issued at '[^']+'\.$`,
		},
		{
			name: "ShouldRejectAnAssertionWithoutARequiredTokenID",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				pubKey := f.createJWK(f.privateKey.Public(), keyID)
				cl := f.createStandardClaim()
				cl.ID = ""
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertion(cl, keyID))
				f.mockStore.EXPECT().GetRFC7523PublicKey(f.ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)
			},
			err:      oauth2.ErrInvalidGrant,
			expected: "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. The JWT in 'assertion' request parameter MUST contain an 'jti' (JWT ID) claim.",
		},
		{
			name: "ShouldRejectAnAssertionAlreadyUsed",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				pubKey := f.createJWK(f.privateKey.Public(), keyID)
				cl := f.createStandardClaim()
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertion(cl, keyID))
				f.mockStore.EXPECT().GetRFC7523PublicKey(f.ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)
				f.mockStore.EXPECT().IsRFC7523JWTUsed(f.ctx, cl.Issuer, cl.ID).Return(true, nil)
			},
			err:      oauth2.ErrJTIKnown,
			expected: "The jti was already used.",
		},
		{
			name: "ShouldRejectWhenTheUsedCheckFails",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				pubKey := f.createJWK(f.privateKey.Public(), keyID)
				cl := f.createStandardClaim()
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertion(cl, keyID))
				f.mockStore.EXPECT().GetRFC7523PublicKey(f.ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)
				f.mockStore.EXPECT().IsRFC7523JWTUsed(f.ctx, cl.Issuer, cl.ID).Return(false, oauth2.ErrServerError)
			},
			err:      oauth2.ErrServerError,
			expected: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. The authorization server encountered an unexpected condition that prevented it from fulfilling the request.",
		},
		{
			name: "ShouldRejectWhenMarkingTheJWTUsedFails",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				pubKey := f.createJWK(f.privateKey.Public(), keyID)
				cl := f.createStandardClaim()
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertion(cl, keyID))
				f.mockStore.EXPECT().GetRFC7523PublicKey(f.ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)
				f.mockStore.EXPECT().GetRFC7523PublicKeyScopes(f.ctx, cl.Issuer, cl.Subject, keyID).Return([]string{"valid_scope"}, nil)
				f.mockStore.EXPECT().IsRFC7523JWTUsed(f.ctx, cl.Issuer, cl.ID).Return(false, nil)
				f.mockStore.EXPECT().MarkRFC7523JWTUsedForTime(f.ctx, cl.Issuer, cl.ID, cl.Expiry.Time()).Return(oauth2.ErrServerError)
			},
			err:      oauth2.ErrServerError,
			expected: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. The authorization server encountered an unexpected condition that prevented it from fulfilling the request.",
		},
		{
			name: "ShouldRejectWhenFetchingThePublicKeyScopesFails",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				pubKey := f.createJWK(f.privateKey.Public(), keyID)
				cl := f.createStandardClaim()
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertion(cl, keyID))
				f.mockStore.EXPECT().GetRFC7523PublicKey(f.ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)
				f.mockStore.EXPECT().GetRFC7523PublicKeyScopes(f.ctx, cl.Issuer, cl.Subject, keyID).Return([]string{}, oauth2.ErrServerError)
				f.mockStore.EXPECT().IsRFC7523JWTUsed(f.ctx, cl.Issuer, cl.ID).Return(false, nil)
			},
			err:      oauth2.ErrServerError,
			expected: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. The authorization server encountered an unexpected condition that prevented it from fulfilling the request.",
		},
		{
			name: "ShouldRejectScopesTheKeyIsNotGranted",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				pubKey := f.createJWK(f.privateKey.Public(), keyID)
				cl := f.createStandardClaim()
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertion(cl, keyID))
				f.requester.RequestedScope = []string{"some_scope"}
				f.mockStore.EXPECT().GetRFC7523PublicKey(f.ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)
				f.mockStore.EXPECT().GetRFC7523PublicKeyScopes(f.ctx, cl.Issuer, cl.Subject, keyID).Return([]string{"valid_scope"}, nil)
				f.mockStore.EXPECT().IsRFC7523JWTUsed(f.ctx, cl.Issuer, cl.ID).Return(false, nil)
			},
			err:      oauth2.ErrInvalidScope,
			expected: "The requested scope is invalid, unknown, or malformed. The public key registered for issuer 'trusted_issuer' and subject 'some_ro' is not allowed to request scope 'some_scope'.",
		},
		{
			name: "ShouldAcceptAValidAssertion",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				pubKey := f.createJWK(f.privateKey.Public(), keyID)
				cl := f.createStandardClaim()
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertion(cl, keyID))
				f.requester.RequestedScope = []string{"valid_scope"}
				f.mockStore.EXPECT().GetRFC7523PublicKey(f.ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)
				f.mockStore.EXPECT().GetRFC7523PublicKeyScopes(f.ctx, cl.Issuer, cl.Subject, keyID).Return([]string{"valid_scope", consts.ScopeOpenID}, nil)
				f.mockStore.EXPECT().IsRFC7523JWTUsed(f.ctx, cl.Issuer, cl.ID).Return(false, nil)
				f.mockStore.EXPECT().MarkRFC7523JWTUsedForTime(f.ctx, cl.Issuer, cl.ID, cl.Expiry.Time()).Return(nil)
			},
		},
		{
			name: "ShouldAcceptAValidAssertionWithNoScopesRequested",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				pubKey := f.createJWK(f.privateKey.Public(), keyID)
				cl := f.createStandardClaim()
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertion(cl, keyID))
				f.mockStore.EXPECT().GetRFC7523PublicKey(f.ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)
				f.mockStore.EXPECT().GetRFC7523PublicKeyScopes(f.ctx, cl.Issuer, cl.Subject, keyID).Return([]string{"valid_scope"}, nil)
				f.mockStore.EXPECT().IsRFC7523JWTUsed(f.ctx, cl.Issuer, cl.ID).Return(false, nil)
				f.mockStore.EXPECT().MarkRFC7523JWTUsedForTime(f.ctx, cl.Issuer, cl.ID, cl.Expiry.Time()).Return(nil)
			},
		},
		{
			name: "ShouldAcceptAnAssertionWithoutATokenIDWhenOptional",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				pubKey := f.createJWK(f.privateKey.Public(), keyID)
				cl := f.createStandardClaim()
				f.handler.Config.(*oauth2.Config).GrantTypeJWTBearerIDOptional = true
				cl.ID = ""
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertion(cl, keyID))
				f.mockStore.EXPECT().GetRFC7523PublicKey(f.ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)
				f.mockStore.EXPECT().GetRFC7523PublicKeyScopes(f.ctx, cl.Issuer, cl.Subject, keyID).Return([]string{"valid_scope"}, nil)
			},
		},
		{
			name: "ShouldAcceptAnAssertionWithoutAnIssuedAtWhenOptional",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				pubKey := f.createJWK(f.privateKey.Public(), keyID)
				cl := f.createStandardClaim()
				cl.IssuedAt = nil
				f.handler.Config.(*oauth2.Config).GrantTypeJWTBearerIssuedDateOptional = true
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertion(cl, keyID))
				f.mockStore.EXPECT().GetRFC7523PublicKey(f.ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)
				f.mockStore.EXPECT().GetRFC7523PublicKeyScopes(f.ctx, cl.Issuer, cl.Subject, keyID).Return([]string{"valid_scope"}, nil)
				f.mockStore.EXPECT().IsRFC7523JWTUsed(f.ctx, cl.Issuer, cl.ID).Return(false, nil)
				f.mockStore.EXPECT().MarkRFC7523JWTUsedForTime(f.ctx, cl.Issuer, cl.ID, cl.Expiry.Time()).Return(nil)
			},
		},
		{
			name: "ShouldAcceptWhenClientAuthenticationMayBeSkipped",
			setup: func(f *jwtBearerFixture) {
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				pubKey := f.createJWK(f.privateKey.Public(), keyID)
				cl := f.createStandardClaim()
				f.requester.Client = &oauth2.DefaultClient{}
				f.handler.Config.(*oauth2.Config).GrantTypeJWTBearerCanSkipClientAuth = true
				f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertion(cl, keyID))
				f.mockStore.EXPECT().GetRFC7523PublicKey(f.ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)
				f.mockStore.EXPECT().GetRFC7523PublicKeyScopes(f.ctx, cl.Issuer, cl.Subject, keyID).Return([]string{"valid_scope"}, nil)
				f.mockStore.EXPECT().IsRFC7523JWTUsed(f.ctx, cl.Issuer, cl.ID).Return(false, nil)
				f.mockStore.EXPECT().MarkRFC7523JWTUsedForTime(f.ctx, cl.Issuer, cl.ID, cl.Expiry.Time()).Return(nil)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := newJWTBearerFixture(t)

			tc.setup(f)

			err := f.handler.HandleTokenEndpointRequest(f.ctx, f.requester)

			if tc.err == nil {
				assert.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				return
			}

			require.Error(t, err)
			assert.ErrorIs(t, err, tc.err)

			if tc.pattern != "" {
				assert.Regexp(t, tc.pattern, oauth2.ErrorToDebugRFC6749Error(err).Error())

				return
			}

			assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.expected)
		})
	}
}

func TestAuthorizeJWTGrantPopulateTokenEndpointResponse(t *testing.T) {
	testCases := []struct {
		name     string
		setup    func(f *jwtBearerFixture)
		err      error
		expected string
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
				f.mockAccessTokenStrategy.EXPECT().GenerateAccessToken(f.ctx, f.requester).Return(token, sig, nil)
				f.mockAccessTokenStore.EXPECT().CreateAccessTokenSession(f.ctx, sig, f.requester.Sanitize([]string{}))
			},
			check: func(t *testing.T, f *jwtBearerFixture) {
				assert.Equal(t, token, f.responder.AccessToken)
				assert.Equal(t, oauth2.BearerAccessToken, f.responder.TokenType)
				assert.Equal(t, int64(f.handler.HandleHelper.Config.GetAccessTokenLifespan(f.ctx).Seconds()), f.responder.GetExtra(consts.AccessResponseExpiresIn))
				assert.Equal(t, "", f.responder.GetExtra(consts.AccessResponseScope))
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
				f.mockAccessTokenStrategy.EXPECT().GenerateAccessToken(f.ctx, f.requester).Return(token, sig, nil)
				f.mockAccessTokenStore.EXPECT().CreateAccessTokenSession(f.ctx, sig, f.requester.Sanitize([]string{}))
			},
			check: func(t *testing.T, f *jwtBearerFixture) {
				assert.Equal(t, token, f.responder.AccessToken)
				assert.Equal(t, oauth2.BearerAccessToken, f.responder.TokenType)
				assert.Equal(t, int64(internal.TestLifespans.JwtBearerGrantAccessTokenLifespan.Seconds()), f.responder.GetExtra(consts.AccessResponseExpiresIn))
				assert.Equal(t, "", f.responder.GetExtra(consts.AccessResponseScope))
				assert.Nil(t, f.responder.GetExtra(consts.AccessResponseRefreshToken))
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := newJWTBearerFixture(t)

			tc.setup(f)

			err := f.handler.PopulateTokenEndpointResponse(f.ctx, f.requester, f.responder)

			if tc.err != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tc.err)
				assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.expected)

				return
			}

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

			tc.check(t, f)
		})
	}
}

// newJWTBearerFixture builds the mocks, requester and handler a single case runs against. gomock.NewController
// registers its own cleanup, so the controller is finished when the subtest ends.
func newJWTBearerFixture(t *testing.T) *jwtBearerFixture {
	t.Helper()

	ctrl := gomock.NewController(t)

	f := &jwtBearerFixture{
		ctx:                     t.Context(),
		privateKey:              jwtBearerKey,
		mockStore:               mock.NewMockRFC7523Storage(ctrl),
		mockAccessTokenStrategy: mock.NewMockAccessTokenStrategy(ctrl),
		mockAccessTokenStore:    mock.NewMockAccessTokenStorage(ctrl),
		responder:               oauth2.NewAccessResponse(),
	}

	f.requester = oauth2.NewAccessRequest(new(oauth2.DefaultSession))
	f.requester.Form = url.Values{}
	f.requester.Client = &oauth2.DefaultClient{GrantTypes: []string{consts.GrantTypeOAuthJWTBearer}}

	f.handler = &Handler{
		Storage: f.mockStore,
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
			AccessTokenStorage:  f.mockAccessTokenStore,
			Config: &oauth2.Config{
				AccessTokenLifespan: time.Hour,
			},
		},
	}

	return f
}

type jwtBearerFixture struct {
	ctx                     context.Context
	privateKey              *rsa.PrivateKey
	mockStore               *mock.MockRFC7523Storage
	mockAccessTokenStrategy *mock.MockAccessTokenStrategy
	mockAccessTokenStore    *mock.MockAccessTokenStorage
	requester               *oauth2.AccessRequest
	responder               *oauth2.AccessResponse
	handler                 *Handler
}

func (f *jwtBearerFixture) createTestAssertion(cl jwt.Claims, keyID string) string {
	return f.createTestAssertionWithType(cl, keyID, "JWT")
}

// createTestAssertionWithType signs as createTestAssertion does, with a caller-chosen 'typ' header; "" omits it.
func (f *jwtBearerFixture) createTestAssertionWithType(cl jwt.Claims, keyID, typ string) string {
	jwk := jose.JSONWebKey{Key: f.privateKey, KeyID: keyID, Algorithm: string(jose.RS256)}

	opts := &jose.SignerOptions{}
	if typ != "" {
		opts = opts.WithType(jose.ContentType(typ))
	}

	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jwk}, opts)
	if err != nil {
		panic(fmt.Sprintf("failed to create signer: %s", err))
	}

	raw, err := jwt.Signed(sig).Claims(cl).Serialize()
	if err != nil {
		panic(fmt.Sprintf("failed to sign assertion: %s", err))
	}

	return raw
}

func (f *jwtBearerFixture) createStandardClaim() jwt.Claims {
	return jwt.Claims{
		Issuer:    "trusted_issuer",
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

	return f.createJWK(privateKey.Public(), strconv.Itoa(mrand.Int())) //nolint:gosec
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

// jwtBearerKey is generated once because RSA generation dominates the runtime of these cases.
var jwtBearerKey = func() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	return key
}()
