// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7523

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	mrand "math/rand"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/testing/mock"
)

func TestAuthorizeJWTGrantRequestHandlerTestSuite(t *testing.T) {
	suite.Run(t, new(AuthorizeJWTGrantRequestHandlerTestSuite))
}

type AuthorizeJWTGrantRequestHandlerTestSuite struct {
	suite.Suite

	privateKey              *rsa.PrivateKey
	mockCtrl                *gomock.Controller
	mockStore               *mock.MockRFC7523Storage
	mockAccessTokenStrategy *mock.MockAccessTokenStrategy
	mockAccessTokenStore    *mock.MockAccessTokenStorage
	requester               *oauth2.AccessRequest
	handler                 *Handler
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) SetupSuite() {
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec
	if err != nil {
		s.FailNowf("failed to setup test suite", "failed to generate RSA private key: %s", err.Error())
	}
	s.privateKey = privateKey
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) SetupTest() {
	s.mockCtrl = gomock.NewController(s.T())
	s.mockStore = mock.NewMockRFC7523Storage(s.mockCtrl)
	s.mockAccessTokenStrategy = mock.NewMockAccessTokenStrategy(s.mockCtrl)
	s.mockAccessTokenStore = mock.NewMockAccessTokenStorage(s.mockCtrl)
	s.requester = oauth2.NewAccessRequest(new(oauth2.DefaultSession))
	s.requester.Form = url.Values{}
	s.requester.Client = &oauth2.DefaultClient{GrantTypes: []string{consts.GrantTypeOAuthJWTBearer}}
	s.handler = &Handler{
		Storage: s.mockStore,
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
			AccessTokenStrategy: s.mockAccessTokenStrategy,
			AccessTokenStorage:  s.mockAccessTokenStore,
			Config: &oauth2.Config{
				AccessTokenLifespan: time.Hour,
			},
		},
	}
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TearDownTest() {
	s.mockCtrl.Finish()
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestRequestWithInvalidGrantType() {
	s.requester.GrantTypes = []string{consts.GrantTypeAuthorizationCode}

	err := s.handler.HandleTokenEndpointRequest(context.Background(), s.requester)

	s.True(errors.Is(err, oauth2.ErrUnknownRequest))
	s.EqualError(err, oauth2.ErrUnknownRequest.Error(), "expected error, because of invalid grant type")
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestClientIsNotRegisteredForGrantType() {
	s.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
	s.requester.Client = &oauth2.DefaultClient{GrantTypes: []string{consts.GrantTypeAuthorizationCode}}
	s.handler.Config.(*oauth2.Config).GrantTypeJWTBearerCanSkipClientAuth = false

	err := s.handler.HandleTokenEndpointRequest(context.Background(), s.requester)

	s.True(errors.Is(err, oauth2.ErrUnauthorizedClient))
	s.EqualError(err, oauth2.ErrUnauthorizedClient.Error(), "expected error, because client is not registered to use this grant type")
	s.Equal(
		"The OAuth 2.0 Client is not allowed to use authorization grant 'urn:ietf:params:oauth:grant-type:jwt-bearer'.",
		oauth2.ErrorToRFC6749Error(err).HintField,
	)
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestRequestWithoutAssertion() {
	s.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}

	err := s.handler.HandleTokenEndpointRequest(context.Background(), s.requester)

	s.True(errors.Is(err, oauth2.ErrInvalidRequest))
	s.EqualError(err, oauth2.ErrInvalidRequest.Error(), "expected error, because of missing assertion")
	s.Equal(
		"The assertion request parameter must be set when using grant_type of 'urn:ietf:params:oauth:grant-type:jwt-bearer'.",
		oauth2.ErrorToRFC6749Error(err).HintField,
	)
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestRequestWithMalformedAssertion() {
	s.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
	s.requester.Form.Add(consts.FormParameterAssertion, "fjigjgfkjgkf")

	err := s.handler.HandleTokenEndpointRequest(context.Background(), s.requester)

	s.True(errors.Is(err, oauth2.ErrInvalidGrant))
	s.EqualError(err, oauth2.ErrInvalidGrant.Error(), "expected error, because of malformed assertion")
	s.Equal(
		"Unable to parse JSON Web Token passed in 'assertion' request parameter.",
		oauth2.ErrorToRFC6749Error(err).HintField,
	)
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestRequestAssertionWithoutIssuer() {
	s.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
	cl := s.createStandardClaim()
	cl.Issuer = ""
	s.requester.Form.Add(consts.FormParameterAssertion, s.createTestAssertion(cl, keyID))

	err := s.handler.HandleTokenEndpointRequest(context.Background(), s.requester)

	s.True(errors.Is(err, oauth2.ErrInvalidGrant))
	s.EqualError(err, oauth2.ErrInvalidGrant.Error(), "expected error, because of missing issuer claim in assertion")
	s.Equal(
		"The JWT in 'assertion' request parameter MUST contain an 'iss' (issuer) claim.",
		oauth2.ErrorToRFC6749Error(err).HintField,
	)
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestRequestAssertionWithoutSubject() {
	s.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
	cl := s.createStandardClaim()
	cl.Subject = ""
	s.requester.Form.Add(consts.FormParameterAssertion, s.createTestAssertion(cl, keyID))

	err := s.handler.HandleTokenEndpointRequest(context.Background(), s.requester)

	s.True(errors.Is(err, oauth2.ErrInvalidGrant))
	s.EqualError(err, oauth2.ErrInvalidGrant.Error(), "expected error, because of missing subject claim in assertion")
	s.Equal(
		"The JWT in 'assertion' request parameter MUST contain a 'sub' (subject) claim.",
		oauth2.ErrorToRFC6749Error(err).HintField,
	)
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestNoMatchingPublicKeyToCheckAssertionSignature() {
	ctx := context.Background()
	s.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
	cl := s.createStandardClaim()
	s.requester.Form.Add(consts.FormParameterAssertion, s.createTestAssertion(cl, keyID))
	s.mockStore.EXPECT().GetRFC7523PublicKey(ctx, cl.Issuer, cl.Subject, keyID).Return(nil, oauth2.ErrNotFound)

	err := s.handler.HandleTokenEndpointRequest(ctx, s.requester)

	s.True(errors.Is(err, oauth2.ErrInvalidGrant))
	s.EqualError(err, oauth2.ErrInvalidGrant.Error(), "expected error, because of missing public key to check assertion")
	s.Equal(
		fmt.Sprintf(
			"No public JWK was registered for issuer '%s' and subject '%s', and public key is required to check signature of JWT in 'assertion' request parameter.",
			cl.Issuer, cl.Subject,
		),
		oauth2.ErrorToRFC6749Error(err).HintField,
	)
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestNoMatchingPublicKeysToCheckAssertionSignature() {
	ctx := context.Background()
	s.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
	keyID := "" // provide no hint of what key was used to sign assertion
	cl := s.createStandardClaim()
	s.requester.Form.Add(consts.FormParameterAssertion, s.createTestAssertion(cl, keyID))
	s.mockStore.EXPECT().GetRFC7523PublicKeys(ctx, cl.Issuer, cl.Subject).Return(nil, oauth2.ErrNotFound)

	err := s.handler.HandleTokenEndpointRequest(ctx, s.requester)

	s.True(errors.Is(err, oauth2.ErrInvalidGrant))
	s.EqualError(err, oauth2.ErrInvalidGrant.Error(), "expected error, because of missing public keys to check assertion")
	s.Equal(
		fmt.Sprintf(
			"No public JWK was registered for issuer '%s' and subject '%s', and public key is required to check signature of JWT in 'assertion' request parameter.",
			cl.Issuer, cl.Subject,
		),
		oauth2.ErrorToRFC6749Error(err).HintField,
	)
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestWrongPublicKeyToCheckAssertionSignature() {
	ctx := context.Background()
	s.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
	keyID := "wrong_key"
	cl := s.createStandardClaim()
	s.requester.Form.Add(consts.FormParameterAssertion, s.createTestAssertion(cl, keyID))
	jwk := s.createRandomTestJWK()
	s.mockStore.EXPECT().GetRFC7523PublicKey(ctx, cl.Issuer, cl.Subject, keyID).Return(&jwk, nil)

	err := s.handler.HandleTokenEndpointRequest(ctx, s.requester)

	s.True(errors.Is(err, oauth2.ErrInvalidGrant))
	s.EqualError(err, oauth2.ErrInvalidGrant.Error(), "expected error, because wrong public key was registered for assertion")
	s.Equal("Unable to verify the integrity of the 'assertion' value.", oauth2.ErrorToRFC6749Error(err).HintField)
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestWrongPublicKeysToCheckAssertionSignature() {
	ctx := context.Background()
	s.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
	keyID := "" // provide no hint of what key was used to sign assertion
	cl := s.createStandardClaim()
	s.requester.Form.Add(consts.FormParameterAssertion, s.createTestAssertion(cl, keyID))
	s.mockStore.EXPECT().GetRFC7523PublicKeys(ctx, cl.Issuer, cl.Subject).Return(s.createJWS(s.createRandomTestJWK(), s.createRandomTestJWK()), nil)

	err := s.handler.HandleTokenEndpointRequest(ctx, s.requester)

	s.True(errors.Is(err, oauth2.ErrInvalidGrant))
	s.EqualError(err, oauth2.ErrInvalidGrant.Error(), "expected error, because wrong public keys was registered for assertion")
	s.Equal(
		fmt.Sprintf(
			"No public JWK was registered for issuer '%s' and subject '%s', and public key is required to check signature of JWT in 'assertion' request parameter.",
			cl.Issuer, cl.Subject,
		),
		oauth2.ErrorToRFC6749Error(err).HintField,
	)
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestNoAudienceInAssertion() {
	ctx := context.Background()
	s.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
	pubKey := s.createJWK(s.privateKey.Public(), keyID)
	cl := s.createStandardClaim()
	cl.Audience = []string{}
	s.requester.Form.Add(consts.FormParameterAssertion, s.createTestAssertion(cl, keyID))
	s.mockStore.EXPECT().GetRFC7523PublicKey(ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)

	err := s.handler.HandleTokenEndpointRequest(ctx, s.requester)

	s.True(errors.Is(err, oauth2.ErrInvalidGrant))
	s.EqualError(err, oauth2.ErrInvalidGrant.Error(), "expected error, because of missing audience claim in assertion")
	s.Equal(
		"The JWT in 'assertion' request parameter MUST contain an 'aud' (audience) claim.",
		oauth2.ErrorToRFC6749Error(err).HintField,
	)
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestNotValidAudienceInAssertion() {
	ctx := context.Background()
	s.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
	pubKey := s.createJWK(s.privateKey.Public(), keyID)
	cl := s.createStandardClaim()
	cl.Audience = jwt.Audience{"leela", "fry"}
	s.requester.Form.Add(consts.FormParameterAssertion, s.createTestAssertion(cl, keyID))
	s.mockStore.EXPECT().GetRFC7523PublicKey(ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)

	err := s.handler.HandleTokenEndpointRequest(ctx, s.requester)

	s.True(errors.Is(err, oauth2.ErrInvalidGrant))
	s.EqualError(err, oauth2.ErrInvalidGrant.Error(), "expected error, because of invalid audience claim in assertion")
	s.Equal(
		fmt.Sprintf(
			"The JWT in 'assertion' request parameter MUST contain an 'aud' (audience) claim containing a value '%s' that identifies the authorization server as an intended audience.",
			strings.Join(s.handler.Config.GetAllowedJWTAssertionAudiences(ctx), "', '"),
		),
		oauth2.ErrorToRFC6749Error(err).HintField,
	)
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestNoExpirationInAssertion() {
	ctx := context.Background()
	s.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
	pubKey := s.createJWK(s.privateKey.Public(), keyID)
	cl := s.createStandardClaim()
	cl.Expiry = nil
	s.requester.Form.Add(consts.FormParameterAssertion, s.createTestAssertion(cl, keyID))
	s.mockStore.EXPECT().GetRFC7523PublicKey(ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)

	err := s.handler.HandleTokenEndpointRequest(ctx, s.requester)

	s.True(errors.Is(err, oauth2.ErrInvalidGrant))
	s.EqualError(err, oauth2.ErrInvalidGrant.Error(), "expected error, because of missing expiration claim in assertion")
	s.Equal(
		"The JWT in 'assertion' request parameter MUST contain an 'exp' (expiration time) claim.",
		oauth2.ErrorToRFC6749Error(err).HintField,
	)
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestExpiredAssertion() {
	ctx := context.Background()
	s.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
	pubKey := s.createJWK(s.privateKey.Public(), keyID)
	cl := s.createStandardClaim()
	cl.Expiry = jwt.NewNumericDate(time.Now().AddDate(0, -1, 0))
	s.requester.Form.Add(consts.FormParameterAssertion, s.createTestAssertion(cl, keyID))
	s.mockStore.EXPECT().GetRFC7523PublicKey(ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)

	err := s.handler.HandleTokenEndpointRequest(ctx, s.requester)

	s.True(errors.Is(err, oauth2.ErrInvalidGrant))
	s.EqualError(err, oauth2.ErrInvalidGrant.Error(), "expected error, because assertion expired")
	s.Equal(
		"The JWT provided in the 'assertion' request parameter is expired.",
		oauth2.ErrorToRFC6749Error(err).HintField,
	)
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestAssertionNotAcceptedBeforeDate() {
	ctx := context.Background()
	s.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
	pubKey := s.createJWK(s.privateKey.Public(), keyID)
	nbf := time.Now().AddDate(0, 1, 0)
	cl := s.createStandardClaim()
	cl.NotBefore = jwt.NewNumericDate(nbf)
	s.requester.Form.Add(consts.FormParameterAssertion, s.createTestAssertion(cl, keyID))
	s.mockStore.EXPECT().GetRFC7523PublicKey(ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)

	err := s.handler.HandleTokenEndpointRequest(ctx, s.requester)

	s.True(errors.Is(err, oauth2.ErrInvalidGrant))
	s.EqualError(err, oauth2.ErrInvalidGrant.Error(), "expected error, nbf claim in assertion indicates, that assertion can not be accepted now")
	s.Equal(
		fmt.Sprintf(
			"The JWT in 'assertion' request parameter contains an 'nbf' (not before) claim, that identifies the time '%s' before which the token MUST NOT be accepted.",
			nbf.Format(time.RFC3339),
		),
		oauth2.ErrorToRFC6749Error(err).HintField,
	)
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestAssertionWithoutRequiredIssueDate() {
	ctx := context.Background()
	s.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
	pubKey := s.createJWK(s.privateKey.Public(), keyID)
	cl := s.createStandardClaim()
	cl.IssuedAt = nil
	s.handler.Config.(*oauth2.Config).GrantTypeJWTBearerIssuedDateOptional = false
	s.requester.Form.Add(consts.FormParameterAssertion, s.createTestAssertion(cl, keyID))
	s.mockStore.EXPECT().GetRFC7523PublicKey(ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)

	err := s.handler.HandleTokenEndpointRequest(ctx, s.requester)

	s.True(errors.Is(err, oauth2.ErrInvalidGrant))
	s.EqualError(err, oauth2.ErrInvalidGrant.Error(), "expected error, because of missing iat claim in assertion")
	s.Equal(
		"The JWT in 'assertion' request parameter MUST contain an 'iat' (issued at) claim.",
		oauth2.ErrorToRFC6749Error(err).HintField,
	)
}

// RFC 7519 §5.1: the 'typ' header is RECOMMENDED but not required, so an assertion without one is accepted.
func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestAssertionTypeHeaderAbsent() {
	ctx := context.Background()
	s.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
	pubKey := s.createJWK(s.privateKey.Public(), keyID)
	cl := s.createStandardClaim()

	s.requester.Form.Add(consts.FormParameterAssertion, s.createTestAssertionWithType(cl, keyID, ""))
	s.mockStore.EXPECT().GetRFC7523PublicKey(ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)
	s.mockStore.EXPECT().IsRFC7523JWTUsed(ctx, cl.Issuer, cl.ID).Return(false, nil)
	s.mockStore.EXPECT().GetRFC7523PublicKeyScopes(ctx, cl.Issuer, cl.Subject, keyID).Return([]string{"valid_scope"}, nil)
	s.mockStore.EXPECT().MarkRFC7523JWTUsedForTime(ctx, cl.Issuer, cl.ID, cl.Expiry.Time()).Return(nil)

	err := s.handler.HandleTokenEndpointRequest(ctx, s.requester)

	s.NoError(err, "no error expected, an absent 'typ' header is allowed per RFC 7519 §5.1")
}

// RFC 8725 §3.11: 'application/jwt' is equivalent to 'JWT', since RFC 6838 media-type names are
// case-insensitive.
func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestAssertionTypeHeaderApplicationJWT() {
	ctx := context.Background()
	s.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
	pubKey := s.createJWK(s.privateKey.Public(), keyID)
	cl := s.createStandardClaim()
	s.requester.Form.Add(consts.FormParameterAssertion, s.createTestAssertionWithType(cl, keyID, "application/jwt"))
	s.mockStore.EXPECT().GetRFC7523PublicKey(ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)
	s.mockStore.EXPECT().IsRFC7523JWTUsed(ctx, cl.Issuer, cl.ID).Return(false, nil)
	s.mockStore.EXPECT().GetRFC7523PublicKeyScopes(ctx, cl.Issuer, cl.Subject, keyID).Return([]string{"valid_scope"}, nil)
	s.mockStore.EXPECT().MarkRFC7523JWTUsedForTime(ctx, cl.Issuer, cl.ID, cl.Expiry.Time()).Return(nil)

	err := s.handler.HandleTokenEndpointRequest(ctx, s.requester)

	s.NoError(err, "no error expected, 'application/jwt' is equivalent to 'JWT'")
}

// RFC 6838: media-type names are case-insensitive.
func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestAssertionTypeHeaderLowercaseJWT() {
	ctx := context.Background()
	s.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
	pubKey := s.createJWK(s.privateKey.Public(), keyID)
	cl := s.createStandardClaim()
	s.requester.Form.Add(consts.FormParameterAssertion, s.createTestAssertionWithType(cl, keyID, "jwt"))
	s.mockStore.EXPECT().GetRFC7523PublicKey(ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)
	s.mockStore.EXPECT().IsRFC7523JWTUsed(ctx, cl.Issuer, cl.ID).Return(false, nil)
	s.mockStore.EXPECT().GetRFC7523PublicKeyScopes(ctx, cl.Issuer, cl.Subject, keyID).Return([]string{"valid_scope"}, nil)
	s.mockStore.EXPECT().MarkRFC7523JWTUsedForTime(ctx, cl.Issuer, cl.ID, cl.Expiry.Time()).Return(nil)

	err := s.handler.HandleTokenEndpointRequest(ctx, s.requester)

	s.NoError(err, "no error expected, 'typ' header comparison is case-insensitive")
}

// RFC 8725 §3.11: a 'typ' identifying a different JWT profile, such as a DPoP proof or a secevent, MUST NOT
// be accepted as an authorization-grant assertion.
func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestAssertionTypeHeaderNonJWTRejected() {
	ctx := context.Background()
	s.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
	cl := s.createStandardClaim()
	s.requester.Form.Add(consts.FormParameterAssertion, s.createTestAssertionWithType(cl, keyID, consts.JSONWebTokenTypeDPoP))

	err := s.handler.HandleTokenEndpointRequest(ctx, s.requester)

	s.True(errors.Is(err, oauth2.ErrInvalidGrant))
	s.EqualError(err, oauth2.ErrInvalidGrant.Error(), "expected error, because 'typ' header is not 'JWT'")
	s.Equal(
		"The JWT in 'assertion' request parameter has an invalid 'typ' header value 'dpop+jwt'; expected 'JWT'.",
		oauth2.ErrorToRFC6749Error(err).HintField,
	)
}

// RFC 7519 §4.1.6: 'iat' identifies the time at which the JWT was issued, so any value at or after now is
// invalid. The check is '!iat.Before(now)', symmetric with the nbf check, rejecting both 'iat == now' and
// 'iat > now'.
func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestAssertionWithIssueDateInFuture() {
	ctx := context.Background()
	s.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
	pubKey := s.createJWK(s.privateKey.Public(), keyID)
	issuedAt := time.Now().Add(2 * time.Hour)
	cl := s.createStandardClaim()
	cl.IssuedAt = jwt.NewNumericDate(issuedAt)
	cl.Expiry = jwt.NewNumericDate(issuedAt.Add(30 * time.Minute))
	s.handler.Config.(*oauth2.Config).GrantTypeJWTBearerIssuedDateOptional = false
	s.handler.Config.(*oauth2.Config).GrantTypeJWTBearerMaxDuration = time.Hour * 24
	s.requester.Form.Add(consts.FormParameterAssertion, s.createTestAssertion(cl, keyID))
	s.mockStore.EXPECT().GetRFC7523PublicKey(ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)

	err := s.handler.HandleTokenEndpointRequest(ctx, s.requester)

	s.True(errors.Is(err, oauth2.ErrInvalidGrant))
	s.EqualError(err, oauth2.ErrInvalidGrant.Error(), "expected error, because assertion 'iat' claim is in the future")
	s.Equal(
		fmt.Sprintf(
			"The JWT in 'assertion' request parameter contains an 'iat' (issued at) claim, that identifies the time '%s' which is after the current time",
			cl.IssuedAt.Time().Format(time.RFC3339),
		),
		oauth2.ErrorToRFC6749Error(err).HintField,
	)
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestAssertionWithIssueDateFarInPast() {
	ctx := context.Background()
	s.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
	pubKey := s.createJWK(s.privateKey.Public(), keyID)
	issuedAt := time.Now().AddDate(0, 0, -31)
	cl := s.createStandardClaim()
	cl.IssuedAt = jwt.NewNumericDate(issuedAt)
	s.handler.Config.(*oauth2.Config).GrantTypeJWTBearerIssuedDateOptional = false
	s.handler.Config.(*oauth2.Config).GrantTypeJWTBearerMaxDuration = time.Hour * 24 * 30
	s.requester.Form.Add(consts.FormParameterAssertion, s.createTestAssertion(cl, keyID))
	s.mockStore.EXPECT().GetRFC7523PublicKey(ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)

	err := s.handler.HandleTokenEndpointRequest(ctx, s.requester)

	s.True(errors.Is(err, oauth2.ErrInvalidGrant))
	s.EqualError(err, oauth2.ErrInvalidGrant.Error(), "expected error, because assertion was issued far in the past")
	s.Equal(
		fmt.Sprintf(
			"The JWT in 'assertion' request parameter contains an 'exp' (expiration time) claim with value '%s' that is unreasonably far in the future, considering token issued at '%s'.",
			cl.Expiry.Time().Format(time.RFC3339),
			cl.IssuedAt.Time().Format(time.RFC3339),
		),
		oauth2.ErrorToRFC6749Error(err).HintField,
	)
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestAssertionWithExpirationDateFarInFuture() {
	ctx := context.Background()
	s.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
	pubKey := s.createJWK(s.privateKey.Public(), keyID)
	cl := s.createStandardClaim()
	cl.IssuedAt = jwt.NewNumericDate(time.Now().AddDate(0, 0, -15))
	cl.Expiry = jwt.NewNumericDate(time.Now().AddDate(0, 0, 20))
	s.handler.Config.(*oauth2.Config).GrantTypeJWTBearerIssuedDateOptional = false
	s.handler.Config.(*oauth2.Config).GrantTypeJWTBearerMaxDuration = time.Hour * 24 * 30
	s.requester.Form.Add(consts.FormParameterAssertion, s.createTestAssertion(cl, keyID))
	s.mockStore.EXPECT().GetRFC7523PublicKey(ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)

	err := s.handler.HandleTokenEndpointRequest(ctx, s.requester)

	s.True(errors.Is(err, oauth2.ErrInvalidGrant))
	s.EqualError(err, oauth2.ErrInvalidGrant.Error(), "expected error, because assertion will expire unreasonably far in the future.")
	s.Equal(
		fmt.Sprintf(
			"The JWT in 'assertion' request parameter contains an 'exp' (expiration time) claim with value '%s' that is unreasonably far in the future, considering token issued at '%s'.",
			cl.Expiry.Time().Format(time.RFC3339),
			cl.IssuedAt.Time().Format(time.RFC3339),
		),
		oauth2.ErrorToRFC6749Error(err).HintField,
	)
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestAssertionWithExpirationDateFarInFutureWithNoIssuerDate() {
	ctx := context.Background()
	s.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
	pubKey := s.createJWK(s.privateKey.Public(), keyID)
	cl := s.createStandardClaim()
	cl.IssuedAt = nil
	cl.Expiry = jwt.NewNumericDate(time.Now().AddDate(0, 0, 31))
	s.handler.Config.(*oauth2.Config).GrantTypeJWTBearerIssuedDateOptional = true
	s.handler.Config.(*oauth2.Config).GrantTypeJWTBearerMaxDuration = time.Hour * 24 * 30
	s.requester.Form.Add(consts.FormParameterAssertion, s.createTestAssertion(cl, keyID))
	s.mockStore.EXPECT().GetRFC7523PublicKey(ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)

	err := s.handler.HandleTokenEndpointRequest(ctx, s.requester)

	s.True(errors.Is(err, oauth2.ErrInvalidGrant))
	s.EqualError(err, oauth2.ErrInvalidGrant.Error(), "expected error, because assertion will expire unreasonably far in the future.")
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestAssertionWithoutRequiredTokenID() {
	ctx := context.Background()
	s.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
	pubKey := s.createJWK(s.privateKey.Public(), keyID)
	cl := s.createStandardClaim()
	cl.ID = ""
	s.requester.Form.Add(consts.FormParameterAssertion, s.createTestAssertion(cl, keyID))
	s.mockStore.EXPECT().GetRFC7523PublicKey(ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)

	err := s.handler.HandleTokenEndpointRequest(ctx, s.requester)

	s.True(errors.Is(err, oauth2.ErrInvalidGrant))
	s.EqualError(err, oauth2.ErrInvalidGrant.Error(), "expected error, because of missing jti claim in assertion")
	s.Equal(
		"The JWT in 'assertion' request parameter MUST contain an 'jti' (JWT ID) claim.",
		oauth2.ErrorToRFC6749Error(err).HintField,
	)
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestAssertionAlreadyUsed() {
	ctx := context.Background()
	s.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
	pubKey := s.createJWK(s.privateKey.Public(), keyID)
	cl := s.createStandardClaim()
	s.requester.Form.Add(consts.FormParameterAssertion, s.createTestAssertion(cl, keyID))
	s.mockStore.EXPECT().GetRFC7523PublicKey(ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)
	s.mockStore.EXPECT().IsRFC7523JWTUsed(ctx, cl.Issuer, cl.ID).Return(true, nil)

	err := s.handler.HandleTokenEndpointRequest(ctx, s.requester)

	s.True(errors.Is(err, oauth2.ErrJTIKnown))
	s.EqualError(err, oauth2.ErrJTIKnown.Error(), "expected error, because assertion was used")
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestErrWhenCheckingIfJWTWasUsed() {
	ctx := context.Background()
	s.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
	pubKey := s.createJWK(s.privateKey.Public(), keyID)
	cl := s.createStandardClaim()
	s.requester.Form.Add(consts.FormParameterAssertion, s.createTestAssertion(cl, keyID))
	s.mockStore.EXPECT().GetRFC7523PublicKey(ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)
	s.mockStore.EXPECT().IsRFC7523JWTUsed(ctx, cl.Issuer, cl.ID).Return(false, oauth2.ErrServerError)

	err := s.handler.HandleTokenEndpointRequest(ctx, s.requester)

	s.True(errors.Is(err, oauth2.ErrServerError))
	s.EqualError(err, oauth2.ErrServerError.Error(), "expected error, because error occurred while trying to check if jwt was used")
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestErrWhenMarkingJWTAsUsed() {
	ctx := context.Background()
	s.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
	pubKey := s.createJWK(s.privateKey.Public(), keyID)
	cl := s.createStandardClaim()
	s.requester.Form.Add(consts.FormParameterAssertion, s.createTestAssertion(cl, keyID))
	s.mockStore.EXPECT().GetRFC7523PublicKey(ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)
	s.mockStore.EXPECT().GetRFC7523PublicKeyScopes(ctx, cl.Issuer, cl.Subject, keyID).Return([]string{"valid_scope"}, nil)
	s.mockStore.EXPECT().IsRFC7523JWTUsed(ctx, cl.Issuer, cl.ID).Return(false, nil)
	s.mockStore.EXPECT().MarkRFC7523JWTUsedForTime(ctx, cl.Issuer, cl.ID, cl.Expiry.Time()).Return(oauth2.ErrServerError)

	err := s.handler.HandleTokenEndpointRequest(ctx, s.requester)

	s.True(errors.Is(err, oauth2.ErrServerError))
	s.EqualError(err, oauth2.ErrServerError.Error(), "expected error, because error occurred while trying to mark jwt as used")
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestErrWhileFetchingPublicKeyScope() {
	ctx := context.Background()
	s.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
	pubKey := s.createJWK(s.privateKey.Public(), keyID)
	cl := s.createStandardClaim()

	s.requester.Form.Add(consts.FormParameterAssertion, s.createTestAssertion(cl, keyID))
	s.mockStore.EXPECT().GetRFC7523PublicKey(ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)
	s.mockStore.EXPECT().GetRFC7523PublicKeyScopes(ctx, cl.Issuer, cl.Subject, keyID).Return([]string{}, oauth2.ErrServerError)
	s.mockStore.EXPECT().IsRFC7523JWTUsed(ctx, cl.Issuer, cl.ID).Return(false, nil)

	err := s.handler.HandleTokenEndpointRequest(ctx, s.requester)

	s.True(errors.Is(err, oauth2.ErrServerError))
	s.EqualError(err, oauth2.ErrServerError.Error(), "expected error, because error occurred while fetching public key scopes")
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestAssertionWithInvalidScopes() {
	ctx := context.Background()
	s.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
	pubKey := s.createJWK(s.privateKey.Public(), keyID)
	cl := s.createStandardClaim()

	s.requester.Form.Add(consts.FormParameterAssertion, s.createTestAssertion(cl, keyID))
	s.requester.RequestedScope = []string{"some_scope"}
	s.mockStore.EXPECT().GetRFC7523PublicKey(ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)
	s.mockStore.EXPECT().GetRFC7523PublicKeyScopes(ctx, cl.Issuer, cl.Subject, keyID).Return([]string{"valid_scope"}, nil)
	s.mockStore.EXPECT().IsRFC7523JWTUsed(ctx, cl.Issuer, cl.ID).Return(false, nil)

	err := s.handler.HandleTokenEndpointRequest(ctx, s.requester)

	s.True(errors.Is(err, oauth2.ErrInvalidScope))
	s.EqualError(err, oauth2.ErrInvalidScope.Error(), "expected error, because requested scopes don't match allowed scope for this assertion")
	s.Equal(
		"The public key registered for issuer 'trusted_issuer' and subject 'some_ro' is not allowed to request scope 'some_scope'.",
		oauth2.ErrorToRFC6749Error(err).HintField,
	)
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestValidAssertion() {
	ctx := context.Background()
	s.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
	pubKey := s.createJWK(s.privateKey.Public(), keyID)
	cl := s.createStandardClaim()

	s.requester.Form.Add(consts.FormParameterAssertion, s.createTestAssertion(cl, keyID))
	s.requester.RequestedScope = []string{"valid_scope"}
	s.mockStore.EXPECT().GetRFC7523PublicKey(ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)
	s.mockStore.EXPECT().GetRFC7523PublicKeyScopes(ctx, cl.Issuer, cl.Subject, keyID).Return([]string{"valid_scope", consts.ScopeOpenID}, nil)
	s.mockStore.EXPECT().IsRFC7523JWTUsed(ctx, cl.Issuer, cl.ID).Return(false, nil)
	s.mockStore.EXPECT().MarkRFC7523JWTUsedForTime(ctx, cl.Issuer, cl.ID, cl.Expiry.Time()).Return(nil)

	err := s.handler.HandleTokenEndpointRequest(ctx, s.requester)

	s.NoError(err, "no error expected, because assertion must be valid")
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestAssertionIsValidWhenNoScopesPassed() {
	ctx := context.Background()
	s.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
	pubKey := s.createJWK(s.privateKey.Public(), keyID)
	cl := s.createStandardClaim()
	s.requester.Form.Add(consts.FormParameterAssertion, s.createTestAssertion(cl, keyID))
	s.mockStore.EXPECT().GetRFC7523PublicKey(ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)
	s.mockStore.EXPECT().GetRFC7523PublicKeyScopes(ctx, cl.Issuer, cl.Subject, keyID).Return([]string{"valid_scope"}, nil)
	s.mockStore.EXPECT().IsRFC7523JWTUsed(ctx, cl.Issuer, cl.ID).Return(false, nil)
	s.mockStore.EXPECT().MarkRFC7523JWTUsedForTime(ctx, cl.Issuer, cl.ID, cl.Expiry.Time()).Return(nil)

	err := s.handler.HandleTokenEndpointRequest(ctx, s.requester)

	s.NoError(err, "no error expected, because assertion must be valid")
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestAssertionIsValidWhenJWTIDIsOptional() {
	ctx := context.Background()
	s.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
	pubKey := s.createJWK(s.privateKey.Public(), keyID)
	cl := s.createStandardClaim()
	s.handler.Config.(*oauth2.Config).GrantTypeJWTBearerIDOptional = true
	cl.ID = ""
	s.requester.Form.Add(consts.FormParameterAssertion, s.createTestAssertion(cl, keyID))
	s.mockStore.EXPECT().GetRFC7523PublicKey(ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)
	s.mockStore.EXPECT().GetRFC7523PublicKeyScopes(ctx, cl.Issuer, cl.Subject, keyID).Return([]string{"valid_scope"}, nil)

	err := s.handler.HandleTokenEndpointRequest(ctx, s.requester)

	s.NoError(err, "no error expected, because assertion must be valid, when no jti claim and it is allowed by option")
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestAssertionIsValidWhenJWTIssuedDateOptional() {
	ctx := context.Background()
	s.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
	pubKey := s.createJWK(s.privateKey.Public(), keyID)
	cl := s.createStandardClaim()
	cl.IssuedAt = nil
	s.handler.Config.(*oauth2.Config).GrantTypeJWTBearerIssuedDateOptional = true
	s.requester.Form.Add(consts.FormParameterAssertion, s.createTestAssertion(cl, keyID))
	s.mockStore.EXPECT().GetRFC7523PublicKey(ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)
	s.mockStore.EXPECT().GetRFC7523PublicKeyScopes(ctx, cl.Issuer, cl.Subject, keyID).Return([]string{"valid_scope"}, nil)
	s.mockStore.EXPECT().IsRFC7523JWTUsed(ctx, cl.Issuer, cl.ID).Return(false, nil)
	s.mockStore.EXPECT().MarkRFC7523JWTUsedForTime(ctx, cl.Issuer, cl.ID, cl.Expiry.Time()).Return(nil)

	err := s.handler.HandleTokenEndpointRequest(ctx, s.requester)

	s.NoError(err, "no error expected, because assertion must be valid, when no iss claim and it is allowed by option")
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestRequestIsValidWhenClientAuthOptional() {
	ctx := context.Background()
	s.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
	pubKey := s.createJWK(s.privateKey.Public(), keyID)
	cl := s.createStandardClaim()
	s.requester.Client = &oauth2.DefaultClient{}
	s.handler.Config.(*oauth2.Config).GrantTypeJWTBearerCanSkipClientAuth = true
	s.requester.Form.Add(consts.FormParameterAssertion, s.createTestAssertion(cl, keyID))
	s.mockStore.EXPECT().GetRFC7523PublicKey(ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)
	s.mockStore.EXPECT().GetRFC7523PublicKeyScopes(ctx, cl.Issuer, cl.Subject, keyID).Return([]string{"valid_scope"}, nil)
	s.mockStore.EXPECT().IsRFC7523JWTUsed(ctx, cl.Issuer, cl.ID).Return(false, nil)
	s.mockStore.EXPECT().MarkRFC7523JWTUsedForTime(ctx, cl.Issuer, cl.ID, cl.Expiry.Time()).Return(nil)

	err := s.handler.HandleTokenEndpointRequest(ctx, s.requester)

	s.NoError(err, "no error expected, because request must be valid, when no client unauthenticated and it is allowed by option")
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) createTestAssertion(cl jwt.Claims, keyID string) string {
	return s.createTestAssertionWithType(cl, keyID, "JWT")
}

// createTestAssertionWithType signs as createTestAssertion does but lets the caller choose the JOSE 'typ'
// header. Pass "" to omit the header entirely.
func (s *AuthorizeJWTGrantRequestHandlerTestSuite) createTestAssertionWithType(cl jwt.Claims, keyID, typ string) string {
	jwk := jose.JSONWebKey{Key: s.privateKey, KeyID: keyID, Algorithm: string(jose.RS256)}

	opts := &jose.SignerOptions{}
	if typ != "" {
		opts = opts.WithType(jose.ContentType(typ))
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jwk}, opts)
	if err != nil {
		s.FailNowf("failed to create test assertion", "failed to create signer: %s", err.Error())
	}

	raw, err := jwt.Signed(signer).Claims(cl).Serialize()
	if err != nil {
		s.FailNowf("failed to create test assertion", "failed to sign assertion: %s", err.Error())
	}

	return raw
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) createStandardClaim() jwt.Claims {
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

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) createRandomTestJWK() jose.JSONWebKey {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		s.FailNowf("failed to create random test JWK", "failed to generate RSA private key: %s", err.Error())
	}

	return s.createJWK(privateKey.Public(), strconv.Itoa(mrand.Int())) //nolint:gosec
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) createJWK(key any, keyID string) jose.JSONWebKey {
	return jose.JSONWebKey{
		Key:       key,
		KeyID:     keyID,
		Algorithm: string(jose.RS256),
		Use:       consts.JSONWebTokenUseSignature,
	}
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) createJWS(keys ...jose.JSONWebKey) *jose.JSONWebKeySet {
	return &jose.JSONWebKeySet{Keys: keys}
}
