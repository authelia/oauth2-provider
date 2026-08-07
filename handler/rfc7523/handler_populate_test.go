// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7523

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/internal"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/testing/mock"
)

func TestAuthorizeJWTGrantPopulateTokenEndpointTestSuite(t *testing.T) {
	suite.Run(t, new(AuthorizeJWTGrantPopulateTokenEndpointTestSuite))
}

type AuthorizeJWTGrantPopulateTokenEndpointTestSuite struct {
	suite.Suite

	mockCtrl                *gomock.Controller
	mockStore               *mock.MockRFC7523Storage
	mockAccessTokenStrategy *mock.MockAccessTokenStrategy
	mockAccessTokenStore    *mock.MockAccessTokenStorage
	requester               *oauth2.AccessRequest
	responder               *oauth2.AccessResponse
	handler                 *Handler
}

func (s *AuthorizeJWTGrantPopulateTokenEndpointTestSuite) SetupTest() {
	s.mockCtrl = gomock.NewController(s.T())
	s.mockStore = mock.NewMockRFC7523Storage(s.mockCtrl)
	s.mockAccessTokenStrategy = mock.NewMockAccessTokenStrategy(s.mockCtrl)
	s.mockAccessTokenStore = mock.NewMockAccessTokenStorage(s.mockCtrl)
	s.requester = oauth2.NewAccessRequest(new(oauth2.DefaultSession))
	s.requester.Form = url.Values{}
	s.requester.Client = &oauth2.DefaultClient{GrantTypes: []string{consts.GrantTypeOAuthJWTBearer}}
	s.responder = oauth2.NewAccessResponse()
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

func (s *AuthorizeJWTGrantPopulateTokenEndpointTestSuite) TearDownTest() {
	s.mockCtrl.Finish()
}

func (s *AuthorizeJWTGrantPopulateTokenEndpointTestSuite) TestRequestWithInvalidGrantType() {
	s.requester.GrantTypes = []string{consts.GrantTypeAuthorizationCode}

	err := s.handler.PopulateTokenEndpointResponse(context.Background(), s.requester, s.responder)

	s.True(errors.Is(err, oauth2.ErrUnknownRequest))
	s.EqualError(err, oauth2.ErrUnknownRequest.Error(), "expected error, because of invalid grant type")
}

func (s *AuthorizeJWTGrantPopulateTokenEndpointTestSuite) TestClientIsNotRegisteredForGrantType() {
	s.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
	s.requester.Client = &oauth2.DefaultClient{GrantTypes: []string{consts.GrantTypeAuthorizationCode}}
	s.handler.Config.(*oauth2.Config).GrantTypeJWTBearerCanSkipClientAuth = false

	err := s.handler.PopulateTokenEndpointResponse(context.Background(), s.requester, s.responder)

	s.True(errors.Is(err, oauth2.ErrUnauthorizedClient))
	s.EqualError(err, oauth2.ErrUnauthorizedClient.Error(), "expected error, because client is not registered to use this grant type")
	s.Equal(
		"The OAuth 2.0 Client is not allowed to use authorization grant 'urn:ietf:params:oauth:grant-type:jwt-bearer'.",
		oauth2.ErrorToRFC6749Error(err).HintField,
	)
}

func (s *AuthorizeJWTGrantPopulateTokenEndpointTestSuite) TestAccessTokenIssuedSuccessfully() {
	ctx := context.Background()
	s.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
	s.mockAccessTokenStrategy.EXPECT().GenerateAccessToken(ctx, s.requester).Return(token, sig, nil)
	s.mockAccessTokenStore.EXPECT().CreateAccessTokenSession(ctx, sig, s.requester.Sanitize([]string{}))

	err := s.handler.PopulateTokenEndpointResponse(context.Background(), s.requester, s.responder)

	s.NoError(err, "no error expected")
	s.Equal(s.responder.AccessToken, token, "access token expected in response")
	s.Equal(s.responder.TokenType, oauth2.BearerAccessToken, "token type expected to be 'bearer'")
	s.Equal(
		s.responder.GetExtra(consts.AccessResponseExpiresIn), int64(s.handler.HandleHelper.Config.GetAccessTokenLifespan(s.T().Context()).Seconds()),
		"token expiration time expected in response to be equal to AccessTokenLifespan setting in handler",
	)
	s.Equal(s.responder.GetExtra(consts.AccessResponseScope), "", "no scopes expected in response")
	s.Nil(s.responder.GetExtra(consts.AccessResponseRefreshToken), "refresh token not expected in response")
}

func (s *AuthorizeJWTGrantPopulateTokenEndpointTestSuite) TestAccessTokenIssuedSuccessfullyWithCustomLifespan() {
	s.requester.Client = &oauth2.DefaultClientWithCustomTokenLifespans{
		DefaultClient: &oauth2.DefaultClient{
			GrantTypes: []string{consts.GrantTypeOAuthJWTBearer},
		},
		TokenLifespans: &internal.TestLifespans,
	}
	ctx := context.Background()
	s.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
	s.mockAccessTokenStrategy.EXPECT().GenerateAccessToken(ctx, s.requester).Return(token, sig, nil)
	s.mockAccessTokenStore.EXPECT().CreateAccessTokenSession(ctx, sig, s.requester.Sanitize([]string{}))

	err := s.handler.PopulateTokenEndpointResponse(context.Background(), s.requester, s.responder)

	s.NoError(err, "no error expected")
	s.Equal(s.responder.AccessToken, token, "access token expected in response")
	s.Equal(s.responder.TokenType, oauth2.BearerAccessToken, "token type expected to be 'bearer'")
	s.Equal(
		s.responder.GetExtra(consts.AccessResponseExpiresIn), int64(internal.TestLifespans.JwtBearerGrantAccessTokenLifespan.Seconds()),
		"token expiration time expected in response to be equal to the pertinent AccessTokenLifespan setting in client",
	)
	s.Equal(s.responder.GetExtra(consts.AccessResponseScope), "", "no scopes expected in response")
	s.Nil(s.responder.GetExtra(consts.AccessResponseRefreshToken), "refresh token not expected in response")
}
