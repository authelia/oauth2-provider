// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/compose"
	"authelia.com/provider/oauth2/integration/clients"
)

type authorizeJWTBearerRequiredIATSuite struct {
	suite.Suite

	client *clients.JWTBearer
}

func (s *authorizeJWTBearerRequiredIATSuite) TestBadResponseWithoutIssuedAt() {
	ctx := context.Background()
	client := s.getClient()
	token, err := client.GetToken(ctx, &clients.JWTBearerPayload{
		Claims: &jwt.Claims{
			Issuer:   firstJWTBearerIssuer,
			Subject:  firstJWTBearerSubject,
			Audience: []string{tokenURL},
			Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
			ID:       uuid.New().String(),
		},
	}, []string{"oauth2"})

	s.assertBadResponse(s.T(), token, err)
}

func (s *authorizeJWTBearerRequiredIATSuite) TestSuccessResponseWithIssuedAt() {
	ctx := context.Background()
	client := s.getClient()
	token, err := client.GetToken(ctx, &clients.JWTBearerPayload{
		Claims: &jwt.Claims{
			Issuer:   firstJWTBearerIssuer,
			Subject:  firstJWTBearerSubject,
			Audience: []string{tokenURL},
			Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt: jwt.NewNumericDate(time.Now()),
			ID:       uuid.New().String(),
		},
	}, []string{"oauth2"})

	s.assertSuccessResponse(s.T(), token, err)
}

func (s *authorizeJWTBearerRequiredIATSuite) getClient() *clients.JWTBearer {
	client := *s.client

	return &client
}

func (s *authorizeJWTBearerRequiredIATSuite) assertSuccessResponse(t *testing.T, token *clients.Token, err error) {
	require.NoError(t, err)
	require.NotNil(t, token)

	assert.Equal(t, token.TokenType, "bearer")
	assert.Empty(t, token.RefreshToken)
	assert.NotEmpty(t, token.ExpiresIn)
	assert.NotEmpty(t, token.AccessToken)
}

func (s *authorizeJWTBearerRequiredIATSuite) assertBadResponse(t *testing.T, token *clients.Token, err error) {
	assert.Nil(t, token)
	assert.NotNil(t, err)

	retrieveError, ok := err.(*clients.RequestError)
	assert.True(t, ok)
	assert.Equal(t, retrieveError.Response.StatusCode, http.StatusBadRequest)
}

func TestAuthorizeJWTBearerRequiredIATSuite(t *testing.T) {
	provider := compose.Compose(
		&oauth2.Config{
			GrantTypeJWTBearerCanSkipClientAuth:  true,
			GrantTypeJWTBearerIDOptional:         true,
			GrantTypeJWTBearerIssuedDateOptional: false,
			AllowedJWTAssertionAudiences:         []string{tokenURL},
		},
		store,
		jwtStrategy,
		compose.OAuth2ClientCredentialsGrantFactory,
		compose.RFC7523AssertionGrantFactory,
	)
	testServer := mockServer(t, provider, &oauth2.DefaultSession{})
	defer testServer.Close()

	client := newJWTBearerAppClient(testServer)
	if err := client.SetPrivateKey(firstKeyID, firstPrivateKey); err != nil {
		assert.Nil(t, err)
	}

	suite.Run(t, &authorizeJWTBearerRequiredIATSuite{
		client: client,
	})
}
