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

func TestCustomJWTUsesTheLifespanOfTheClient(t *testing.T) {
	testCases := []struct {
		name     string
		expiry   time.Duration
		grant    bool
		client   *time.Duration
		subject  time.Duration
		expected time.Duration
	}{
		{name: "ShouldUseTheConfiguredLifespanWithoutOneForTheClient", expected: 30 * time.Minute},
		{name: "ShouldUseTheLifespanOfTheClient", client: durationPointer(5 * time.Minute), expected: 5 * time.Minute},
		{name: "ShouldPermitALongerLifespanForTheClient", client: durationPointer(2 * time.Hour), expected: 2 * time.Hour},
		{name: "ShouldPreferTheExpiryOfTheTokenType", expiry: 10 * time.Minute, client: durationPointer(5 * time.Minute), expected: 10 * time.Minute},
		{name: "ShouldNotOutliveTheSubjectToken", client: durationPointer(2 * time.Hour), subject: time.Minute, expected: time.Minute},
		{name: "ShouldUseTheLifespanOfTheClientForAGrant", grant: true, client: durationPointer(5 * time.Minute), expected: 5 * time.Minute},
		{name: "ShouldPreferTheExpiryOfTheTokenTypeForAGrant", grant: true, expiry: 10 * time.Minute, client: durationPointer(5 * time.Minute), expected: 10 * time.Minute},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := newSpecConfig(t)
			config.AccessTokenLifespan = 30 * time.Minute

			jwtType := config.RFC8693TokenTypes["urn:spec:jwt"].(*JWTType)
			jwtType.Expiry = tc.expiry
			jwtType.AuthorizationGrant = tc.grant

			store := storage.NewExampleStore()

			handler := &CustomJWTTypeHandler{
				Config:   config,
				Strategy: &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(key)},
				Storage:  store,
			}

			session := newValidatedSpecSession("alice")

			if tc.subject != 0 {
				session.SetSubjectToken(map[string]any{consts.ClaimSubject: "alice", consts.ClaimExpirationTime: time.Now().Add(tc.subject).Unix()})
			}

			client := &oauth2.DefaultClientWithCustomTokenLifespans{
				DefaultClient:  store.Clients["my-client"].(*oauth2.DefaultClient),
				TokenLifespans: &oauth2.ClientLifespanConfig{TokenExchangeGrantAccessTokenLifespan: tc.client},
			}

			request := newClientLifespanRequest(client, session, "urn:spec:jwt", consts.TokenTypeRFC8693AccessToken)
			request.GrantedAudience = oauth2.Arguments{"https://as.example.org"}

			response := oauth2.NewAccessResponse()

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.PopulateTokenEndpointResponse(t.Context(), request, response)))

			assertIssuedLifespan(t, response, tc.expected)
		})
	}
}

func TestIDTokenUsesTheLifespanOfTheClient(t *testing.T) {
	testCases := []struct {
		name     string
		client   *time.Duration
		access   *time.Duration
		subject  time.Duration
		expected time.Duration
	}{
		{name: "ShouldUseTheConfiguredLifespanWithoutOneForTheClient", expected: 30 * time.Minute},
		{name: "ShouldUseTheLifespanOfTheClient", client: durationPointer(5 * time.Minute), expected: 5 * time.Minute},
		{name: "ShouldPermitALongerLifespanForTheClient", client: durationPointer(2 * time.Hour), expected: 2 * time.Hour},
		{name: "ShouldNotUseTheAccessTokenLifespanOfTheClient", access: durationPointer(5 * time.Minute), expected: 30 * time.Minute},
		{name: "ShouldNotOutliveTheSubjectToken", client: durationPointer(2 * time.Hour), subject: time.Minute, expected: time.Minute},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := newSpecConfig(t)
			config.IDTokenLifespan = 30 * time.Minute

			store := storage.NewExampleStore()
			strategy := &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(key)}

			handler := &IDTokenTypeHandler{
				Config:             config,
				Strategy:           strategy,
				IssueStrategy:      &openid.DefaultStrategy{Strategy: strategy, Config: config},
				ValidationStrategy: &openid.DefaultIDTokenValidationStrategy{Strategy: strategy},
				Storage:            store,
			}

			session := newValidatedSpecSession("alice")
			session.IDTokenClaims().AuthTime = jwt.Now()

			if tc.subject != 0 {
				session.SetSubjectToken(map[string]any{consts.ClaimSubject: "alice", consts.ClaimExpirationTime: time.Now().Add(tc.subject).Unix()})
			}

			client := &oauth2.DefaultClientWithCustomTokenLifespans{
				DefaultClient: store.Clients["my-client"].(*oauth2.DefaultClient),
				TokenLifespans: &oauth2.ClientLifespanConfig{
					TokenExchangeGrantIDTokenLifespan:     tc.client,
					TokenExchangeGrantAccessTokenLifespan: tc.access,
				},
			}

			request := newClientLifespanRequest(client, session, consts.TokenTypeRFC8693IDToken, consts.TokenTypeRFC8693IDToken)

			response := oauth2.NewAccessResponse()

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.PopulateTokenEndpointResponse(t.Context(), request, response)))

			assertIssuedLifespan(t, response, tc.expected)
		})
	}
}

func assertIssuedLifespan(t *testing.T, response *oauth2.AccessResponse, expected time.Duration) {
	t.Helper()

	claims := map[string]any{}

	_, err := jwt.UnsafeParseSignedAny(response.GetAccessToken(), &claims)
	require.NoError(t, err)

	assert.WithinDuration(t, time.Now().Add(expected), time.Unix(int64(claims[consts.ClaimExpirationTime].(float64)), 0), 5*time.Second)
	assert.InDelta(t, int64(expected.Seconds()), response.ToMap()[consts.AccessResponseExpiresIn], 5)
}

func newClientLifespanRequest(client oauth2.Client, session oauth2.Session, requested, subject string) *oauth2.AccessRequest {
	return &oauth2.AccessRequest{
		GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthTokenExchange},
		Request: oauth2.Request{
			ID:      uuid.New().String(),
			Client:  client,
			Session: session,
			Form: url.Values{
				consts.FormParameterGrantType:          {consts.GrantTypeOAuthTokenExchange},
				consts.FormParameterRequestedTokenType: {requested},
				consts.FormParameterSubjectToken:       {"opaque-subject-token"},
				consts.FormParameterSubjectTokenType:   {subject},
			},
		},
	}
}

func durationPointer(d time.Duration) *time.Duration {
	return &d
}
