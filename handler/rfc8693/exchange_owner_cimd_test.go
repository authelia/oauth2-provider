// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693_test

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/cimd"
	. "authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestSpec_5_RebuiltDocumentClientIsResolvedAgain(t *testing.T) {
	const id = "https://client.example.com/cimd.json"

	registered := func(permitted ...string) *oauth2.DefaultRegisteredClient {
		return &oauth2.DefaultRegisteredClient{
			DefaultClient: &oauth2.DefaultClient{
				ID:         id,
				GrantTypes: []string{consts.GrantTypeAuthorizationCode, consts.GrantTypeRefreshToken},
				Scopes:     []string{consts.ScopeOpenID, consts.ScopeOffline},
			},
			TokenExchangePermittedClientIDs: permitted,
		}
	}

	rebuilt := &oauth2.DefaultClient{
		ID:         id,
		GrantTypes: []string{consts.GrantTypeAuthorizationCode, consts.GrantTypeRefreshToken},
		Scopes:     []string{consts.ScopeOpenID, consts.ScopeOffline},
	}

	testCases := []struct {
		name       string
		disabled   bool
		registered oauth2.Client
		resolved   oauth2.Client
		err        error
		expected   error
		debug      string
	}{
		{name: "ShouldRefuseADocumentClientPermittingNoClient", resolved: &cimd.Client{DefaultRegisteredClient: registered()}, expected: oauth2.ErrInvalidRequest, debug: "not permitted to exchange"},
		{name: "ShouldAllowADocumentClientPermittingTheClient", resolved: &cimd.Client{DefaultRegisteredClient: registered("exchange-client")}},
		{name: "ShouldPreferARegisteredClient", registered: registered()},
		{name: "ShouldRefuseAClientWhichCanNotBeResolved", err: oauth2.ErrInvalidClient, expected: oauth2.ErrInvalidRequest, debug: "could not be resolved"},
		{name: "ShouldReportATransientFailure", err: oauth2.ErrTemporarilyUnavailable, expected: oauth2.ErrTemporarilyUnavailable},
		{name: "ShouldNotResolveWhenDisabled", disabled: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, store, strategy := newExchangeFixture(t)

			resolver := &documentResolver{client: tc.resolved, err: tc.err}

			if !tc.disabled {
				cfg.ClientIDMetadataDocumentResolver = resolver
				cfg.AuthorizationServerIdentificationIssuer = "https://as.example.com"
			}

			if tc.registered != nil {
				store.Clients[id] = tc.registered
			}

			req := newExchangeRequest(t, newConfidentialClient(), newSpecSession("alice"), url.Values{
				consts.FormParameterSubjectTokenType: {consts.TokenTypeRFC8693AccessToken},
				consts.FormParameterSubjectToken:     {createExchangeAccessToken(t, strategy, store, rebuilt, "alice", consts.ScopeOpenID)},
			})

			err := newAccessTokenTypeHandler(cfg, store, strategy).HandleTokenEndpointRequest(context.Background(), req)

			if tc.disabled {
				assert.Equal(t, 0, resolver.calls)
			}

			if tc.expected == nil {
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				return
			}

			require.ErrorIs(t, err, tc.expected)
			assert.Contains(t, oauth2.ErrorToDebugRFC6749Error(err).Error(), tc.debug)
		})
	}
}

func TestSpec_5_CustomJWTOfAnotherClientIsGatedByItsPermittedClients(t *testing.T) {
	const id = "https://client.example.com/cimd.json"

	registered := func(permitted ...string) *oauth2.DefaultRegisteredClient {
		return &oauth2.DefaultRegisteredClient{
			DefaultClient:                   &oauth2.DefaultClient{ID: id},
			TokenExchangePermittedClientIDs: permitted,
		}
	}

	external := gen.MustRSAKey()

	testCases := []struct {
		name     string
		clientID any
		owner    oauth2.Client
		external bool
		expected error
		debug    string
	}{
		{name: "ShouldAllowATokenWithoutAClientID"},
		{name: "ShouldAllowATokenWithANonStringClientID", clientID: 1},
		{name: "ShouldAllowATokenIssuedToTheRequestingClient", clientID: "my-client"},
		{name: "ShouldRefuseADocumentClientPermittingNoClient", clientID: id, owner: &cimd.Client{DefaultRegisteredClient: registered()}, expected: oauth2.ErrInvalidRequest, debug: "not permitted to exchange a subject token issued to client " + id},
		{name: "ShouldAllowADocumentClientPermittingTheClient", clientID: id, owner: &cimd.Client{DefaultRegisteredClient: registered("my-client")}},
		{name: "ShouldRefuseARegisteredClientPermittingAnotherClient", clientID: id, owner: registered("other"), expected: oauth2.ErrInvalidRequest, debug: "not permitted to exchange"},
		{name: "ShouldAllowARegisteredClientPermittingAnyClient", clientID: id, owner: registered()},
		{name: "ShouldRefuseAnUnknownClient", clientID: id, expected: oauth2.ErrInvalidRequest, debug: "could not be resolved"},
		{name: "ShouldIgnoreTheClientIDOfAnExternalToken", clientID: "0oa-external-idp-client", external: true},
		{name: "ShouldIgnoreTheClientIdentifierURLOfAnExternalToken", clientID: id, external: true},
		{name: "ShouldIgnoreTheRegisteredClientNamedByAnExternalToken", clientID: id, owner: &cimd.Client{DefaultRegisteredClient: registered()}, external: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := newSpecConfig(t)
			store := storage.NewExampleStore()

			if tc.owner != nil {
				store.Clients[id] = tc.owner
			}

			resolver := &documentResolver{}
			signer := key

			if tc.external {
				signer = external

				config.ClientIDMetadataDocumentResolver = resolver
				config.AuthorizationServerIdentificationIssuer = "https://as.example.com"

				jwtType := *config.RFC8693TokenTypes["urn:spec:jwt"].(*JWTType)
				validation := *jwtType.Validate
				validation.ValidateFunc = func(_ *jwt.Token) (any, error) { return external.PublicKey, nil }
				jwtType.Validate = &validation
				config.RFC8693TokenTypes["urn:spec:jwt"] = &jwtType
			}

			claims := jwt.MapClaims{
				consts.ClaimIssuer:         "https://as.example.com",
				consts.ClaimSubject:        "peter",
				"subject":                  "peter",
				consts.ClaimExpirationTime: time.Now().Add(time.Minute).Unix(),
				consts.ClaimIssuedAt:       time.Now().Unix(),
				consts.ClaimAudience:       []string{"my-client"},
			}

			if tc.clientID != nil {
				claims[consts.ClaimClientIdentifier] = tc.clientID
			}

			request := newExchangeRequest(t, store.Clients["my-client"], newSpecSession("peter"), url.Values{
				consts.FormParameterSubjectToken:       {signCustomJWTWithKey(t, signer, claims)},
				consts.FormParameterSubjectTokenType:   {"urn:spec:jwt"},
				consts.FormParameterRequestedTokenType: {consts.TokenTypeRFC8693AccessToken},
			})

			handler := &CustomJWTTypeHandler{Config: config, Strategy: &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(key)}, Storage: store}

			err := handler.HandleTokenEndpointRequest(t.Context(), request)

			assert.Equal(t, 0, resolver.calls)

			if tc.expected == nil {
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				return
			}

			require.ErrorIs(t, err, tc.expected)
			assert.Contains(t, oauth2.ErrorToDebugRFC6749Error(err).Error(), tc.debug)
		})
	}
}

type documentResolver struct {
	client oauth2.Client
	err    error
	calls  int
}

func (r *documentResolver) ResolveClientIDMetadataDocumentClient(_ context.Context, _ string) (oauth2.Client, error) {
	r.calls++

	return r.client, r.err
}

func signCustomJWTWithKey(t *testing.T, key *rsa.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithType(consts.JSONWebTokenTypeJWT))
	require.NoError(t, err)

	payload, err := json.Marshal(claims)
	require.NoError(t, err)

	signed, err := signer.Sign(payload)
	require.NoError(t, err)

	token, err := signed.CompactSerialize()
	require.NoError(t, err)

	return token
}
