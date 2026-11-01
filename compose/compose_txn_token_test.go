// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestRFC8693TxnTokenTypeFactory(t *testing.T) {
	config := &oauth2.Config{GlobalSecret: []byte("some-cool-secret-that-is-32bytes")}
	strategy := &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(gen.MustRSAKey())}

	testCases := []struct {
		name     string
		storage  any
		expected rfc8693.TxnTokenStorage
	}{
		{name: "ShouldWireTheStorageAsTxnTokenStorage", storage: txnScopeStorage{}, expected: txnScopeStorage{}},
		{name: "ShouldLeaveTheStorageUnsetWhenItCannotResolveSubjectScopes", storage: struct{}{}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			handler, ok := RFC8693TxnTokenTypeFactory(config, tc.storage, strategy).(*rfc8693.TxnTokenTypeHandler)
			require.True(t, ok)

			assert.Same(t, config, handler.Config)
			assert.Same(t, strategy, handler.Strategy)
			assert.Equal(t, tc.expected, handler.Storage)
		})
	}

	assert.Panics(t, func() { RFC8693TxnTokenTypeFactory(config, struct{}{}, struct{}{}) })
}

func TestComposeIssuesATransactionToken(t *testing.T) {
	stores := []func() (txnComposeStore, map[string]oauth2.Client){
		func() (txnComposeStore, map[string]oauth2.Client) {
			store := storage.NewExampleStore()

			return store, store.Clients
		},
		func() (txnComposeStore, map[string]oauth2.Client) {
			store := storage.NewHydratingMemoryStore()

			return store, store.Clients
		},
	}

	for _, newStore := range stores {
		store, clients := newStore()

		t.Run(fmt.Sprintf("%T", store), func(t *testing.T) {
			key := gen.MustRSAKey()

			config := &oauth2.Config{
				GlobalSecret:  []byte("some-cool-secret-that-is-32bytes"),
				IDTokenIssuer: "https://op.example",
				RFC8693TokenTypes: map[string]oauth2.RFC8693TokenType{
					consts.TokenTypeRFC8693AccessToken: &rfc8693.DefaultTokenType{Name: consts.TokenTypeRFC8693AccessToken},
					consts.TokenTypeRFC8693TxnToken: &rfc8693.TxnTokenType{
						Name:        consts.TokenTypeRFC8693TxnToken,
						TrustDomain: txnComposeTrustDomain,
						Replacement: &rfc8693.TxnTokenReplacement{KeyFunc: func(*jwt.Token) (any, error) { return &key.PublicKey, nil }},
					},
				},
			}

			jwtStrategy := &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(key)}
			core := NewOAuth2HMACStrategy(config)

			provider := Compose(config, store, &CommonStrategy{
				CoreStrategy:               core,
				OpenIDConnectTokenStrategy: NewOpenIDConnectStrategy(func(context.Context) (any, error) { return key, nil }, jwtStrategy, config),
				Strategy:                   jwtStrategy,
			},
				RFC8693TokenExchangeGrantFactory,
				RFC8693AccessTokenTypeFactory,
				RFC8693TxnTokenTypeFactory,
				RFC8693ActorTokenValidationFactory,
			)

			clients[txnComposeClientID] = &txnComposeClient{DefaultClient: &oauth2.DefaultClient{
				ID:           txnComposeClientID,
				ClientSecret: oauth2.NewPlainTextClientSecret(txnComposeSecret),
				GrantTypes:   []string{consts.GrantTypeOAuthTokenExchange},
				Scopes:       []string{"photos"},
				Audience:     []string{txnComposeTrustDomain},
			}}

			subject := &oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeClientCredentials},
				Request: oauth2.Request{
					ID:           uuid.New().String(),
					Client:       clients[txnComposeClientID],
					GrantedScope: oauth2.Arguments{"photos"},
					Session:      &openid.DefaultSession{Claims: &jwt.IDTokenClaims{Subject: "alice"}, Headers: &jwt.Headers{}, Subject: "alice", ExpiresAt: map[oauth2.TokenType]time.Time{oauth2.AccessToken: time.Now().UTC().Add(time.Hour)}},
				},
			}

			token, signature, err := core.GenerateAccessToken(t.Context(), subject)
			require.NoError(t, err)
			require.NoError(t, store.CreateAccessTokenSession(t.Context(), signature, subject))

			form := url.Values{
				consts.FormParameterGrantType:          {consts.GrantTypeOAuthTokenExchange},
				consts.FormParameterClientID:           {txnComposeClientID},
				consts.FormParameterClientSecret:       {txnComposeSecret},
				consts.FormParameterSubjectToken:       {token},
				consts.FormParameterSubjectTokenType:   {consts.TokenTypeRFC8693AccessToken},
				consts.FormParameterRequestedTokenType: {consts.TokenTypeRFC8693TxnToken},
				consts.FormParameterAudience:           {txnComposeTrustDomain},
				consts.FormParameterScope:              {"photos"},
			}

			r := httptest.NewRequest(http.MethodPost, "https://op.example/token", strings.NewReader(form.Encode()))
			r.Header.Set(consts.HeaderContentType, consts.ContentTypeApplicationURLEncodedForm)

			requester, err := provider.NewAccessRequest(t.Context(), r, rfc8693.NewDefaultSession())
			require.NoError(t, err)

			response, err := provider.NewAccessResponse(t.Context(), requester)
			require.NoError(t, err)

			body, err := json.Marshal(response.ToMap())
			require.NoError(t, err)

			var actual map[string]any

			require.NoError(t, json.Unmarshal(body, &actual))

			assert.Equal(t, "N_A", actual[consts.AccessResponseTokenType])
			assert.Equal(t, consts.TokenTypeRFC8693TxnToken, actual[consts.FormParameterIssuedTokenType])
			assert.NotContains(t, actual, consts.AccessResponseRefreshToken)

			issued, _ := actual[consts.AccessResponseAccessToken].(string)
			require.NotEmpty(t, issued)

			decoded, err := jwtStrategy.Decode(t.Context(), issued)
			require.NoError(t, err)

			assert.Equal(t, consts.JSONWebTokenTypeTxnToken, decoded.Header[consts.JSONWebTokenHeaderType])

			form.Set(consts.FormParameterSubjectToken, issued)
			form.Set(consts.FormParameterSubjectTokenType, consts.TokenTypeRFC8693TxnToken)

			r = httptest.NewRequest(http.MethodPost, "https://op.example/token", strings.NewReader(form.Encode()))
			r.Header.Set(consts.HeaderContentType, consts.ContentTypeApplicationURLEncodedForm)

			requester, err = provider.NewAccessRequest(t.Context(), r, rfc8693.NewDefaultSession())
			require.NoError(t, err)

			response, err = provider.NewAccessResponse(t.Context(), requester)
			require.NoError(t, err)

			replaced, err := jwtStrategy.Decode(t.Context(), response.GetAccessToken())
			require.NoError(t, err)

			first := decoded.Claims.ToMapClaims()
			claims := replaced.Claims.ToMapClaims()

			assert.Equal(t, consts.JSONWebTokenTypeTxnToken, replaced.Header[consts.JSONWebTokenHeaderType])
			assert.Equal(t, first[consts.ClaimTransaction], claims[consts.ClaimTransaction])
			assert.Equal(t, first[consts.ClaimSubject], claims[consts.ClaimSubject])
			assert.Equal(t, []any{txnComposeClientID}, claims[consts.ClaimRequestingWorkloadChain])
		})
	}
}

const (
	txnComposeClientID    = "txn-compose-client"
	txnComposeSecret      = "txn-compose-secret"
	txnComposeTrustDomain = "trust-domain.example"
)

type txnComposeStore interface {
	oauth2.Storage
	CreateAccessTokenSession(ctx context.Context, signature string, request oauth2.Requester) (err error)
}

type txnComposeClient struct {
	*oauth2.DefaultClient
}

func (*txnComposeClient) GetAllowOwnAccessTokenExchange() bool {
	return true
}

func (*txnComposeClient) GetAllowTxnTokenReplacement() bool {
	return true
}

type txnScopeStorage struct{}

func (txnScopeStorage) GetTxnTokenSubjectScopes(context.Context, oauth2.Client, string, string, map[string]any) ([]string, error) {
	return nil, nil
}

func TestRFC8693TxnTokenTypeFactoryWiresTheJTIStorage(t *testing.T) {
	config := &oauth2.Config{}
	strategy := &jwt.DefaultStrategy{Config: config}
	store := storage.NewMemoryStore()

	handler, ok := RFC8693TxnTokenTypeFactory(config, store, strategy).(*rfc8693.TxnTokenTypeHandler)

	require.True(t, ok)
	assert.Same(t, store, handler.JTIStorage)
}
