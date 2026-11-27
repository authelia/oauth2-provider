// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"
	josejwt "authelia.com/provider/jose/jwt"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/compose"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/handler/rfc7523"
	"authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestIdentityChaining(t *testing.T) {
	stores := []struct {
		name string
		new  func() (store hoauth2.CoreStorage, memory *storage.MemoryStore)
	}{
		{
			name: idjagStoreMemory,
			new: func() (hoauth2.CoreStorage, *storage.MemoryStore) {
				store := storage.NewMemoryStore()

				return store, store
			},
		},
		{
			name: idjagStoreHydrate,
			new: func() (hoauth2.CoreStorage, *storage.MemoryStore) {
				store := storage.NewHydratingMemoryStore()

				return store, store.MemoryStore
			},
		},
	}

	actor := map[string]any{consts.ClaimSubject: chainingActor}

	for _, s := range stores {
		t.Run(s.name, func(t *testing.T) {
			t.Run("ShouldIssueAShortLivedGrantAtDomainA", func(t *testing.T) {
				env := newChainingEnvironment(t, s.new)

				status, body := postChainingToken(t, env.a, chainingClientA, env.exchangeForm(env.subjectToken(t), consts.TokenTypeRFC8693AccessToken, chainingScope))

				require.Equal(t, http.StatusOK, status, "exchange error: %+v", body)
				assert.Equal(t, consts.TokenTypeRFC8693JWT, body[consts.FormParameterIssuedTokenType])
				assert.Equal(t, oauth2.RFC8693NAToken, body[consts.AccessResponseTokenType])

				grant, ok := body[consts.AccessResponseAccessToken].(string)
				require.True(t, ok)

				claims := env.decodeGrant(t, grant)

				assert.Equal(t, env.a.URL+chainingGrantIssuerPath, claims[consts.ClaimIssuer])
				assert.Equal(t, []any{env.b.URL}, claims[consts.ClaimAudience])
				assert.Equal(t, chainingSubject, claims[consts.ClaimSubject])
				assert.Equal(t, chainingScope, claims[consts.ClaimScope])
				assert.Equal(t, actor, claims[consts.ClaimActor])

				exp, ok := claims[consts.ClaimExpirationTime].(float64)
				require.True(t, ok)

				iat, ok := claims[consts.ClaimIssuedAt].(float64)
				require.True(t, ok)

				assert.Equal(t, float64(300), exp-iat)
			})

			t.Run("ShouldRedeemTheGrantAtDomainB", func(t *testing.T) {
				env := newChainingEnvironment(t, s.new)

				grant := env.grant(t, chainingScope)

				grantExpiry, ok := env.decodeGrant(t, grant)[consts.ClaimExpirationTime].(float64)
				require.True(t, ok)

				status, body := postChainingToken(t, env.b, chainingClientB, chainingRedeemForm(grant, ""))

				require.Equal(t, http.StatusOK, status, "redeem error: %+v", body)
				assert.Equal(t, chainingScope, body[consts.AccessResponseScope])

				expiresIn, ok := body[consts.AccessResponseExpiresIn].(float64)
				require.True(t, ok)

				assert.Greater(t, expiresIn, float64(0))
				assert.LessOrEqual(t, expiresIn, float64(300))

				_, present := body[consts.AccessResponseRefreshToken]
				assert.False(t, present)

				token, ok := body[consts.AccessResponseAccessToken].(string)
				require.True(t, ok)

				requester, err := env.bStore.GetAccessTokenSession(t.Context(), env.bStrategy.AccessTokenSignature(t.Context(), token), newChainingSession())
				require.NoError(t, err)

				session, ok := requester.GetSession().(*chainingSession)
				require.True(t, ok)

				assert.Equal(t, chainingSubjectB, session.GetSubject())
				assert.Equal(t, chainingSubject, session.Claims[consts.ClaimSubject])
				assert.Equal(t, actor, session.Claims[consts.ClaimActor])
				assert.False(t, session.GetExpiresAt(oauth2.AccessToken).IsZero())
				assert.LessOrEqual(t, session.GetExpiresAt(oauth2.AccessToken).Unix(), int64(grantExpiry))

				introspection := env.introspect(t, token)

				assert.Equal(t, true, introspection[consts.ClaimActive])
				assert.Equal(t, chainingSubjectB, introspection[consts.ClaimSubject])

				expiry, ok := introspection[consts.ClaimExpirationTime].(float64)
				require.True(t, ok)

				assert.LessOrEqual(t, expiry, grantExpiry)

				_, present = introspection[consts.ClaimActor]
				assert.False(t, present)
			})

			t.Run("ShouldRefuseAReplayedGrant", func(t *testing.T) {
				env := newChainingEnvironment(t, s.new)

				grant := env.grant(t, chainingScope)

				status, body := postChainingToken(t, env.b, chainingClientB, chainingRedeemForm(grant, ""))
				require.Equal(t, http.StatusOK, status, "redeem error: %+v", body)

				status, body = postChainingToken(t, env.b, chainingClientB, chainingRedeemForm(grant, ""))

				assert.Equal(t, http.StatusBadRequest, status)
				assert.Equal(t, oauth2.ErrInvalidGrant.ErrorField, body[chainingError])
			})

			t.Run("ShouldRefuseAScopeOutsideTheIssuer", func(t *testing.T) {
				env := newChainingEnvironment(t, s.new)

				status, body := postChainingToken(t, env.b, chainingClientB, chainingRedeemForm(env.grant(t, chainingScopeAdmin), chainingScopeAdmin))

				assert.Equal(t, http.StatusBadRequest, status)
				assert.Equal(t, oauth2.ErrInvalidScope.ErrorField, body[chainingError])

				status, body = postChainingToken(t, env.b, chainingClientB, chainingRedeemForm(env.grant(t, chainingScopeAdmin), ""))

				require.Equal(t, http.StatusOK, status, "redeem error: %+v", body)
				assert.Empty(t, body[consts.AccessResponseScope])
			})

			t.Run("ShouldRefuseAnUnmappedSubject", func(t *testing.T) {
				env := newChainingEnvironment(t, s.new)

				delete(env.bMemory.RFC7523Subjects, storage.RFC7523SubjectKey{Issuer: env.a.URL + chainingGrantIssuerPath, Subject: chainingSubject})

				status, body := postChainingToken(t, env.b, chainingClientB, chainingRedeemForm(env.grant(t, chainingScope), ""))

				assert.Equal(t, http.StatusBadRequest, status)
				assert.Equal(t, oauth2.ErrInvalidGrant.ErrorField, body[chainingError])
			})

			t.Run("ShouldRefuseAClientTheIssuerDoesNotList", func(t *testing.T) {
				env := newChainingEnvironment(t, s.new)

				status, body := postChainingToken(t, env.b, chainingClientOtherB, chainingRedeemForm(env.grant(t, chainingScope), ""))

				assert.Equal(t, http.StatusBadRequest, status)
				assert.Equal(t, oauth2.ErrAccessDenied.ErrorField, body[chainingError])
			})

			t.Run("ShouldRefuseTheGrantBackAtDomainA", func(t *testing.T) {
				env := newChainingEnvironment(t, s.new)

				status, body := postChainingToken(t, env.a, chainingClientA, env.exchangeForm(env.grant(t, chainingScope), chainingTrustingTokenType, chainingScope))

				assert.Equal(t, http.StatusBadRequest, status)
				assert.Equal(t, oauth2.ErrInvalidRequest.ErrorField, body[chainingError])
				assert.Contains(t, body[chainingErrorDescription], "issued by this authorization server")
			})
		})
	}
}

const (
	chainingClientA         = "chain-a"
	chainingClientB         = "chain-b"
	chainingClientOtherB    = "other-b"
	chainingSubject         = "peter"
	chainingSubjectB        = "b-peter"
	chainingActor           = "https://svc.a.example"
	chainingScope           = "photos"
	chainingScopeAdmin      = "admin"
	chainingGrantIssuerPath = "/grants"
	chainingIntrospectPath  = "/introspect"
	chainingError           = "error"

	chainingErrorDescription  = "error_description"
	chainingTrustingTokenType = "urn:example:token-type:trusting-jwt"
)

type chainingSession struct {
	*oauth2.DefaultSession

	Claims map[string]any `json:"grant_claims"`
}

func newChainingSession() *chainingSession {
	return &chainingSession{DefaultSession: &oauth2.DefaultSession{}}
}

func (s *chainingSession) SetRFC7523GrantClaims(claims map[string]any) {
	s.Claims = claims
}

func (s *chainingSession) Clone() oauth2.Session {
	if s == nil {
		return nil
	}

	cloned := &chainingSession{}

	if s.DefaultSession != nil {
		cloned.DefaultSession, _ = s.DefaultSession.Clone().(*oauth2.DefaultSession)
	}

	if s.Claims != nil {
		data, _ := json.Marshal(s.Claims)
		_ = json.Unmarshal(data, &cloned.Claims)
	}

	return cloned
}

var _ rfc7523.GrantClaimsSession = (*chainingSession)(nil)

type chainingEnvironment struct {
	a, b *httptest.Server

	aKey      *rsa.PrivateKey
	aClient   oauth2.Client
	aStore    hoauth2.CoreStorage
	aStrategy hoauth2.CoreStrategy

	bStore    hoauth2.CoreStorage
	bMemory   *storage.MemoryStore
	bStrategy hoauth2.CoreStrategy
}

func newChainingEnvironment(t *testing.T, newStore func() (hoauth2.CoreStorage, *storage.MemoryStore)) *chainingEnvironment {
	t.Helper()

	aMux, bMux := http.NewServeMux(), http.NewServeMux()

	env := &chainingEnvironment{
		a:    httptest.NewServer(aMux),
		b:    httptest.NewServer(bMux),
		aKey: gen.MustRSAKey(),
	}

	t.Cleanup(env.a.Close)
	t.Cleanup(env.b.Close)

	aConfig := &oauth2.Config{
		GlobalSecret: []byte("chaining-integration-a-secret-32-bytes"),
		Issuer:       env.a.URL,
		RFC8693TokenTypes: map[string]oauth2.RFC8693TokenType{
			consts.TokenTypeRFC8693AccessToken: &rfc8693.DefaultTokenType{Name: consts.TokenTypeRFC8693AccessToken},
			consts.TokenTypeRFC8693JWT: &rfc8693.JWTType{
				Name:  consts.TokenTypeRFC8693JWT,
				Issue: &rfc8693.JWTIssueConfig{Issuer: env.a.URL + chainingGrantIssuerPath, AuthorizationGrant: true},
			},
			chainingTrustingTokenType: &rfc8693.JWTType{
				Name: chainingTrustingTokenType,
				Validate: &rfc8693.JWTValidationConfig{
					Issuer:       env.a.URL + chainingGrantIssuerPath,
					ValidateFunc: func(_ *jwt.Token) (any, error) { return &env.aKey.PublicKey, nil },
				},
			},
		},
	}

	aStore, aMemory := newStore()

	env.aClient = &oauth2.DefaultRegisteredClient{
		DefaultClient: &oauth2.DefaultClient{
			ID:           chainingClientA,
			ClientSecret: oauth2.NewBCryptClientSecret(idjagSecretHash),
			GrantTypes:   []string{consts.GrantTypeOAuthTokenExchange},
			Scopes:       []string{chainingScope, chainingScopeAdmin},
			Audience:     []string{env.b.URL},
		},
		TokenExchangeAuthorizationGrant: true,
	}

	aMemory.Clients[chainingClientA] = env.aClient

	aJWT := &jwt.DefaultStrategy{Config: aConfig, Issuer: jwt.NewDefaultIssuerRS256Unverified(env.aKey)}

	env.aStore, env.aStrategy = aStore, compose.NewOAuth2HMACStrategy(aConfig)

	aProvider := compose.Compose(
		aConfig,
		aStore,
		&compose.CommonStrategy{
			CoreStrategy: env.aStrategy,
			Strategy:     aJWT,
		},
		compose.RFC8693TokenExchangeGrantFactory,
		compose.RFC8693AccessTokenTypeFactory,
		compose.RFC8693CustomJWTTypeFactory,
		compose.RFC8693ActorTokenValidationFactory,
	)

	aMux.HandleFunc(tokenRelativePath, idjagTokenHandler(aProvider, func() oauth2.Session { return rfc8693.NewDefaultSession() }))

	bConfig := &oauth2.Config{
		GlobalSecret:        []byte("chaining-integration-b-secret-32-bytes"),
		Issuer:              env.b.URL,
		AccessTokenLifespan: time.Hour,
	}

	bStore, bMemory := newStore()

	env.bStore, env.bMemory, env.bStrategy = bStore, bMemory, compose.NewOAuth2HMACStrategy(bConfig)

	bMemory.Clients[chainingClientB] = &oauth2.DefaultClient{
		ID:           chainingClientB,
		ClientSecret: oauth2.NewBCryptClientSecret(idjagSecretHash),
		GrantTypes:   []string{consts.GrantTypeOAuthJWTBearer},
		Scopes:       []string{chainingScope, chainingScopeAdmin, consts.ScopeOfflineAccess},
	}

	bMemory.Clients[chainingClientOtherB] = &oauth2.DefaultClient{
		ID:           chainingClientOtherB,
		ClientSecret: oauth2.NewBCryptClientSecret(idjagSecretHash),
		GrantTypes:   []string{consts.GrantTypeOAuthJWTBearer},
		Scopes:       []string{chainingScope},
	}

	bMemory.RFC7523TrustedIssuers[env.a.URL+chainingGrantIssuerPath] = oauth2.RFC7523TrustedIssuer{
		Issuer: env.a.URL + chainingGrantIssuerPath,
		JSONWebKeys: &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key:       &env.aKey.PublicKey,
			KeyID:     "default",
			Algorithm: string(jose.RS256),
			Use:       consts.JSONWebTokenUseSignature,
		}}},
		SigningAlgs: []string{string(jose.RS256)},
		Scopes:      []string{chainingScope},
		Clients:     []string{chainingClientB},
	}

	bMemory.RFC7523Subjects[storage.RFC7523SubjectKey{Issuer: env.a.URL + chainingGrantIssuerPath, Subject: chainingSubject}] = chainingSubjectB

	bProvider := compose.Compose(
		bConfig,
		bStore,
		&compose.CommonStrategy{
			CoreStrategy: env.bStrategy,
			Strategy:     &jwt.DefaultStrategy{Config: bConfig, Issuer: jwt.NewDefaultIssuerRS256Unverified(gen.MustRSAKey())},
		},
		compose.RFC7523AssertionGrantFactory,
		compose.OAuth2TokenIntrospectionFactory,
	)

	bMux.HandleFunc(tokenRelativePath, idjagTokenHandler(bProvider, func() oauth2.Session { return newChainingSession() }))
	bMux.HandleFunc(chainingIntrospectPath, func(rw http.ResponseWriter, req *http.Request) {
		ctx := req.Context()

		responder, err := bProvider.NewIntrospectionRequest(ctx, req, newChainingSession())
		if err != nil {
			bProvider.WriteIntrospectionError(ctx, rw, req, err)

			return
		}

		bProvider.WriteIntrospectionResponse(ctx, rw, responder)
	})

	return env
}

func (env *chainingEnvironment) subjectToken(t *testing.T) string {
	t.Helper()

	ctx := context.Background()

	session := rfc8693.NewDefaultSession()
	session.Subject = chainingSubject
	session.Claims.Subject = chainingSubject
	session.SetExpiresAt(oauth2.AccessToken, time.Now().UTC().Add(time.Hour))
	session.SetClaimActor(map[string]any{consts.ClaimSubject: chainingActor})

	request := &oauth2.AccessRequest{
		GrantTypes: oauth2.Arguments{consts.GrantTypeClientCredentials},
		Request: oauth2.Request{
			ID:           uuid.New().String(),
			RequestedAt:  time.Now().UTC(),
			Client:       env.aClient,
			GrantedScope: oauth2.Arguments{chainingScope, chainingScopeAdmin},
			Session:      session,
		},
	}

	token, signature, err := env.aStrategy.GenerateAccessToken(ctx, request)
	require.NoError(t, err)
	require.NoError(t, env.aStore.CreateAccessTokenSession(ctx, signature, request))

	return token
}

func (env *chainingEnvironment) grant(t *testing.T, scope string) string {
	t.Helper()

	status, body := postChainingToken(t, env.a, chainingClientA, env.exchangeForm(env.subjectToken(t), consts.TokenTypeRFC8693AccessToken, scope))
	require.Equal(t, http.StatusOK, status, "exchange error: %+v", body)

	grant, ok := body[consts.AccessResponseAccessToken].(string)
	require.True(t, ok)

	return grant
}

func (env *chainingEnvironment) exchangeForm(subjectToken, subjectTokenType, scope string) url.Values {
	return url.Values{
		consts.FormParameterGrantType:          {consts.GrantTypeOAuthTokenExchange},
		consts.FormParameterRequestedTokenType: {consts.TokenTypeRFC8693JWT},
		consts.FormParameterAudience:           {env.b.URL},
		consts.FormParameterScope:              {scope},
		consts.FormParameterSubjectToken:       {subjectToken},
		consts.FormParameterSubjectTokenType:   {subjectTokenType},
	}
}

func (env *chainingEnvironment) decodeGrant(t *testing.T, raw string) (claims map[string]any) {
	t.Helper()

	token, err := josejwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err)
	require.NoError(t, token.Claims(&env.aKey.PublicKey, &claims))

	return claims
}

func (env *chainingEnvironment) introspect(t *testing.T, token string) (body map[string]any) {
	t.Helper()

	var status int

	status, body = postChaining(t, env.b.URL+chainingIntrospectPath, chainingClientB, url.Values{consts.FormParameterToken: {token}})
	require.Equal(t, http.StatusOK, status, "introspection error: %+v", body)

	return body
}

func chainingRedeemForm(assertion, scope string) url.Values {
	form := url.Values{
		consts.FormParameterGrantType: {consts.GrantTypeOAuthJWTBearer},
		consts.FormParameterAssertion: {assertion},
	}

	if scope != "" {
		form.Set(consts.FormParameterScope, scope)
	}

	return form
}

func postChainingToken(t *testing.T, ts *httptest.Server, clientID string, form url.Values) (status int, body map[string]any) {
	t.Helper()

	return postChaining(t, ts.URL+tokenRelativePath, clientID, form)
}

func postChaining(t *testing.T, endpoint, clientID string, form url.Values) (status int, body map[string]any) {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	require.NoError(t, err)

	req.Header.Set(consts.HeaderContentType, consts.ContentTypeApplicationURLEncodedForm)
	req.SetBasicAuth(clientID, idjagClientSecret)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)

	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, &body), "response: %s", data)

	return resp.StatusCode, body
}
