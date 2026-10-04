// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693_test

import (
	"context"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	. "authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestCustomJWTIsMarkedUsedWhenTheResponseIsPopulated(t *testing.T) {
	testCases := []struct {
		name      string
		validate  bool
		noStorage bool
		form      func(token string) url.Values
		marked    bool
		expected  string
	}{
		{
			name:     "ShouldMarkASubjectToken",
			validate: true,
			form: func(token string) url.Values {
				return url.Values{
					consts.FormParameterSubjectTokenType: {"urn:spec:jwt"},
					consts.FormParameterSubjectToken:     {token},
				}
			},
			marked: true,
		},
		{
			name:     "ShouldMarkAnActorToken",
			validate: true,
			form: func(token string) url.Values {
				return url.Values{
					consts.FormParameterActorTokenType: {"urn:spec:jwt"},
					consts.FormParameterActorToken:     {token},
				}
			},
			marked: true,
		},
		{
			name: "ShouldNotMarkWhenTheJTIIsNotValidated",
			form: func(token string) url.Values {
				return url.Values{
					consts.FormParameterSubjectTokenType: {"urn:spec:jwt"},
					consts.FormParameterSubjectToken:     {token},
				}
			},
		},
		{
			name:      "ShouldFailWithoutStorage",
			validate:  true,
			noStorage: true,
			form: func(token string) url.Values {
				return url.Values{
					consts.FormParameterSubjectTokenType: {"urn:spec:jwt"},
					consts.FormParameterSubjectToken:     {token},
				}
			},
			expected: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. Failed to perform token exchange because the storage required to validate the 'jti' claim of a JSON Web Token is not configured.",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := newCustomJWTConsumeFixture(t, tc.validate)

			if tc.noStorage {
				f.grant.Storage = nil
			}

			jti := uuid.New().String()
			request := f.request(tc.form(f.token(t, jti)))

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.custom.HandleTokenEndpointRequest(t.Context(), request)))

			assert.Empty(t, f.store.TokenExchangeJTIs)

			err := f.grant.PopulateTokenEndpointResponse(t.Context(), request, oauth2.NewAccessResponse())

			if tc.expected != "" {
				assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.expected)

				return
			}

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

			if tc.marked {
				assert.Contains(t, f.store.TokenExchangeJTIs, storage.JTIMarker{Issuer: "https://as.example.com", JTI: jti})
			} else {
				assert.Empty(t, f.store.TokenExchangeJTIs)
			}
		})
	}
}

func TestCustomJWTIsNotConsumedByARequestThatIsNotPopulated(t *testing.T) {
	f := newCustomJWTConsumeFixture(t, true)

	form := url.Values{
		consts.FormParameterSubjectTokenType: {"urn:spec:jwt"},
		consts.FormParameterSubjectToken:     {f.token(t, uuid.New().String())},
	}

	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.custom.HandleTokenEndpointRequest(t.Context(), f.request(form))))

	retry := f.request(form)

	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.custom.HandleTokenEndpointRequest(t.Context(), retry)))
	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.grant.PopulateTokenEndpointResponse(t.Context(), retry, oauth2.NewAccessResponse())))

	replay := f.request(form)

	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.custom.HandleTokenEndpointRequest(t.Context(), replay)))

	err := f.grant.PopulateTokenEndpointResponse(t.Context(), replay, oauth2.NewAccessResponse())

	require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
	assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Claim 'jti' from the token must be used only once.")
}

func TestCustomJWTIsNotConsumedWhenTheActorIsNotIdentified(t *testing.T) {
	f := newCustomJWTConsumeFixture(t, true)

	actor := createJWT(t.Context(), f.client, f.strategy, jwt.MapClaims{
		consts.ClaimIssuer:         "https://as.example.com",
		consts.ClaimJWTID:          uuid.New().String(),
		consts.ClaimExpirationTime: time.Now().Add(10 * time.Minute).Unix(),
		consts.ClaimIssuedAt:       time.Now().Unix(),
	})

	request := f.request(url.Values{
		consts.FormParameterSubjectTokenType: {"urn:spec:jwt"},
		consts.FormParameterSubjectToken:     {f.token(t, uuid.New().String())},
		consts.FormParameterActorTokenType:   {"urn:spec:jwt"},
		consts.FormParameterActorToken:       {actor},
	})

	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.custom.HandleTokenEndpointRequest(t.Context(), request)))

	err := f.grant.PopulateTokenEndpointResponse(t.Context(), request, oauth2.NewAccessResponse())

	require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
	assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'actor_token' does not identify the actor as it has neither a 'sub' nor a 'client_id' claim.")
	assert.Empty(t, f.store.TokenExchangeJTIs)
}

func TestCustomJWTPresentedInBothRolesIsMarkedOnce(t *testing.T) {
	f := newCustomJWTConsumeFixture(t, true)

	jti := uuid.New().String()
	token := f.token(t, jti)

	request := f.request(url.Values{
		consts.FormParameterSubjectTokenType: {"urn:spec:jwt"},
		consts.FormParameterSubjectToken:     {token},
		consts.FormParameterActorTokenType:   {"urn:spec:jwt"},
		consts.FormParameterActorToken:       {token},
	})

	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.custom.HandleTokenEndpointRequest(t.Context(), request)))
	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.grant.PopulateTokenEndpointResponse(t.Context(), request, oauth2.NewAccessResponse())))

	assert.Len(t, f.store.TokenExchangeJTIs, 1)
	assert.Contains(t, f.store.TokenExchangeJTIs, storage.JTIMarker{Issuer: "https://as.example.com", JTI: jti})
}

func TestCustomJWTMarksAreRolledBackWhenOneWasAlreadyUsed(t *testing.T) {
	f := newCustomJWTConsumeFixture(t, true)

	store := &transactionalCustomJWTStore{MemoryStore: f.store}
	f.grant.Storage = store

	subject := f.token(t, uuid.New().String())

	first := f.request(url.Values{
		consts.FormParameterSubjectTokenType: {"urn:spec:jwt"},
		consts.FormParameterSubjectToken:     {subject},
	})

	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.custom.HandleTokenEndpointRequest(t.Context(), first)))
	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.grant.PopulateTokenEndpointResponse(t.Context(), first, oauth2.NewAccessResponse())))

	assert.Equal(t, 1, store.commits)
	assert.Equal(t, 0, store.rollbacks)

	second := f.request(url.Values{
		consts.FormParameterSubjectTokenType: {"urn:spec:jwt"},
		consts.FormParameterSubjectToken:     {subject},
		consts.FormParameterActorTokenType:   {"urn:spec:jwt"},
		consts.FormParameterActorToken:       {f.token(t, uuid.New().String())},
	})

	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.custom.HandleTokenEndpointRequest(t.Context(), second)))

	err := f.grant.PopulateTokenEndpointResponse(t.Context(), second, oauth2.NewAccessResponse())

	require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
	assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Claim 'jti' from the token must be used only once.")
	assert.Equal(t, 2, store.begins)
	assert.Equal(t, 1, store.commits)
	assert.Equal(t, 1, store.rollbacks)
}

func TestCustomJWTIsConsumedOnceByConcurrentRequests(t *testing.T) {
	f := newCustomJWTConsumeFixture(t, true)

	token := f.token(t, uuid.New().String())

	const n = 2

	var (
		ready, done sync.WaitGroup
		start       = make(chan struct{})
		errs        = make([]error, n)
	)

	for i := range n {
		request := f.request(url.Values{
			consts.FormParameterSubjectTokenType: {"urn:spec:jwt"},
			consts.FormParameterSubjectToken:     {token},
		})

		require.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.custom.HandleTokenEndpointRequest(t.Context(), request)))

		ready.Add(1)
		done.Add(1)

		go func() {
			defer done.Done()

			ready.Done()
			<-start

			errs[i] = f.grant.PopulateTokenEndpointResponse(t.Context(), request, oauth2.NewAccessResponse())
		}()
	}

	ready.Wait()
	close(start)
	done.Wait()

	var succeeded int

	for _, err := range errs {
		if err == nil {
			succeeded++

			continue
		}

		require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
		assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Claim 'jti' from the token must be used only once.")
	}

	assert.Equal(t, 1, succeeded)
}

func newCustomJWTConsumeFixture(t *testing.T, validate bool) *customJWTConsumeFixture {
	t.Helper()

	store := storage.NewExampleStore()
	cfg := newSpecConfig(t)
	cfg.RFC8693TokenTypes["urn:spec:jwt"].(*JWTType).ValidateJTI = validate

	strategy := &jwt.DefaultStrategy{Config: cfg, Issuer: jwt.NewDefaultIssuerRS256Unverified(key)}

	return &customJWTConsumeFixture{
		store:    store,
		client:   store.Clients["my-client"],
		strategy: strategy,
		custom:   &CustomJWTTypeHandler{Config: cfg, Strategy: strategy, Storage: store},
		grant:    &TokenExchangeGrantHandler{Config: cfg, Storage: store},
	}
}

type customJWTConsumeFixture struct {
	store    *storage.MemoryStore
	client   oauth2.Client
	strategy jwt.Strategy
	custom   *CustomJWTTypeHandler
	grant    *TokenExchangeGrantHandler
}

func (f *customJWTConsumeFixture) token(t *testing.T, jti string) string {
	t.Helper()

	return createJWT(t.Context(), f.client, f.strategy, jwt.MapClaims{
		consts.ClaimIssuer:         "https://as.example.com",
		consts.ClaimSubject:        "peter",
		consts.ClaimJWTID:          jti,
		consts.ClaimExpirationTime: time.Now().Add(10 * time.Minute).Unix(),
		consts.ClaimIssuedAt:       time.Now().Unix(),
		"subject":                  "peter",
	})
}

func (f *customJWTConsumeFixture) request(form url.Values) *oauth2.AccessRequest {
	form.Set(consts.FormParameterGrantType, consts.GrantTypeOAuthTokenExchange)

	return &oauth2.AccessRequest{
		GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthTokenExchange},
		Request: oauth2.Request{
			ID:      uuid.New().String(),
			Client:  f.client,
			Form:    form,
			Session: newSpecSession("peter"),
		},
	}
}

type transactionalCustomJWTStore struct {
	*storage.MemoryStore

	begins, commits, rollbacks int
}

func (s *transactionalCustomJWTStore) BeginTX(ctx context.Context) (context.Context, error) {
	s.begins++

	return ctx, nil
}

func (s *transactionalCustomJWTStore) Commit(_ context.Context) error {
	s.commits++

	return nil
}

func (s *transactionalCustomJWTStore) Rollback(_ context.Context) error {
	s.rollbacks++

	return nil
}
