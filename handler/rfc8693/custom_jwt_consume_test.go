// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693_test

import (
	"context"
	"errors"
	"maps"
	"math"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"
	josejwt "authelia.com/provider/jose/jwt"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	. "authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/hmac"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestCustomJWTIsMarkedUsedWhenATokenIsIssued(t *testing.T) {
	testCases := []struct {
		name      string
		unchecked bool
		form      func(t *testing.T, f *customJWTConsumeFixture) (form url.Values, jtis []string)
	}{
		{
			name: "ShouldMarkASubjectTokenForAnAccessToken",
			form: func(t *testing.T, f *customJWTConsumeFixture) (url.Values, []string) {
				jti := uuid.New().String()

				return url.Values{
					consts.FormParameterSubjectTokenType: {"urn:spec:jwt"},
					consts.FormParameterSubjectToken:     {f.token(t, jti)},
				}, []string{jti}
			},
		},
		{
			name: "ShouldMarkASubjectTokenAndAnActorTokenForAnAccessToken",
			form: func(t *testing.T, f *customJWTConsumeFixture) (url.Values, []string) {
				subject, actor := uuid.New().String(), uuid.New().String()

				return url.Values{
					consts.FormParameterSubjectTokenType: {"urn:spec:jwt"},
					consts.FormParameterSubjectToken:     {f.token(t, subject)},
					consts.FormParameterActorTokenType:   {"urn:spec:jwt"},
					consts.FormParameterActorToken:       {f.token(t, actor)},
				}, []string{subject, actor}
			},
		},
		{
			name: "ShouldMarkAnActorTokenForARefreshToken",
			form: func(t *testing.T, f *customJWTConsumeFixture) (url.Values, []string) {
				jti := uuid.New().String()

				return url.Values{
					consts.FormParameterRequestedTokenType: {consts.TokenTypeRFC8693RefreshToken},
					consts.FormParameterSubjectTokenType:   {consts.TokenTypeRFC8693RefreshToken},
					consts.FormParameterSubjectToken:       {f.refreshToken(t)},
					consts.FormParameterActorTokenType:     {"urn:spec:jwt"},
					consts.FormParameterActorToken:         {f.token(t, jti)},
				}, []string{jti}
			},
		},
		{
			name: "ShouldMarkAnActorTokenForAnIDToken",
			form: func(t *testing.T, f *customJWTConsumeFixture) (url.Values, []string) {
				jti := uuid.New().String()

				return url.Values{
					consts.FormParameterRequestedTokenType: {consts.TokenTypeRFC8693IDToken},
					consts.FormParameterSubjectTokenType:   {consts.TokenTypeRFC8693RefreshToken},
					consts.FormParameterSubjectToken:       {f.refreshToken(t)},
					consts.FormParameterActorTokenType:     {"urn:spec:jwt"},
					consts.FormParameterActorToken:         {f.token(t, jti)},
				}, []string{jti}
			},
		},
		{
			name: "ShouldMarkASubjectTokenForACustomJWT",
			form: func(t *testing.T, f *customJWTConsumeFixture) (url.Values, []string) {
				jti := uuid.New().String()

				return url.Values{
					consts.FormParameterRequestedTokenType: {"urn:spec:jwt"},
					consts.FormParameterSubjectTokenType:   {"urn:spec:jwt"},
					consts.FormParameterSubjectToken:       {f.token(t, jti)},
				}, []string{jti}
			},
		},
		{
			name: "ShouldMarkASubjectTokenForAJWTAuthorizationGrant",
			form: func(t *testing.T, f *customJWTConsumeFixture) (url.Values, []string) {
				jti := uuid.New().String()

				return url.Values{
					consts.FormParameterRequestedTokenType: {customJWTConsumeGrantType},
					consts.FormParameterAudience:           {grantTarget},
					consts.FormParameterSubjectTokenType:   {"urn:spec:jwt"},
					consts.FormParameterSubjectToken:       {f.token(t, jti)},
				}, []string{jti}
			},
		},
		{
			name:      "ShouldNotMarkWhenTheJTIIsNotValidated",
			unchecked: true,
			form: func(t *testing.T, f *customJWTConsumeFixture) (url.Values, []string) {
				return url.Values{
					consts.FormParameterSubjectTokenType: {"urn:spec:jwt"},
					consts.FormParameterSubjectToken:     {f.token(t, uuid.New().String())},
				}, nil
			},
		},
	}

	for _, store := range customJWTConsumeStores() {
		for _, tc := range testCases {
			t.Run(store.name+"/"+tc.name, func(t *testing.T) {
				exchange, memory := store.newStore()
				f := newCustomJWTConsumeFixtureWithStore(t, exchange, memory, !tc.unchecked)

				form, jtis := tc.form(t, f)
				request := f.request(form)

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.handle(t, request)))

				assert.Empty(t, f.store.TokenExchangeJTIs)

				response := oauth2.NewAccessResponse()

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.populate(t, request, response)))

				assert.NotEmpty(t, response.GetAccessToken())
				assert.Len(t, f.store.TokenExchangeJTIs, len(jtis))

				for _, jti := range jtis {
					assert.Contains(t, f.store.TokenExchangeJTIs, storage.JTIMarker{Issuer: "https://as.example.com", JTI: jti})
				}

				replay := f.request(form)

				if tc.unchecked || replay.GetRequestForm().Get(consts.FormParameterSubjectTokenType) != "urn:spec:jwt" {
					return
				}

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.handle(t, replay)))

				response = oauth2.NewAccessResponse()

				err := f.populate(t, replay, response)

				require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
				assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Claim 'jti' from the token must be used only once.")
				assert.Empty(t, response.GetAccessToken())
			})
		}
	}
}

func TestCustomJWTIsNotConsumedByARefusedRequest(t *testing.T) {
	testCases := []struct {
		name      string
		configure func(f *customJWTConsumeFixture)
		form      func(t *testing.T, f *customJWTConsumeFixture, subject string) url.Values
		details   oauth2.AuthorizationDetails
		err       error
		expected  string
	}{
		{
			name: "ShouldNotMarkWhenTheAudienceOfACustomJWTIsUnknown",
			configure: func(f *customJWTConsumeFixture) {
				f.config.RFC8693TokenTypes["urn:spec:jwt"].(*JWTType).Issue.Audience = nil
			},
			form: func(_ *testing.T, _ *customJWTConsumeFixture, subject string) url.Values {
				return url.Values{
					consts.FormParameterRequestedTokenType: {"urn:spec:jwt"},
					consts.FormParameterSubjectTokenType:   {"urn:spec:jwt"},
					consts.FormParameterSubjectToken:       {subject},
				}
			},
			err:      oauth2.ErrInvalidTarget,
			expected: "The requested resource is invalid, missing, unknown, or malformed. Unable to determine the audience for the issued JSON Web Token. The token exchange request did not include an 'audience' or 'resource' parameter and the JSON Web Token type 'urn:spec:jwt' has no default audience configured.",
		},
		{
			name: "ShouldNotMarkWhenARefreshTokenIsRequestedForAnotherSubjectToken",
			form: func(_ *testing.T, _ *customJWTConsumeFixture, subject string) url.Values {
				return url.Values{
					consts.FormParameterRequestedTokenType: {consts.TokenTypeRFC8693RefreshToken},
					consts.FormParameterSubjectTokenType:   {"urn:spec:jwt"},
					consts.FormParameterSubjectToken:       {subject},
				}
			},
			err:      oauth2.ErrInvalidRequest,
			expected: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. A refresh token can only be issued by a token exchange whose 'subject_token' is a refresh token.",
		},
		{
			name: "ShouldNotMarkWhenTheClaimsOfAJWTAuthorizationGrantAreRefused",
			configure: func(f *customJWTConsumeFixture) {
				f.config.RFC8693TokenTypes[customJWTConsumeGrantType].(*JWTType).Issue.TranscribeClaims = func(_ context.Context, _ oauth2.AccessRequester, _ map[string]any) error {
					return oauth2.ErrAccessDenied
				}
			},
			form: func(_ *testing.T, _ *customJWTConsumeFixture, subject string) url.Values {
				return url.Values{
					consts.FormParameterRequestedTokenType: {customJWTConsumeGrantType},
					consts.FormParameterAudience:           {grantTarget},
					consts.FormParameterSubjectTokenType:   {"urn:spec:jwt"},
					consts.FormParameterSubjectToken:       {subject},
				}
			},
			err: oauth2.ErrAccessDenied,
		},
		{
			name: "ShouldNotMarkWhenNoHandlerIssuesTheRequestedTokenType",
			form: func(_ *testing.T, _ *customJWTConsumeFixture, subject string) url.Values {
				return url.Values{
					consts.FormParameterRequestedTokenType: {customJWTConsumeUnissuedType},
					consts.FormParameterSubjectTokenType:   {"urn:spec:jwt"},
					consts.FormParameterSubjectToken:       {subject},
				}
			},
		},
		{
			name: "ShouldNotMarkWhenTheActorIsNotIdentified",
			form: func(t *testing.T, f *customJWTConsumeFixture, subject string) url.Values {
				actor := createJWT(t.Context(), f.client, f.strategy, jwt.MapClaims{
					consts.ClaimIssuer:         "https://as.example.com",
					consts.ClaimJWTID:          uuid.New().String(),
					consts.ClaimExpirationTime: time.Now().Add(10 * time.Minute).Unix(),
					consts.ClaimIssuedAt:       time.Now().Unix(),
				})

				return url.Values{
					consts.FormParameterSubjectTokenType: {"urn:spec:jwt"},
					consts.FormParameterSubjectToken:     {subject},
					consts.FormParameterActorTokenType:   {"urn:spec:jwt"},
					consts.FormParameterActorToken:       {actor},
				}
			},
			err:      oauth2.ErrInvalidRequest,
			expected: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'actor_token' does not identify the actor as it has neither a 'sub' nor a 'client_id' claim.",
		},
		{
			name: "ShouldNotMarkWhenTheAuthorizationDetailsAreRejected",
			configure: func(f *customJWTConsumeFixture) {
				f.config.AuthorizationDetailsTypeHandlers = []oauth2.AuthorizationDetailsTypeHandler{internal.PaymentInitiationTypeHandler{}}
			},
			form: func(t *testing.T, f *customJWTConsumeFixture, subject string) url.Values {
				return url.Values{
					consts.FormParameterSubjectTokenType: {"urn:spec:jwt"},
					consts.FormParameterSubjectToken:     {subject},
					consts.FormParameterActorTokenType:   {"urn:spec:jwt"},
					consts.FormParameterActorToken:       {f.token(t, uuid.New().String())},
				}
			},
			details: oauth2.AuthorizationDetails{{Type: internal.AuthorizationDetailsTypePaymentInitiation, Actions: []string{idjagActionStatus}}},
			err:     oauth2.ErrInvalidAuthorizationDetails,
		},
	}

	for _, store := range customJWTConsumeStores() {
		for _, tc := range testCases {
			t.Run(store.name+"/"+tc.name, func(t *testing.T) {
				exchange, memory := store.newStore()
				f := newCustomJWTConsumeFixtureWithStore(t, exchange, memory, true)

				if tc.configure != nil {
					tc.configure(f)
				}

				jti := uuid.New().String()
				subject := f.token(t, jti)

				request := f.request(tc.form(t, f, subject))
				request.SetRequestedAuthorizationDetails(tc.details)

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.handle(t, request)))

				response := oauth2.NewAccessResponse()

				err := f.populate(t, request, response)

				if tc.err == nil {
					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
				} else {
					require.ErrorIs(t, err, tc.err)
				}

				if tc.expected != "" {
					assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.expected)
				}

				assert.Empty(t, response.GetAccessToken())
				assert.Empty(t, f.store.TokenExchangeJTIs)
				assert.Empty(t, f.store.AccessTokens)

				retry := f.request(url.Values{
					consts.FormParameterSubjectTokenType: {"urn:spec:jwt"},
					consts.FormParameterSubjectToken:     {subject},
				})

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.handle(t, retry)))
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.populate(t, retry, response)))

				assert.NotEmpty(t, response.GetAccessToken())
				assert.Len(t, f.store.TokenExchangeJTIs, 1)
				assert.Contains(t, f.store.TokenExchangeJTIs, storage.JTIMarker{Issuer: "https://as.example.com", JTI: jti})
			})
		}
	}
}

func TestCustomJWTIsNotMarkedWithoutStorage(t *testing.T) {
	f := newCustomJWTConsumeFixture(t, true)

	request := f.request(url.Values{
		consts.FormParameterSubjectTokenType: {"urn:spec:jwt"},
		consts.FormParameterSubjectToken:     {f.token(t, uuid.New().String())},
	})

	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.handle(t, request)))

	f.access.Storage = nil

	response := oauth2.NewAccessResponse()

	err := f.populate(t, request, response)

	require.ErrorIs(t, err, oauth2.ErrServerError)
	assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. Failed to perform token exchange because the storage required to validate the 'jti' claim of a JSON Web Token is not configured.")
	assert.Empty(t, response.GetAccessToken())
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

	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.handle(t, request)))
	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.populate(t, request, oauth2.NewAccessResponse())))

	assert.Len(t, f.store.TokenExchangeJTIs, 1)
	assert.Contains(t, f.store.TokenExchangeJTIs, storage.JTIMarker{Issuer: "https://as.example.com", JTI: jti})
}

func TestCustomJWTIsMarkedInTheTransactionThatIssues(t *testing.T) {
	testCases := []struct {
		name      string
		requested string
		persisted int
	}{
		{name: "ShouldMarkWithTheAccessTokenSession", persisted: 1},
		{name: "ShouldMarkOnceACustomJWTIsSigned", requested: "urn:spec:jwt"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := newCustomJWTConsumeFixture(t, true)

			store := &transactionalCustomJWTStore{MemoryStore: f.store}

			f.access.Storage, f.access.TokenRevocationStorage, f.custom.Storage = store, store, store

			subject := f.token(t, uuid.New().String())

			form := func(extra url.Values) url.Values {
				values := url.Values{
					consts.FormParameterSubjectTokenType: {"urn:spec:jwt"},
					consts.FormParameterSubjectToken:     {subject},
				}

				if tc.requested != "" {
					values.Set(consts.FormParameterRequestedTokenType, tc.requested)
				}

				for name, value := range extra {
					values[name] = value
				}

				return values
			}

			first := f.request(form(nil))

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.handle(t, first)))
			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.populate(t, first, oauth2.NewAccessResponse())))

			assert.Equal(t, 1, store.begins)
			assert.Equal(t, 1, store.commits)
			assert.Equal(t, 0, store.rollbacks)
			assert.Len(t, f.store.AccessTokens, tc.persisted)

			actor := uuid.New().String()
			actorToken := f.token(t, actor)

			second := f.request(form(url.Values{
				consts.FormParameterActorTokenType: {"urn:spec:jwt"},
				consts.FormParameterActorToken:     {actorToken},
			}))

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.handle(t, second)))

			response := oauth2.NewAccessResponse()

			err := f.populate(t, second, response)

			require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
			assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Claim 'jti' from the token must be used only once.")
			assert.Empty(t, response.GetAccessToken())
			assert.Equal(t, 2, store.begins)
			assert.Equal(t, 1, store.commits)
			assert.Equal(t, 1, store.rollbacks)
			assert.Len(t, f.store.AccessTokens, tc.persisted)
			assert.NotContains(t, f.store.TokenExchangeJTIs, storage.JTIMarker{Issuer: "https://as.example.com", JTI: actor})

			third := f.request(url.Values{
				consts.FormParameterSubjectTokenType: {"urn:spec:jwt"},
				consts.FormParameterSubjectToken:     {f.token(t, uuid.New().String())},
				consts.FormParameterActorTokenType:   {"urn:spec:jwt"},
				consts.FormParameterActorToken:       {actorToken},
			})

			if tc.requested != "" {
				third.Form.Set(consts.FormParameterRequestedTokenType, tc.requested)
			}

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.handle(t, third)))

			response = oauth2.NewAccessResponse()

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.populate(t, third, response)))
			assert.NotEmpty(t, response.GetAccessToken())
			assert.Contains(t, f.store.TokenExchangeJTIs, storage.JTIMarker{Issuer: "https://as.example.com", JTI: actor})
			assert.Equal(t, 3, store.begins)
			assert.Equal(t, 2, store.commits)
			assert.Equal(t, 1, store.rollbacks)
		})
	}
}

func TestRefusedSingleUseTokenLeavesTheSubjectRefreshTokenActive(t *testing.T) {
	testCases := []struct {
		name      string
		requested string
	}{
		{name: "ShouldNotRotateForAnAccessToken"},
		{name: "ShouldNotRotateForARefreshToken", requested: consts.TokenTypeRFC8693RefreshToken},
	}

	for _, store := range customJWTConsumeStores() {
		for _, tc := range testCases {
			t.Run(store.name+"/"+tc.name, func(t *testing.T) {
				exchange, memory := store.newStore()
				f := newCustomJWTConsumeFixtureWithStore(t, exchange, memory, true)

				used := f.token(t, uuid.New().String())

				spend := f.request(url.Values{
					consts.FormParameterSubjectTokenType: {"urn:spec:jwt"},
					consts.FormParameterSubjectToken:     {used},
				})

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.handle(t, spend)))
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.populate(t, spend, oauth2.NewAccessResponse())))

				subject := f.refreshToken(t)
				signature := f.core.RefreshTokenSignature(t.Context(), subject)

				form := func(actor string) url.Values {
					values := url.Values{
						consts.FormParameterSubjectTokenType: {consts.TokenTypeRFC8693RefreshToken},
						consts.FormParameterSubjectToken:     {subject},
						consts.FormParameterActorTokenType:   {"urn:spec:jwt"},
						consts.FormParameterActorToken:       {actor},
					}

					if tc.requested != "" {
						values.Set(consts.FormParameterRequestedTokenType, tc.requested)
					}

					return values
				}

				refused := f.request(form(used))

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.handle(t, refused)))

				response := oauth2.NewAccessResponse()

				err := f.populate(t, refused, response)

				require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
				assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Claim 'jti' from the token must be used only once.")
				assert.Empty(t, response.GetAccessToken())
				assert.Empty(t, response.GetExtra(consts.FormParameterRefreshToken))

				_, err = exchange.GetRefreshTokenSession(t.Context(), signature, nil)
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				retried := f.request(form(f.token(t, uuid.New().String())))

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.handle(t, retried)))

				response = oauth2.NewAccessResponse()

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.populate(t, retried, response)))

				issued, _ := response.GetExtra(consts.FormParameterRefreshToken).(string)

				if tc.requested == consts.TokenTypeRFC8693RefreshToken {
					issued = response.GetAccessToken()
				}

				require.NotEmpty(t, issued)

				_, err = exchange.GetRefreshTokenSession(t.Context(), signature, nil)
				require.ErrorIs(t, err, oauth2.ErrInactiveToken)

				_, err = exchange.GetRefreshTokenSession(t.Context(), f.core.RefreshTokenSignature(t.Context(), issued), nil)
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
			})
		}
	}
}

func TestFailedRotationRollsBackTheSingleUseToken(t *testing.T) {
	testCases := []struct {
		name      string
		requested string
	}{
		{name: "ShouldRestoreForAnAccessToken"},
		{name: "ShouldRestoreForARefreshToken", requested: consts.TokenTypeRFC8693RefreshToken},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := newCustomJWTConsumeFixture(t, true)

			store := &transactionalCustomJWTStore{MemoryStore: f.store}
			failing := &failingRotationStore{transactionalCustomJWTStore: store}

			f.access.Storage, f.access.TokenRevocationStorage = store, failing
			f.refresh.Storage, f.refresh.TokenRevocationStorage = store, failing

			actor := uuid.New().String()

			request := f.request(url.Values{
				consts.FormParameterSubjectTokenType: {consts.TokenTypeRFC8693RefreshToken},
				consts.FormParameterSubjectToken:     {f.refreshToken(t)},
				consts.FormParameterActorTokenType:   {"urn:spec:jwt"},
				consts.FormParameterActorToken:       {f.token(t, actor)},
			})

			if tc.requested != "" {
				request.Form.Set(consts.FormParameterRequestedTokenType, tc.requested)
			}

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.handle(t, request)))

			response := oauth2.NewAccessResponse()

			require.ErrorIs(t, f.populate(t, request, response), oauth2.ErrServerError)
			assert.Empty(t, response.GetAccessToken())
			assert.Equal(t, 1, failing.rotations)
			assert.Equal(t, 1, store.begins)
			assert.Equal(t, 0, store.commits)
			assert.Equal(t, 1, store.rollbacks)
			assert.NotContains(t, f.store.TokenExchangeJTIs, storage.JTIMarker{Issuer: "https://as.example.com", JTI: actor})
		})
	}
}

func TestSingleUseActorIsConsumedOnceAcrossSubjectRefreshTokens(t *testing.T) {
	testCases := []struct {
		name      string
		requested string
	}{
		{name: "ShouldIssueOneAccessToken"},
		{name: "ShouldIssueOneRefreshToken", requested: consts.TokenTypeRFC8693RefreshToken},
	}

	for _, store := range customJWTConsumeStores() {
		for _, tc := range testCases {
			t.Run(store.name+"/"+tc.name, func(t *testing.T) {
				exchange, memory := store.newStore()
				f := newCustomJWTConsumeFixtureWithStore(t, exchange, memory, true)

				actor := f.token(t, uuid.New().String())

				const n = 16

				var (
					ready, done sync.WaitGroup
					start       = make(chan struct{})
					errs        = make([]error, n)
					signatures  = make([]string, n)
				)

				for i := range n {
					subject := f.refreshToken(t)

					signatures[i] = f.core.RefreshTokenSignature(t.Context(), subject)

					form := url.Values{
						consts.FormParameterSubjectTokenType: {consts.TokenTypeRFC8693RefreshToken},
						consts.FormParameterSubjectToken:     {subject},
						consts.FormParameterActorTokenType:   {"urn:spec:jwt"},
						consts.FormParameterActorToken:       {actor},
					}

					if tc.requested != "" {
						form.Set(consts.FormParameterRequestedTokenType, tc.requested)
					}

					request := f.request(form)

					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.handle(t, request)))

					ready.Add(1)
					done.Add(1)

					go func() {
						defer done.Done()

						ready.Done()
						<-start

						errs[i] = f.populate(t, request, oauth2.NewAccessResponse())
					}()
				}

				ready.Wait()
				close(start)
				done.Wait()

				var succeeded, active int

				for i, err := range errs {
					_, lookup := exchange.GetRefreshTokenSession(t.Context(), signatures[i], nil)

					if err == nil {
						succeeded++

						require.ErrorIs(t, lookup, oauth2.ErrInactiveToken)

						continue
					}

					require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
					assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Claim 'jti' from the token must be used only once.")

					if lookup == nil {
						active++
					}
				}

				assert.Equal(t, 1, succeeded)
				assert.Equal(t, n-1, active)
			})
		}
	}
}

func TestCustomJWTIsConsumedOnceByConcurrentRequests(t *testing.T) {
	testCases := []struct {
		name      string
		requested string
		persisted int
	}{
		{name: "ShouldIssueOneAccessToken", persisted: 1},
		{name: "ShouldIssueOneCustomJWT", requested: "urn:spec:jwt"},
		{name: "ShouldIssueOneJWTAuthorizationGrant", requested: customJWTConsumeGrantType},
	}

	for _, store := range customJWTConsumeStores() {
		for _, tc := range testCases {
			t.Run(store.name+"/"+tc.name, func(t *testing.T) {
				exchange, memory := store.newStore()
				f := newCustomJWTConsumeFixtureWithStore(t, exchange, memory, true)

				token := f.token(t, uuid.New().String())

				const n = 16

				var (
					ready, done sync.WaitGroup
					start       = make(chan struct{})
					errs        = make([]error, n)
					responses   = make([]*oauth2.AccessResponse, n)
				)

				for i := range n {
					form := url.Values{
						consts.FormParameterSubjectTokenType: {"urn:spec:jwt"},
						consts.FormParameterSubjectToken:     {token},
					}

					if tc.requested != "" {
						form.Set(consts.FormParameterRequestedTokenType, tc.requested)
						form.Set(consts.FormParameterAudience, grantTarget)
					}

					request := f.request(form)

					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.handle(t, request)))

					responses[i] = oauth2.NewAccessResponse()

					ready.Add(1)
					done.Add(1)

					go func() {
						defer done.Done()

						ready.Done()
						<-start

						errs[i] = f.populate(t, request, responses[i])
					}()
				}

				ready.Wait()
				close(start)
				done.Wait()

				var succeeded int

				for i, err := range errs {
					if err == nil {
						succeeded++

						assert.NotEmpty(t, responses[i].GetAccessToken())

						continue
					}

					require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
					assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Claim 'jti' from the token must be used only once.")
					assert.Empty(t, responses[i].GetAccessToken())
				}

				assert.Equal(t, 1, succeeded)
				assert.Len(t, f.store.AccessTokens, tc.persisted)
			})
		}
	}
}

func TestCustomJWTExpiration(t *testing.T) {
	const (
		invalid = "Claim 'exp' from token is not a valid expiration time."
		future  = "Claim 'exp' from token is too far in the future."
	)

	testCases := []struct {
		name string
		exp  any
		hint string
	}{
		{name: "ShouldAcceptAFutureExpiration", exp: time.Now().Add(10 * time.Minute).Unix()},
		{name: "ShouldAcceptAFractionalExpiration", exp: float64(time.Now().Add(10*time.Minute).Unix()) + 0.5},
		{name: "ShouldRejectZero", exp: 0, hint: invalid},
		{name: "ShouldRejectNull", exp: nil, hint: invalid},
		{name: "ShouldRejectAFractionOfASecond", exp: 0.5, hint: invalid},
		{name: "ShouldRejectBeyondTheWindow", exp: time.Now().Add(2 * time.Hour).Unix(), hint: future},
		{name: "ShouldRejectAValueLargerThanAnInt64", exp: 1e300, hint: future},
		{name: "ShouldRejectTheLargestInt64", exp: int64(math.MaxInt64), hint: future},
	}

	roles := []struct {
		name string
		form func(f *customJWTConsumeFixture, t *testing.T, token string) url.Values
	}{
		{
			name: "Subject",
			form: func(_ *customJWTConsumeFixture, _ *testing.T, token string) url.Values {
				return url.Values{consts.FormParameterSubjectTokenType: {"urn:spec:jwt"}, consts.FormParameterSubjectToken: {token}}
			},
		},
		{
			name: "Actor",
			form: func(f *customJWTConsumeFixture, t *testing.T, token string) url.Values {
				return url.Values{
					consts.FormParameterSubjectTokenType: {"urn:spec:jwt"},
					consts.FormParameterSubjectToken:     {f.token(t, uuid.New().String())},
					consts.FormParameterActorTokenType:   {"urn:spec:jwt"},
					consts.FormParameterActorToken:       {token},
				}
			},
		},
	}

	for _, role := range roles {
		for _, tc := range testCases {
			t.Run(role.name+"/"+tc.name, func(t *testing.T) {
				f := newCustomJWTConsumeFixture(t, true)

				token := f.malformedToken(t, map[string]any{
					consts.ClaimIssuer:         "https://as.example.com",
					consts.ClaimSubject:        "peter",
					consts.ClaimAudience:       []string{f.client.GetID()},
					consts.ClaimJWTID:          uuid.New().String(),
					consts.ClaimExpirationTime: tc.exp,
				})

				err := f.custom.HandleTokenEndpointRequest(t.Context(), f.request(role.form(f, t, token)))

				if tc.hint == "" {
					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

					return
				}

				require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
				assert.Equal(t, tc.hint, oauth2.ErrorToRFC6749Error(err).HintField)
			})
		}
	}
}

const (
	customJWTConsumeGrantType    = "urn:spec:grant"
	customJWTConsumeUnissuedType = "urn:spec:unissued"
)

func customJWTConsumeStores() []struct {
	name     string
	newStore func() (rfc8693ExchangeStore, *storage.MemoryStore)
} {
	return []struct {
		name     string
		newStore func() (rfc8693ExchangeStore, *storage.MemoryStore)
	}{
		{
			name: "MemoryStore",
			newStore: func() (rfc8693ExchangeStore, *storage.MemoryStore) {
				store := storage.NewExampleStore()

				return &exchangeMemoryStore{store}, store
			},
		},
		{
			name: "HydratingMemoryStore",
			newStore: func() (rfc8693ExchangeStore, *storage.MemoryStore) {
				store := storage.NewHydratingMemoryStore()
				store.MemoryStore = storage.NewExampleStore()

				return &exchangeHydratingStore{store}, store.MemoryStore
			},
		},
	}
}

func newCustomJWTConsumeFixture(t *testing.T, validate bool) *customJWTConsumeFixture {
	t.Helper()

	store := storage.NewExampleStore()

	return newCustomJWTConsumeFixtureWithStore(t, &exchangeMemoryStore{store}, store, validate)
}

func newCustomJWTConsumeFixtureWithStore(t *testing.T, exchange rfc8693ExchangeStore, store *storage.MemoryStore, validate bool) *customJWTConsumeFixture {
	t.Helper()

	cfg := newSpecConfig(t)
	cfg.RefreshTokenScopes = []string{}
	cfg.RFC8693TokenTypes["urn:spec:jwt"].(*JWTType).Validate.ValidateJTI = validate
	cfg.RFC8693TokenTypes[customJWTConsumeUnissuedType] = &DefaultTokenType{Name: customJWTConsumeUnissuedType}
	cfg.RFC8693TokenTypes[customJWTConsumeGrantType] = &JWTType{
		Name:  customJWTConsumeGrantType,
		Issue: &JWTIssueConfig{Issuer: grantIssuer, AuthorizationGrant: true, Expiry: 5 * time.Minute},
	}

	client := &oauth2.DefaultRegisteredClient{
		DefaultClient: &oauth2.DefaultClient{
			ID:           "my-client",
			ClientSecret: oauth2.NewPlainTextClientSecret("secret"),
			GrantTypes:   []string{consts.GrantTypeOAuthTokenExchange, consts.GrantTypeRefreshToken},
			Scopes:       []string{consts.ScopeOpenID},
			Audience:     []string{grantTarget},
		},
		TokenExchangeAuthorizationGrant: true,
		TokenExchangeRefreshToken:       true,
		TokenExchangeOwnRefreshToken:    true,
	}

	core := &hoauth2.HMACCoreStrategy{Enigma: &hmac.HMACStrategy{Config: cfg}, Config: cfg}
	strategy := &jwt.DefaultStrategy{Config: cfg, Issuer: jwt.NewDefaultIssuerRS256Unverified(key)}

	return &customJWTConsumeFixture{
		config:   cfg,
		store:    store,
		exchange: exchange,
		client:   client,
		key:      key,
		core:     core,
		strategy: strategy,
		grant:    &TokenExchangeGrantHandler{Config: cfg, ScopeStrategy: cfg.ScopeStrategy, AudienceStrategy: oauth2.ExactAudienceStrategy, ResourceStrategy: oauth2.ExactAudienceStrategy},
		access:   &AccessTokenTypeHandler{Config: cfg, AccessTokenLifespan: 5 * time.Minute, RefreshTokenLifespan: 5 * time.Minute, CoreStrategy: core, ScopeStrategy: cfg.ScopeStrategy, Storage: exchange, TokenRevocationStorage: exchange},
		refresh:  &RefreshTokenTypeHandler{Config: cfg, RefreshTokenLifespan: 5 * time.Minute, CoreStrategy: core, ScopeStrategy: cfg.ScopeStrategy, Storage: exchange, TokenRevocationStorage: exchange},
		id:       &IDTokenTypeHandler{Config: cfg, Strategy: strategy, IssueStrategy: &openid.DefaultStrategy{Strategy: strategy, Config: cfg}, ValidationStrategy: &openid.DefaultIDTokenValidationStrategy{Strategy: strategy}, Storage: exchange},
		custom:   &CustomJWTTypeHandler{Config: cfg, Strategy: strategy, Storage: exchange},
	}
}

type customJWTConsumeFixture struct {
	key      any
	config   *oauth2.Config
	store    *storage.MemoryStore
	exchange rfc8693ExchangeStore
	client   oauth2.Client
	core     hoauth2.CoreStrategy
	strategy jwt.Strategy
	grant    *TokenExchangeGrantHandler
	access   *AccessTokenTypeHandler
	refresh  *RefreshTokenTypeHandler
	id       *IDTokenTypeHandler
	custom   *CustomJWTTypeHandler
}

func (f *customJWTConsumeFixture) handlers() []oauth2.TokenEndpointHandler {
	return []oauth2.TokenEndpointHandler{f.grant, f.access, f.refresh, f.id, f.custom}
}

func (f *customJWTConsumeFixture) handle(t *testing.T, request oauth2.AccessRequester) error {
	t.Helper()

	for _, handler := range f.handlers() {
		if err := handler.HandleTokenEndpointRequest(t.Context(), request); err != nil && !errors.Is(err, oauth2.ErrUnknownRequest) {
			return err
		}
	}

	return nil
}

func (f *customJWTConsumeFixture) populate(t *testing.T, request oauth2.AccessRequester, response oauth2.AccessResponder) error {
	t.Helper()

	for _, handler := range f.handlers() {
		if err := handler.PopulateTokenEndpointResponse(t.Context(), request, response); err != nil && !errors.Is(err, oauth2.ErrUnknownRequest) {
			return err
		}
	}

	return nil
}

func (f *customJWTConsumeFixture) refreshToken(t *testing.T) string {
	t.Helper()

	return mintScopedRefreshToken(t.Context(), f.core, f.exchange, f.client, oauth2.Arguments{consts.ScopeOpenID})
}

func (f *customJWTConsumeFixture) token(t *testing.T, jti string) string {
	t.Helper()

	return createJWT(t.Context(), f.client, f.strategy, jwt.MapClaims{
		consts.ClaimIssuer:         "https://as.example.com",
		consts.ClaimSubject:        "peter",
		consts.ClaimJWTID:          jti,
		consts.ClaimExpirationTime: time.Now().Add(10 * time.Minute).Unix(),
		consts.ClaimIssuedAt:       time.Now().Unix(),
	})
}

func (f *customJWTConsumeFixture) malformedToken(t *testing.T, claims map[string]any) string {
	t.Helper()

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: &jose.JSONWebKey{Key: f.key, KeyID: "default"}}, (&jose.SignerOptions{}).WithType(jwt.JSONWebTokenTypeJWT))
	require.NoError(t, err)

	token, err := josejwt.Signed(signer).UnsafeSkipClaimsValidation().Claims(claims).Serialize()
	require.NoError(t, err)

	return token
}

func (f *customJWTConsumeFixture) request(form url.Values) *oauth2.AccessRequest {
	form.Set(consts.FormParameterGrantType, consts.GrantTypeOAuthTokenExchange)

	return &oauth2.AccessRequest{
		GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthTokenExchange},
		Request: oauth2.Request{
			ID:                uuid.New().String(),
			Client:            f.client,
			Form:              form,
			RequestedAudience: oauth2.Arguments(form[consts.FormParameterAudience]),
			Session:           newSpecSession("peter"),
		},
	}
}

type transactionalCustomJWTStore struct {
	*storage.MemoryStore

	jtis                       map[storage.JTIMarker]time.Time
	begins, commits, rollbacks int
}

func (s *transactionalCustomJWTStore) BeginTX(ctx context.Context) (context.Context, error) {
	s.begins++
	s.jtis = maps.Clone(s.TokenExchangeJTIs)

	return ctx, nil
}

func (s *transactionalCustomJWTStore) Commit(_ context.Context) error {
	s.commits++

	return nil
}

func (s *transactionalCustomJWTStore) Rollback(_ context.Context) error {
	s.rollbacks++
	s.TokenExchangeJTIs = s.jtis

	return nil
}

type failingRotationStore struct {
	*transactionalCustomJWTStore

	rotations int
}

func (s *failingRotationStore) RotateRefreshToken(_ context.Context, _, _ string) error {
	s.rotations++

	return errors.New("the storage is unavailable")
}
