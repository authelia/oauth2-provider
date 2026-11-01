// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
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

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	. "authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/handler/rfc9449"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/hmac"
	"authelia.com/provider/oauth2/token/jwt"
)

// §13.6: the scope of an access token subject is its grant, and storage is not consulted.
func TestTxnTokenScopeCeilingAccessToken(t *testing.T) {
	for name, store := range txnIssueStores() {
		t.Run(name, func(t *testing.T) {
			f := newTxnIssueFixture(t, store)

			token := f.mint(t, txnMint{scopes: []string{"trade.stocks"}})

			_, err := f.exchange(t, txnExchange{subjectToken: token, scopes: []string{"trade.bonds"}})

			require.ErrorIs(t, err, oauth2.ErrInvalidScope)
			assert.Empty(t, f.scopes.calls)

			_, err = f.exchange(t, txnExchange{subjectToken: token, scopes: []string{"trade.stocks"}})

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
			assert.Empty(t, f.scopes.calls)
		})
	}
}

// §13.14: a subject token that carries no scope takes its ceiling from storage, and an undeterminable scope is refused.
func TestTxnTokenScopeCeilingFromStorage(t *testing.T) {
	failure := errors.New("the database is down")

	outcomes := []struct {
		name    string
		scopes  []string
		noStore bool
		failure error
		want    error
	}{
		{name: "ShouldSucceedWithinTheResult", scopes: []string{"trade.stocks", "trade.bonds"}},
		{name: "ShouldRefuseOutsideTheResult", scopes: []string{"trade.bonds"}, want: oauth2.ErrInvalidScope},
		{name: "ShouldRefuseAnEmptyResult", scopes: []string{}, want: oauth2.ErrInvalidRequest},
		{name: "ShouldRefuseANilResult", want: oauth2.ErrInvalidRequest},
		{name: "ShouldRefuseNilStorage", noStore: true, want: oauth2.ErrInvalidRequest},
		{name: "ShouldReturnServerErrorOnAStorageError", failure: failure, want: oauth2.ErrServerError},
	}

	for _, kind := range txnStorageSubjects() {
		for _, outcome := range outcomes {
			t.Run(kind.name+"/"+outcome.name, func(t *testing.T) {
				f := newTxnIssueFixture(t, storage.NewExampleStore())
				f.scopes.scopes, f.scopes.err = outcome.scopes, outcome.failure

				if outcome.noStore {
					f.txn.Storage = nil
				}

				_, err := f.exchange(t, txnExchange{subjectType: kind.subjectType(f), subjectToken: kind.token(t, f), scopes: []string{"trade.stocks"}})

				if outcome.want != nil {
					require.ErrorIs(t, err, outcome.want)
				} else {
					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
				}

				if outcome.failure != nil {
					assert.ErrorIs(t, err, failure)
				}

				if outcome.noStore {
					assert.Empty(t, f.scopes.calls)

					return
				}

				require.Len(t, f.scopes.calls, 1)

				call := f.scopes.calls[0]

				assert.Equal(t, txnClientID, call.client.GetID())
				assert.Equal(t, kind.subjectType(f), call.subjectType)
				assert.Equal(t, "alice", call.subject)
				assert.Equal(t, "alice", call.claims[consts.ClaimSubject])
			})
		}
	}
}

func TestTxnTokenScopeCeilingStorageCannotChangeTheSession(t *testing.T) {
	for _, kind := range txnStorageSubjects() {
		t.Run(kind.name, func(t *testing.T) {
			f := newTxnIssueFixture(t, storage.NewExampleStore())
			f.scopes.scopes = []string{"trade.stocks"}
			f.scopes.mutate = func(claims map[string]any) {
				delete(claims, consts.ClaimSubject)
				claims["injected"] = true
			}

			request, _, err := f.run(t, txnExchange{subjectType: kind.subjectType(f), subjectToken: kind.token(t, f), scopes: []string{"trade.stocks"}})
			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

			claims := request.GetSession().(Session).GetSubjectToken()

			assert.Equal(t, "alice", claims[consts.ClaimSubject])
			assert.NotContains(t, claims, "injected")
		})
	}
}

// §13.6: a scope the workload wrote into its own subject token is not a ceiling.
func TestTxnTokenScopeClaimOfAssertedSubjectIgnored(t *testing.T) {
	testCases := []struct {
		name        string
		subjectType string
		token       func(t *testing.T, f *txnIssueFixture) string
	}{
		{"ShouldIgnoreSelfSigned", consts.TokenTypeRFC8693SelfSigned, func(t *testing.T, f *txnIssueFixture) string {
			claims := selfSignedClaims()
			claims[consts.ClaimScope] = "trade.stocks trade.bonds"

			return signToken(t, jose.ES256, f.workloadKey, txnKeyID, claims, nil)
		}},
		{"ShouldIgnoreUnsignedJSON", consts.TokenTypeRFC8693UnsignedJSON, func(t *testing.T, f *txnIssueFixture) string {
			return `{"sub":"alice","scope":"trade.stocks trade.bonds"}`
		}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := newTxnIssueFixture(t, storage.NewExampleStore())
			f.scopes.scopes = []string{"trade.stocks"}

			_, err := f.exchange(t, txnExchange{subjectType: tc.subjectType, subjectToken: tc.token(t, f), scopes: []string{"trade.bonds"}})

			require.ErrorIs(t, err, oauth2.ErrInvalidScope)
			require.Len(t, f.scopes.calls, 1)

			_, err = f.exchange(t, txnExchange{subjectType: tc.subjectType, subjectToken: tc.token(t, f), scopes: []string{"trade.stocks"}})

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
		})
	}
}

func TestTxnTokenScopeClaimOfCustomJWTIsTheCeiling(t *testing.T) {
	testCases := []struct {
		name  string
		claim any
		want  error
	}{
		{name: "ShouldSucceedWithinAString", claim: "trade.stocks trade.bonds"},
		{name: "ShouldSucceedWithinAnArray", claim: []string{"trade.stocks"}},
		{name: "ShouldRefuseOutside", claim: "trade.bonds", want: oauth2.ErrInvalidScope},
		{name: "ShouldRefuseAnEmptyClaim", claim: "", want: oauth2.ErrInvalidScope},
		{name: "ShouldRefuseAMalformedClaim", claim: 1, want: oauth2.ErrInvalidScope},
		{name: "ShouldRefuseANullClaim", claim: nil, want: oauth2.ErrInvalidScope},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := newTxnIssueFixture(t, storage.NewExampleStore())
			f.scopes.scopes = []string{"trade.stocks"}

			_, err := f.exchange(t, txnExchange{subjectType: txnJWTType, subjectToken: f.customJWT(t, map[string]any{consts.ClaimScope: tc.claim}), scopes: []string{"trade.stocks"}})

			if tc.want != nil {
				require.ErrorIs(t, err, tc.want)
			} else {
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
			}

			assert.Empty(t, f.scopes.calls)
		})
	}
}

func TestTxnTokenScopeCeilingUsesTheScopeStrategyOfTheClient(t *testing.T) {
	testCases := []struct {
		name     string
		strategy oauth2.ScopeStrategy
		want     error
	}{
		{name: "ShouldUseTheConfiguredStrategy"},
		{name: "ShouldPreferTheStrategyOfTheClient", strategy: oauth2.ExactScopeStrategy, want: oauth2.ErrInvalidScope},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := newTxnIssueFixture(t, storage.NewExampleStore())
			f.client.scopeStrategy = tc.strategy
			f.scopes.scopes = []string{"trade"}

			response, err := f.exchange(t, txnExchange{subjectType: consts.TokenTypeRFC8693UnsignedJSON, subjectToken: `{"sub":"alice"}`, scopes: []string{"trade.stocks"}})

			if tc.want != nil {
				require.ErrorIs(t, err, tc.want)

				return
			}

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
			assert.Equal(t, "trade.stocks", txnPayload(t, response)[consts.ClaimScope])
		})
	}
}

func TestTxnTokenScopeRelaxationOnlyForTxnTokenRequests(t *testing.T) {
	testCases := []struct {
		name        string
		subjectType string
		token       func(t *testing.T, f *txnIssueFixture) string
	}{
		{"ShouldRefuseIDToken", consts.TokenTypeRFC8693IDToken, func(t *testing.T, f *txnIssueFixture) string { return f.idToken(t, nil) }},
		{"ShouldRefuseCustomJWT", txnJWTType, func(t *testing.T, f *txnIssueFixture) string { return f.customJWT(t, nil) }},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := newTxnIssueFixture(t, storage.NewExampleStore())
			f.scopes.scopes = []string{"trade.stocks"}

			_, err := f.exchange(t, txnExchange{subjectType: tc.subjectType, subjectToken: tc.token(t, f), scopes: []string{"trade.stocks"}, requested: consts.TokenTypeRFC8693AccessToken})

			require.ErrorIs(t, err, oauth2.ErrInvalidScope)
			assert.Empty(t, f.scopes.calls)
		})
	}
}

// §9.1, §9.2: the header and the claims of an issued token.
func TestTxnTokenIssuedToken(t *testing.T) {
	for name, store := range txnIssueStores() {
		t.Run(name, func(t *testing.T) {
			f := newTxnIssueFixture(t, store)

			token := f.mint(t, txnMint{scopes: []string{"trade.stocks"}})

			before := time.Now().Unix()

			response, err := f.exchange(t, txnExchange{subjectToken: token, scopes: []string{"trade.stocks"}})
			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

			parsed, _ := parseGrant(t, response)

			assert.Equal(t, consts.JSONWebTokenTypeTxnToken, parsed.Header[consts.JSONWebTokenHeaderType])
			assert.NotEmpty(t, parsed.Header[consts.JSONWebTokenHeaderKeyIdentifier])
			assert.Equal(t, "RS256", parsed.Header[consts.JSONWebTokenHeaderAlgorithm])

			claims := txnPayload(t, response)

			assert.ElementsMatch(t, []string{consts.ClaimIssuedAt, consts.ClaimAudience, consts.ClaimExpirationTime, consts.ClaimTransaction, consts.ClaimSubject, consts.ClaimScope, consts.ClaimRequestingWorkload}, claimNames(claims))

			assert.Equal(t, txnTrustDomain, claims[consts.ClaimAudience])
			assert.Equal(t, "alice", claims[consts.ClaimSubject])
			assert.Equal(t, "trade.stocks", claims[consts.ClaimScope])
			assert.Equal(t, txnClientID, claims[consts.ClaimRequestingWorkload])
			assert.GreaterOrEqual(t, toUnix(t, claims[consts.ClaimIssuedAt]), before)
			assert.Greater(t, toUnix(t, claims[consts.ClaimExpirationTime]), toUnix(t, claims[consts.ClaimIssuedAt]))

			first, err := uuid.Parse(claims[consts.ClaimTransaction].(string))
			require.NoError(t, err)

			response, err = f.exchange(t, txnExchange{subjectToken: token, scopes: []string{"trade.stocks"}})
			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

			assert.NotEqual(t, first.String(), txnPayload(t, response)[consts.ClaimTransaction])
		})
	}
}

func TestTxnTokenIssuedSubject(t *testing.T) {
	for name, store := range txnIssueStores() {
		t.Run(name, func(t *testing.T) {
			for _, kind := range txnStorageSubjects() {
				t.Run(kind.name, func(t *testing.T) {
					f := newTxnIssueFixture(t, store)
					f.scopes.scopes = []string{"trade.stocks"}

					response, err := f.exchange(t, txnExchange{subjectType: kind.subjectType(f), subjectToken: kind.token(t, f), scopes: []string{"trade.stocks"}})
					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

					assert.Equal(t, "alice", txnPayload(t, response)[consts.ClaimSubject])
				})
			}

			t.Run("ShouldRefuseAnEmptySubject", func(t *testing.T) {
				f := newTxnIssueFixture(t, store)

				_, err := f.exchange(t, txnExchange{subjectToken: f.mint(t, txnMint{subject: "-", scopes: []string{"trade.stocks"}}), scopes: []string{"trade.stocks"}})

				assert.ErrorIs(t, err, oauth2.ErrInvalidRequest)
			})
		})
	}
}

func TestTxnTokenIssuedIgnoresTheSession(t *testing.T) {
	for name, store := range txnIssueStores() {
		t.Run(name, func(t *testing.T) {
			f := newTxnIssueFixture(t, store)

			session := newSpecSession("")
			session.Claims.Issuer = "https://stale.example"
			session.Claims.JTI = "stale"
			session.Claims.Extra = map[string]any{"email": "alice@example.com"}
			session.Extra["tenant"] = "stale"

			response, err := f.exchange(t, txnExchange{subjectToken: f.mint(t, txnMint{scopes: []string{"trade.stocks"}}), scopes: []string{"trade.stocks"}, session: session})
			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

			assert.ElementsMatch(t, []string{consts.ClaimIssuedAt, consts.ClaimAudience, consts.ClaimExpirationTime, consts.ClaimTransaction, consts.ClaimSubject, consts.ClaimScope, consts.ClaimRequestingWorkload}, claimNames(txnPayload(t, response)))
		})
	}
}

func TestTxnTokenIssuedScopeIsTheGrantedRequestedScopes(t *testing.T) {
	for name, store := range txnIssueStores() {
		t.Run(name, func(t *testing.T) {
			t.Run("ShouldOmitAScopeGrantedButNotRequested", func(t *testing.T) {
				f := newTxnIssueFixture(t, store)

				response, err := f.exchange(t, txnExchange{subjectToken: f.mint(t, txnMint{scopes: []string{"trade.stocks"}}), scopes: []string{"trade.stocks"}, granted: []string{"trade.bonds"}})
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				assert.Equal(t, "trade.stocks", txnPayload(t, response)[consts.ClaimScope])
				assert.Equal(t, "trade.stocks", response.GetExtra(consts.AccessResponseScope))
			})

			t.Run("ShouldRepeatARepeatedScopeOnce", func(t *testing.T) {
				f := newTxnIssueFixture(t, store)

				response, err := f.exchange(t, txnExchange{subjectToken: f.mint(t, txnMint{scopes: []string{"trade.stocks"}}), scopes: []string{"trade.stocks", "trade.stocks"}})
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				assert.Equal(t, "trade.stocks", txnPayload(t, response)[consts.ClaimScope])
			})

			t.Run("ShouldRefuseWhenNothingRequestedWasGranted", func(t *testing.T) {
				f := newTxnIssueFixture(t, store)

				session := newSpecSession("alice")
				session.SetSubjectToken(map[string]any{consts.ClaimSubject: "alice"})

				request := &oauth2.AccessRequest{
					GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthTokenExchange},
					Request: oauth2.Request{
						Client:         f.client,
						Session:        session,
						RequestedScope: oauth2.Arguments{"trade.stocks"},
						GrantedScope:   oauth2.Arguments{"trade.bonds"},
						Form:           url.Values{consts.FormParameterRequestedTokenType: {consts.TokenTypeRFC8693TxnToken}},
					},
				}

				assert.ErrorIs(t, f.txn.PopulateTokenEndpointResponse(t.Context(), request, oauth2.NewAccessResponse()), oauth2.ErrInvalidScope)
			})
		})
	}
}

func TestTxnTokenIssuer(t *testing.T) {
	for name, store := range txnIssueStores() {
		t.Run(name, func(t *testing.T) {
			t.Run("ShouldSetAConfiguredIssuer", func(t *testing.T) {
				f := newTxnIssueFixture(t, store)
				f.txnType.Issuer = "https://tts.example"

				response, err := f.exchange(t, txnExchange{subjectToken: f.mint(t, txnMint{scopes: []string{"trade.stocks"}}), scopes: []string{"trade.stocks"}})
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				assert.Equal(t, "https://tts.example", txnPayload(t, response)[consts.ClaimIssuer])
			})

			t.Run("ShouldRefuseTheIDTokenIssuer", func(t *testing.T) {
				f := newTxnIssueFixture(t, store)
				f.txnType.Issuer = f.cfg.IDTokenIssuer

				_, err := f.exchange(t, txnExchange{subjectToken: f.mint(t, txnMint{scopes: []string{"trade.stocks"}}), scopes: []string{"trade.stocks"}})

				assert.ErrorIs(t, err, oauth2.ErrServerError)
			})
		})
	}
}

func TestTxnTokenSigning(t *testing.T) {
	for name, store := range txnIssueStores() {
		t.Run(name, func(t *testing.T) {
			t.Run("ShouldSelectTheIssuerKeyWithTheSigningAlg", func(t *testing.T) {
				ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)

				f := newTxnIssueFixture(t, store)
				f.txnType.SigningAlg = "ES256"

				f.strategy.Issuer, err = jwt.NewDefaultIssuer(
					jose.JSONWebKey{Key: key, KeyID: "rs", Algorithm: "RS256", Use: "sig"},
					jose.JSONWebKey{Key: ecKey, KeyID: "es", Algorithm: "ES256", Use: "sig"},
				)
				require.NoError(t, err)

				response, err := f.exchange(t, txnExchange{subjectToken: f.mint(t, txnMint{scopes: []string{"trade.stocks"}}), scopes: []string{"trade.stocks"}})
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				token, err := jwt.ParseWithClaims(response.GetAccessToken(), jwt.MapClaims{}, func(_ *jwt.Token) (any, error) {
					return ecKey.Public(), nil
				})
				require.NoError(t, err)

				assert.Equal(t, "ES256", token.Header[consts.JSONWebTokenHeaderAlgorithm])
				assert.Equal(t, "es", token.Header[consts.JSONWebTokenHeaderKeyIdentifier])
				assert.Equal(t, consts.JSONWebTokenTypeTxnToken, token.Header[consts.JSONWebTokenHeaderType])
			})

			t.Run("ShouldReturnServerErrorWithoutAKey", func(t *testing.T) {
				f := newTxnIssueFixture(t, store)
				f.txnType.SigningAlg = "ES256"

				_, err := f.exchange(t, txnExchange{subjectToken: f.mint(t, txnMint{scopes: []string{"trade.stocks"}}), scopes: []string{"trade.stocks"}})

				assert.ErrorIs(t, err, oauth2.ErrServerError)
			})

			t.Run("ShouldReturnServerErrorWithoutAStrategy", func(t *testing.T) {
				f := newTxnIssueFixture(t, store)
				f.txn.Strategy = nil

				_, err := f.exchange(t, txnExchange{subjectToken: f.mint(t, txnMint{scopes: []string{"trade.stocks"}}), scopes: []string{"trade.stocks"}})

				assert.ErrorIs(t, err, oauth2.ErrServerError)
			})
		})
	}
}

// §6: the lifetime of a token, which is short and here never outlives the subject token.
func TestTxnTokenExpiry(t *testing.T) {
	for name, store := range txnIssueStores() {
		t.Run(name, func(t *testing.T) {
			testCases := []struct {
				name    string
				expiry  time.Duration
				subject time.Duration
				present func(t *testing.T, f *txnIssueFixture, expires time.Time) (subjectType, token string)
				want    time.Duration
			}{
				{name: "ShouldDefaultToFiveMinutes", subject: time.Hour, want: 5 * time.Minute},
				{name: "ShouldHonourTheExpiry", expiry: time.Minute, subject: time.Hour, want: time.Minute},
				{name: "ShouldCapToASubjectTokenExpiringSooner", expiry: time.Hour, subject: 2 * time.Minute, want: 2 * time.Minute},
				{name: "ShouldCapTheDefaultToASubjectTokenExpiringSooner", subject: 2 * time.Minute, want: 2 * time.Minute},
				{
					name: "ShouldCapToAnIDToken", expiry: time.Hour, subject: 2 * time.Minute, want: 2 * time.Minute,
					present: func(t *testing.T, f *txnIssueFixture, expires time.Time) (string, string) {
						return consts.TokenTypeRFC8693IDToken, f.idToken(t, map[string]any{consts.ClaimExpirationTime: expires.Unix()})
					},
				},
				{
					name: "ShouldCapToACustomJWT", expiry: time.Hour, subject: 2 * time.Minute, want: 2 * time.Minute,
					present: func(t *testing.T, f *txnIssueFixture, expires time.Time) (string, string) {
						return txnJWTType, f.customJWT(t, map[string]any{consts.ClaimExpirationTime: expires.Unix()})
					},
				},
				{
					name: "ShouldCapToASelfSignedToken", expiry: time.Hour, subject: 2 * time.Minute, want: 2 * time.Minute,
					present: func(t *testing.T, f *txnIssueFixture, expires time.Time) (string, string) {
						claims := selfSignedClaims()
						claims[consts.ClaimExpirationTime] = expires.Unix()

						return consts.TokenTypeRFC8693SelfSigned, signToken(t, jose.ES256, f.workloadKey, txnKeyID, claims, nil)
					},
				},
			}

			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					f := newTxnIssueFixture(t, store)
					f.txnType.Expiry = tc.expiry
					f.scopes.scopes = []string{"trade.stocks"}

					expires := time.Now().Add(tc.subject)

					exchange := txnExchange{scopes: []string{"trade.stocks"}}

					if tc.present != nil {
						exchange.subjectType, exchange.subjectToken = tc.present(t, f, expires)
					} else {
						exchange.subjectToken = f.mint(t, txnMint{scopes: []string{"trade.stocks"}, expires: expires})
					}

					response, err := f.exchange(t, exchange)
					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

					claims := txnPayload(t, response)

					assert.InDelta(t, tc.want.Seconds(), toUnix(t, claims[consts.ClaimExpirationTime])-toUnix(t, claims[consts.ClaimIssuedAt]), 2)
					assert.InDelta(t, tc.want.Seconds(), response.GetExtra(consts.AccessResponseExpiresIn), 2)
				})
			}
		})
	}
}

// A custom JWT refuses an expiry too far ahead before it can cap the issued token.
func TestTxnTokenRefusesAnOverflowingCustomJWTExpiry(t *testing.T) {
	f := newTxnIssueFixture(t, storage.NewExampleStore())
	f.scopes.scopes = []string{"trade.stocks"}

	token := f.customJWT(t, map[string]any{consts.ClaimExpirationTime: int64(math.MaxInt64 - 1024)})

	_, err := f.exchange(t, txnExchange{subjectType: txnJWTType, subjectToken: token, scopes: []string{"trade.stocks"}})

	require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
}

func TestTxnTokenRefusesSubjectExpiringWithinTheSecond(t *testing.T) {
	testCases := []struct {
		name    string
		exp     func() int64
		refused bool
	}{
		{"ShouldRefuseTheCurrentSecond", func() int64 { return time.Now().Unix() }, true},
		{"ShouldRefuseThePriorSecond", func() int64 { return time.Now().Unix() - 1 }, true},
		{"ShouldIssueWhenItEndsLater", func() int64 { return time.Now().Unix() + 30 }, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := newTxnIssueFixture(t, storage.NewExampleStore())
			f.scopes.scopes = []string{"trade.stocks"}

			value, err := json.Marshal(map[string]any{consts.ClaimSubject: "alice", consts.ClaimExpirationTime: tc.exp()})
			require.NoError(t, err)

			response, err := f.exchange(t, txnExchange{subjectType: consts.TokenTypeRFC8693UnsignedJSON, subjectToken: string(value), scopes: []string{"trade.stocks"}})

			if tc.refused {
				require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
				assert.Contains(t, oauth2.ErrorToRFC6749Error(err).HintField, consts.FormParameterSubjectToken)

				return
			}

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
			assert.NotEmpty(t, response.GetAccessToken())
		})
	}
}

// §11.4: the response, which has no refresh token.
func TestTxnTokenResponse(t *testing.T) {
	for name, store := range txnIssueStores() {
		t.Run(name, func(t *testing.T) {
			f := newTxnIssueFixture(t, store)
			f.client.refresh = true
			f.client.GrantTypes = append(f.client.GrantTypes, consts.GrantTypeRefreshToken)

			response, err := f.exchange(t, txnExchange{subjectToken: f.mint(t, txnMint{scopes: []string{"trade.stocks"}}), scopes: []string{"trade.stocks"}})
			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

			assert.NotEmpty(t, response.GetAccessToken())
			assert.Equal(t, oauth2.RFC8693NAToken, response.GetTokenType())
			assert.Equal(t, consts.TokenTypeRFC8693TxnToken, response.GetExtra(consts.FormParameterIssuedTokenType))
			assert.Equal(t, "trade.stocks", response.GetExtra(consts.AccessResponseScope))
			assert.Nil(t, response.GetExtra(consts.FormParameterRefreshToken))
		})
	}
}

func TestTxnTokenPopulateIgnoresOtherRequests(t *testing.T) {
	f := newTxnIssueFixture(t, storage.NewExampleStore())

	response := oauth2.NewAccessResponse()

	unknown := &oauth2.AccessRequest{GrantTypes: oauth2.Arguments{consts.GrantTypeClientCredentials}, Request: oauth2.Request{Form: url.Values{}, Session: newSpecSession("")}}

	assert.ErrorIs(t, f.txn.PopulateTokenEndpointResponse(t.Context(), unknown, response), oauth2.ErrUnknownRequest)

	other := &oauth2.AccessRequest{GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthTokenExchange}, Request: oauth2.Request{Form: url.Values{consts.FormParameterRequestedTokenType: {consts.TokenTypeRFC8693AccessToken}}, Session: newSpecSession("")}}

	require.NoError(t, f.txn.PopulateTokenEndpointResponse(t.Context(), other, response))
	assert.Empty(t, response.GetAccessToken())
}

// §13.4: the credential presented in the request is not carried in the issued token.
func TestTxnTokenCarriesNoPresentedCredential(t *testing.T) {
	for name, store := range txnIssueStores() {
		t.Run(name, func(t *testing.T) {
			f := newTxnIssueFixture(t, store)

			token := f.mint(t, txnMint{scopes: []string{"trade.stocks"}})

			response, err := f.exchange(t, txnExchange{subjectToken: token, scopes: []string{"trade.stocks"}})
			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

			raw, err := json.Marshal(txnPayload(t, response))
			require.NoError(t, err)

			assert.NotContains(t, string(raw), token)
			assert.NotContains(t, string(raw), strings.Split(token, ".")[len(strings.Split(token, "."))-1])
		})
	}
}

func TestTxnTokenActor(t *testing.T) {
	for name, store := range txnIssueStores() {
		t.Run(name, func(t *testing.T) {
			subjects := []struct {
				name        string
				subjectType string
				token       func(t *testing.T, f *txnIssueFixture) string
			}{
				{"AccessToken", consts.TokenTypeRFC8693AccessToken, func(t *testing.T, f *txnIssueFixture) string {
					return f.mint(t, txnMint{scopes: []string{"trade.stocks"}})
				}},
				{"SelfSigned", consts.TokenTypeRFC8693SelfSigned, func(t *testing.T, f *txnIssueFixture) string {
					return signToken(t, jose.ES256, f.workloadKey, txnKeyID, selfSignedClaims(), nil)
				}},
				{"UnsignedJSON", consts.TokenTypeRFC8693UnsignedJSON, func(t *testing.T, f *txnIssueFixture) string {
					return `{"sub":"alice"}`
				}},
			}

			for _, subject := range subjects {
				t.Run("ShouldCarryWhenAllowed/"+subject.name, func(t *testing.T) {
					f := newTxnIssueFixture(t, store)
					f.client.allowActor = true
					f.scopes.scopes = []string{"trade.stocks"}

					response, err := f.exchange(t, txnExchange{subjectType: subject.subjectType, subjectToken: subject.token(t, f), scopes: []string{"trade.stocks"}, actorToken: f.mint(t, txnMint{subject: "bob"})})
					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

					act, ok := txnPayload(t, response)[consts.ClaimActor].(map[string]any)
					require.True(t, ok)
					assert.Equal(t, "bob", act[consts.ClaimSubject])
				})

				t.Run("ShouldRefuseWhenNotAllowed/"+subject.name, func(t *testing.T) {
					f := newTxnIssueFixture(t, store)
					f.scopes.scopes = []string{"trade.stocks"}

					_, err := f.exchange(t, txnExchange{subjectType: subject.subjectType, subjectToken: subject.token(t, f), scopes: []string{"trade.stocks"}, actorToken: f.mint(t, txnMint{subject: "bob"})})

					require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
					assert.Contains(t, oauth2.ErrorToRFC6749Error(err).HintField, consts.ClaimAuthorizedActor)
				})
			}

			t.Run("ShouldNestTheActOfTheSubject", func(t *testing.T) {
				f := newTxnIssueFixture(t, store)
				f.client.allowActor = true

				response, err := f.exchange(t, txnExchange{subjectToken: f.mint(t, txnMint{scopes: []string{"trade.stocks"}, act: map[string]any{consts.ClaimSubject: "carol"}}), scopes: []string{"trade.stocks"}, actorToken: f.mint(t, txnMint{subject: "bob"})})
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				assert.Equal(t, map[string]any{consts.ClaimSubject: "bob", consts.ClaimClientIdentifier: txnClientID, consts.ClaimActor: map[string]any{consts.ClaimSubject: "carol"}}, txnPayload(t, response)[consts.ClaimActor])
			})

			t.Run("ShouldRefuseAnActOfTheSubjectWithoutAnActorToken", func(t *testing.T) {
				f := newTxnIssueFixture(t, store)

				_, err := f.exchange(t, txnExchange{subjectToken: f.mint(t, txnMint{scopes: []string{"trade.stocks"}, act: map[string]any{consts.ClaimSubject: "carol"}}), scopes: []string{"trade.stocks"}})

				require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
				assert.Contains(t, oauth2.ErrorToRFC6749Error(err).HintField, consts.FormParameterActorToken)
			})

			t.Run("ShouldOmitTheActWithoutAnActorToken", func(t *testing.T) {
				f := newTxnIssueFixture(t, store)

				response, err := f.exchange(t, txnExchange{subjectToken: f.mint(t, txnMint{scopes: []string{"trade.stocks"}}), scopes: []string{"trade.stocks"}})
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				assert.NotContains(t, txnPayload(t, response), consts.ClaimActor)
			})

			t.Run("ShouldRefuseAnActorTokenNoHandlerValidated", func(t *testing.T) {
				f := newTxnIssueFixture(t, store)
				f.client.allowActor = true

				_, err := f.exchange(t, txnExchange{subjectToken: f.mint(t, txnMint{scopes: []string{"trade.stocks"}}), scopes: []string{"trade.stocks"}, actorToken: `{"sub":"bob"}`, actorTokenType: consts.TokenTypeRFC8693UnsignedJSON})

				require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
				assert.Contains(t, oauth2.ErrorToRFC6749Error(err).HintField, consts.FormParameterActorTokenType)
			})
		})
	}
}

func TestTxnTokenSenderConstrainedSubject(t *testing.T) {
	for name, store := range txnIssueStores() {
		t.Run(name, func(t *testing.T) {
			f := newTxnIssueFixture(t, store)

			token := f.mint(t, txnMint{scopes: []string{"trade.stocks"}, jkt: bindingJKT})

			request, response, err := f.run(t, txnExchange{subjectToken: token, scopes: []string{"trade.stocks"}})
			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

			binder := &rfc9449.Handler{Config: f.cfg}
			ctx := context.WithValue(t.Context(), oauth2.RequestContextKey, httptest.NewRequest(http.MethodPost, "https://auth.example.com/token", nil))

			require.ErrorIs(t, binder.BindAccessRequest(ctx, request), oauth2.ErrInvalidDPoPProof)

			assert.NotContains(t, txnPayload(t, response), consts.ClaimConfirmation)

			require.NoError(t, binder.PopulateBoundTokenEndpointResponse(ctx, request, response))
			assert.Equal(t, oauth2.RFC8693NAToken, response.GetTokenType())
		})
	}
}

// §13.12, §13.15: a Txn-Token is not accepted as any other token this library validates.
func TestTxnTokenIsNotAcceptedElsewhere(t *testing.T) {
	for name, store := range txnIssueStores() {
		t.Run(name, func(t *testing.T) {
			testCases := []struct {
				name    string
				present func(t *testing.T, f *txnIssueFixture, token string) error
				err     error
				debug   string
			}{
				{
					name: "ShouldRefuseAsACustomJWTSubject",
					present: func(t *testing.T, f *txnIssueFixture, token string) error {
						_, err := f.exchange(t, txnExchange{subjectType: txnJWTType, subjectToken: token, scopes: []string{"trade.stocks"}})

						return err
					},
					err:   oauth2.ErrInvalidRequest,
					debug: "cannot be exchanged",
				},
				{
					name: "ShouldRefuseAsACustomJWTActor",
					present: func(t *testing.T, f *txnIssueFixture, token string) error {
						f.client.allowActor = true

						_, err := f.exchange(t, txnExchange{subjectToken: f.mint(t, txnMint{scopes: []string{"trade.stocks"}}), scopes: []string{"trade.stocks"}, actorToken: token, actorTokenType: txnJWTType})

						return err
					},
					err:   oauth2.ErrInvalidRequest,
					debug: "cannot be exchanged",
				},
				{
					name: "ShouldRefuseAsAStatelessAccessToken",
					present: func(t *testing.T, f *txnIssueFixture, token string) error {
						validator := &hoauth2.StatelessJWTValidator{
							StatelessJWTStrategy: &hoauth2.JWTProfileCoreStrategy{HMACCoreStrategy: hoauth2.NewHMACCoreStrategy(f.cfg, "authelia_%s_"), Strategy: f.strategy, Config: f.cfg},
							Config:               f.cfg,
						}

						_, err := validator.IntrospectToken(t.Context(), token, oauth2.AccessToken, oauth2.NewAccessRequest(newSpecSession("")), nil)

						return err
					},
					err:   oauth2.ErrRequestUnauthorized,
					debug: "at+jwt",
				},
				{
					name: "ShouldRefuseAsAnIDTokenSubject",
					present: func(t *testing.T, f *txnIssueFixture, token string) error {
						f.cfg.IDTokenIssuer = txnJWTIssuer

						_, err := f.exchange(t, txnExchange{subjectType: consts.TokenTypeRFC8693IDToken, subjectToken: token, requested: consts.TokenTypeRFC8693AccessToken, noScope: true})

						return err
					},
					err:   oauth2.ErrInvalidRequest,
					debug: "invalid typ",
				},
			}

			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					f := newTxnIssueFixture(t, store)

					f.txnType.Issuer = txnJWTIssuer
					f.txnType.TrustDomain = txnClientID
					f.client.Audience = []string{txnClientID}
					f.audience = txnClientID

					response, err := f.exchange(t, txnExchange{subjectToken: f.mint(t, txnMint{scopes: []string{"trade.stocks"}}), scopes: []string{"trade.stocks"}})
					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

					err = tc.present(t, f, response.GetAccessToken())

					require.ErrorIs(t, err, tc.err)
					assert.Contains(t, oauth2.ErrorToDebugRFC6749Error(err).Error(), tc.debug)
				})
			}
		})
	}
}

const (
	txnJWTType   = "urn:txn:jwt"
	txnJWTIssuer = "https://idp.example"
)

type txnIssueStore interface {
	hoauth2.AccessTokenStorage
	Storage
}

type txnScopeCall struct {
	client      oauth2.Client
	subjectType string
	subject     string
	claims      map[string]any
}

type txnScopeStub struct {
	scopes []string
	err    error
	calls  []txnScopeCall
	mutate func(claims map[string]any)
}

func (s *txnScopeStub) GetTxnTokenSubjectScopes(_ context.Context, client oauth2.Client, subjectTokenType, subject string, claims map[string]any) ([]string, error) {
	s.calls = append(s.calls, txnScopeCall{client, subjectTokenType, subject, claims})

	if s.mutate != nil {
		s.mutate(claims)
	}

	return s.scopes, s.err
}

type txnIssueClient struct {
	*oauth2.DefaultClient

	jwks          *jose.JSONWebKeySet
	allowActor    bool
	refresh       bool
	replacement   bool
	scopeStrategy oauth2.ScopeStrategy
}

func (c *txnIssueClient) GetAllowTxnTokenReplacement() bool { return c.replacement }

func (c *txnIssueClient) GetScopeStrategy(context.Context) oauth2.ScopeStrategy {
	return c.scopeStrategy
}

func (c *txnIssueClient) GetJSONWebKeys() *jose.JSONWebKeySet       { return c.jwks }
func (c *txnIssueClient) GetJSONWebKeysURI() string                 { return "" }
func (c *txnIssueClient) GetAllowUnsignedJSONSubjectToken() bool    { return true }
func (c *txnIssueClient) GetAllowOwnAccessTokenExchange() bool      { return true }
func (c *txnIssueClient) GetAllowTokenExchangeRefreshToken() bool   { return c.refresh }
func (c *txnIssueClient) GetAllowActorTokenWithoutMayAct() bool     { return c.allowActor }
func (c *txnIssueClient) GetSupportedSubjectTokenTypes() []string   { return nil }
func (c *txnIssueClient) GetSupportedActorTokenTypes() []string     { return nil }
func (c *txnIssueClient) GetSupportedRequestTokenTypes() []string   { return nil }
func (c *txnIssueClient) GetSupportedSubjectTokenIssuers() []string { return nil }
func (c *txnIssueClient) GetSupportedActorTokenIssuers() []string   { return nil }
func (c *txnIssueClient) GetTokenExchangePermitted(oauth2.Client, oauth2.RFC8693TokenType) bool {
	return true
}

type txnMint struct {
	subject string
	scopes  []string
	act     map[string]any
	jkt     string
	expires time.Time
}

type txnExchange struct {
	subjectType, subjectToken  string
	actorToken, actorTokenType string
	requested                  string
	scopes, granted            []string
	noScope                    bool
	session                    *DefaultSession
	form                       url.Values
}

type txnStorageSubject struct {
	name        string
	subjectType func(f *txnIssueFixture) string
	token       func(t *testing.T, f *txnIssueFixture) string
}

type txnIssueFixture struct {
	cfg         *oauth2.Config
	store       txnIssueStore
	client      *txnIssueClient
	core        hoauth2.CoreStrategy
	strategy    *jwt.DefaultStrategy
	txnType     *TxnTokenType
	txn         *TxnTokenTypeHandler
	scopes      *txnScopeStub
	workloadKey *ecdsa.PrivateKey
	audience    string
	handlers    []oauth2.TokenEndpointHandler
}

func newTxnIssueFixture(t *testing.T, store txnIssueStore) *txnIssueFixture {
	t.Helper()

	cfg := newSpecConfig(t)

	txnType := &TxnTokenType{Name: consts.TokenTypeRFC8693TxnToken, TrustDomain: txnTrustDomain}

	cfg.IDTokenIssuer = "https://op.example"
	cfg.RFC8693TokenTypes[consts.TokenTypeRFC8693TxnToken] = txnType
	cfg.RFC8693TokenTypes[consts.TokenTypeRFC8693SelfSigned] = &SelfSignedTokenType{Name: consts.TokenTypeRFC8693SelfSigned, Identifier: txnIdentifier}
	cfg.RFC8693TokenTypes[consts.TokenTypeRFC8693UnsignedJSON] = &UnsignedJSONTokenType{Name: consts.TokenTypeRFC8693UnsignedJSON}
	cfg.RFC8693TokenTypes[txnJWTType] = &JWTType{
		Name:   txnJWTType,
		Issuer: txnJWTIssuer,
		JWTValidationConfig: JWTValidationConfig{
			ValidateFunc: jwt.Keyfunc(func(_ *jwt.Token) (any, error) { return key.PublicKey, nil }),
		},
	}

	workloadKey := newTxnKey(t)

	client := &txnIssueClient{
		DefaultClient: &oauth2.DefaultClient{
			ID:           txnClientID,
			ClientSecret: oauth2.NewPlainTextClientSecret(txnClientSecret),
			GrantTypes:   []string{consts.GrantTypeOAuthTokenExchange},
			Scopes:       []string{"trade.stocks", "trade.bonds"},
			Audience:     []string{txnTrustDomain},
		},
		jwks: &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &workloadKey.PublicKey, KeyID: txnKeyID}}},
	}

	core := &hoauth2.HMACCoreStrategy{Enigma: &hmac.HMACStrategy{Config: cfg}, Config: cfg}
	strategy := &jwt.DefaultStrategy{Config: cfg, Issuer: jwt.NewDefaultIssuerRS256Unverified(key)}
	scopes := &txnScopeStub{}
	txn := &TxnTokenTypeHandler{Config: cfg, Strategy: strategy, Storage: scopes}

	return &txnIssueFixture{
		cfg:         cfg,
		store:       store,
		client:      client,
		core:        core,
		strategy:    strategy,
		txnType:     txnType,
		txn:         txn,
		scopes:      scopes,
		workloadKey: workloadKey,
		audience:    txnTrustDomain,
		handlers: []oauth2.TokenEndpointHandler{
			&TokenExchangeGrantHandler{Config: cfg, ScopeStrategy: oauth2.ExactScopeStrategy, AudienceStrategy: oauth2.ExactAudienceStrategy, ResourceStrategy: oauth2.ExactAudienceStrategy},
			&AccessTokenTypeHandler{Config: cfg, AccessTokenLifespan: 5 * time.Minute, RefreshTokenLifespan: 5 * time.Minute, CoreStrategy: core, Storage: store},
			&CustomJWTTypeHandler{Config: cfg, Strategy: strategy, Storage: store},
			&IDTokenTypeHandler{Config: cfg, Strategy: strategy, IssueStrategy: &openid.DefaultStrategy{Strategy: strategy, Config: cfg}, ValidationStrategy: &openid.DefaultIDTokenValidationStrategy{Strategy: strategy}, Storage: store},
			txn,
			&ActorTokenValidationHandler{},
		},
	}
}

func (f *txnIssueFixture) mint(t *testing.T, m txnMint) string {
	t.Helper()

	subject := m.subject

	switch subject {
	case "":
		subject = "alice"
	case "-":
		subject = ""
	}

	expires := m.expires
	if expires.IsZero() {
		expires = time.Now().UTC().Add(time.Hour)
	}

	session := newSpecSession(subject)
	session.SetExpiresAt(oauth2.AccessToken, expires)
	session.SetDPoPJWKThumbprint(m.jkt)

	if m.act != nil {
		session.SetClaimActor(m.act)
	}

	request := &oauth2.AccessRequest{
		GrantTypes: oauth2.Arguments{consts.GrantTypeClientCredentials},
		Request:    oauth2.Request{ID: uuid.New().String(), Client: f.client, Session: session, GrantedScope: m.scopes},
	}

	grantFixtureAudience(request)

	token, signature, err := f.core.GenerateAccessToken(t.Context(), request)
	require.NoError(t, err)
	require.NoError(t, f.store.CreateAccessTokenSession(t.Context(), signature, request))

	return token
}

func (f *txnIssueFixture) idToken(t *testing.T, extra map[string]any) string {
	t.Helper()

	now := time.Now()

	claims := jwt.MapClaims{
		consts.ClaimIssuer:         f.cfg.IDTokenIssuer,
		consts.ClaimSubject:        "alice",
		consts.ClaimAudience:       []string{txnClientID},
		consts.ClaimIssuedAt:       now.Unix(),
		consts.ClaimExpirationTime: now.Add(time.Hour).Unix(),
	}

	for name, value := range extra {
		claims[name] = value
	}

	token, _, err := f.strategy.Encode(t.Context(), claims)
	require.NoError(t, err)

	return token
}

func (f *txnIssueFixture) customJWT(t *testing.T, extra map[string]any) string {
	t.Helper()

	now := time.Now()

	claims := map[string]any{
		consts.ClaimIssuer:         txnJWTIssuer,
		consts.ClaimSubject:        "alice",
		"subject":                  "alice",
		consts.ClaimAudience:       []string{txnClientID},
		consts.ClaimIssuedAt:       now.Unix(),
		consts.ClaimExpirationTime: now.Add(30 * time.Minute).Unix(),
	}

	for name, value := range extra {
		claims[name] = value
	}

	return signToken(t, jose.RS256, key, "", claims, nil)
}

func (f *txnIssueFixture) run(t *testing.T, e txnExchange) (*oauth2.AccessRequest, *oauth2.AccessResponse, error) {
	t.Helper()

	subjectType := e.subjectType
	if subjectType == "" {
		subjectType = consts.TokenTypeRFC8693AccessToken
	}

	requested := e.requested
	if requested == "" {
		requested = consts.TokenTypeRFC8693TxnToken
	}

	form := url.Values{
		consts.FormParameterGrantType:          {consts.GrantTypeOAuthTokenExchange},
		consts.FormParameterRequestedTokenType: {requested},
		consts.FormParameterSubjectTokenType:   {subjectType},
		consts.FormParameterSubjectToken:       {e.subjectToken},
	}

	if e.actorToken != "" {
		actorTokenType := e.actorTokenType
		if actorTokenType == "" {
			actorTokenType = consts.TokenTypeRFC8693AccessToken
		}

		form.Set(consts.FormParameterActorToken, e.actorToken)
		form.Set(consts.FormParameterActorTokenType, actorTokenType)
	}

	for name, values := range e.form {
		form[name] = values
	}

	session := e.session
	if session == nil {
		session = newSpecSession("")
	}

	request := &oauth2.AccessRequest{
		GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthTokenExchange},
		Request: oauth2.Request{
			ID:                uuid.New().String(),
			Client:            f.client,
			Form:              form,
			RequestedScope:    e.scopes,
			GrantedScope:      e.granted,
			RequestedAudience: []string{f.audience},
			Session:           session,
		},
	}

	ctx := t.Context()
	response := oauth2.NewAccessResponse()

	for _, handler := range f.handlers {
		if err := handler.HandleTokenEndpointRequest(ctx, request); err != nil {
			return request, nil, err
		}
	}

	for _, handler := range f.handlers {
		if err := handler.PopulateTokenEndpointResponse(ctx, request, response); err != nil {
			return request, nil, err
		}
	}

	return request, response, nil
}

func (f *txnIssueFixture) exchange(t *testing.T, e txnExchange) (*oauth2.AccessResponse, error) {
	t.Helper()

	_, response, err := f.run(t, e)

	return response, err
}

func txnIssueStores() map[string]txnIssueStore {
	return map[string]txnIssueStore{
		"ExampleStore":   storage.NewExampleStore(),
		"HydratingStore": storage.NewHydratingMemoryStore(),
	}
}

func txnStorageSubjects() []txnStorageSubject {
	fixed := func(value string) func(*txnIssueFixture) string {
		return func(*txnIssueFixture) string { return value }
	}

	return []txnStorageSubject{
		{"IDToken", fixed(consts.TokenTypeRFC8693IDToken), func(t *testing.T, f *txnIssueFixture) string { return f.idToken(t, nil) }},
		{"SelfSigned", fixed(consts.TokenTypeRFC8693SelfSigned), func(t *testing.T, f *txnIssueFixture) string {
			return signToken(t, jose.ES256, f.workloadKey, txnKeyID, selfSignedClaims(), nil)
		}},
		{"UnsignedJSON", fixed(consts.TokenTypeRFC8693UnsignedJSON), func(t *testing.T, f *txnIssueFixture) string { return `{"sub":"alice"}` }},
		{"CustomJWT", fixed(txnJWTType), func(t *testing.T, f *txnIssueFixture) string { return f.customJWT(t, nil) }},
	}
}

func txnPayload(t *testing.T, response *oauth2.AccessResponse) map[string]any {
	t.Helper()

	parts := strings.Split(response.GetAccessToken(), ".")
	require.Len(t, parts, 3)

	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)

	var claims map[string]any

	require.NoError(t, json.Unmarshal(raw, &claims))

	return claims
}
