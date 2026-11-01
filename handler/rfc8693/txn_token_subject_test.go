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
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	. "authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/hmac"
	"authelia.com/provider/oauth2/token/jwt"
)

const (
	txnIdentifier = "https://tts.example"
	txnKeyID      = "workload-key"
	txnClientID   = "txn-client"
)

func TestTxnTokenSelfSignedAccepted(t *testing.T) {
	f := newTxnSubjectFixture(t)

	session, err := f.exchange(t, f.jwksClient(), consts.TokenTypeRFC8693SelfSigned, f.selfSigned(t, selfSignedClaims(), nil))

	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
	assert.Equal(t, "alice", session.GetSubject())
	assert.Equal(t, "alice", session.GetSubjectToken()[consts.ClaimSubject])
	assert.Equal(t, txnClientID, session.GetSubjectToken()[consts.ClaimIssuer])
}

func TestTxnTokenSelfSignedTiming(t *testing.T) {
	now := time.Now()

	testCases := []struct {
		name     string
		claims   map[string]any
		accepted bool
	}{
		{"ShouldAcceptIssuedAtEdgeOfWindow", map[string]any{consts.ClaimIssuedAt: now.Add(-4 * time.Minute).Unix()}, true},
		{"ShouldAcceptExpiryEdgeOfWindow", map[string]any{consts.ClaimExpirationTime: now.Add(4 * time.Minute).Unix()}, true},
		{"ShouldAcceptIssuedAtWithinClockSkew", map[string]any{consts.ClaimIssuedAt: now.Add(5 * time.Second).Unix()}, true},
		{"ShouldAcceptNotBeforeWithinClockSkew", map[string]any{consts.ClaimNotBefore: now.Add(5 * time.Second).Unix()}, true},
		{"ShouldRefuseIssuedAtBeyondClockSkew", map[string]any{consts.ClaimIssuedAt: now.Add(time.Minute).Unix()}, false},
		{"ShouldRefuseNotBeforeBeyondClockSkew", map[string]any{consts.ClaimNotBefore: now.Add(time.Minute).Unix()}, false},
		{"ShouldRefuseExpired", map[string]any{consts.ClaimExpirationTime: now.Add(-time.Minute).Unix()}, false},
		{"ShouldRefuseIssuedAtOlderThanWindow", map[string]any{consts.ClaimIssuedAt: now.Add(-6 * time.Minute).Unix()}, false},
		{"ShouldRefuseExpiryBeyondWindow", map[string]any{consts.ClaimExpirationTime: now.Add(6 * time.Minute).Unix()}, false},
		{"ShouldRefuseStringIssuedAt", map[string]any{consts.ClaimIssuedAt: "soon"}, false},
		{"ShouldRefuseStringExpiry", map[string]any{consts.ClaimExpirationTime: "later"}, false},
		{"ShouldRefuseNullIssuedAt", map[string]any{consts.ClaimIssuedAt: nil}, false},
		{"ShouldRefuseNullExpiry", map[string]any{consts.ClaimExpirationTime: nil}, false},
		{"ShouldRefuseOverflowingIssuedAt", map[string]any{consts.ClaimIssuedAt: json.Number("1e300")}, false},
		{"ShouldRefuseOverflowingExpiry", map[string]any{consts.ClaimExpirationTime: json.Number("1e300")}, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := newTxnSubjectFixture(t)

			claims := selfSignedClaims()

			for name, value := range tc.claims {
				claims[name] = value
			}

			session, err := f.exchange(t, f.jwksClient(), consts.TokenTypeRFC8693SelfSigned, f.selfSigned(t, claims, nil))

			if tc.accepted {
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
				assert.Equal(t, "alice", session.GetSubject())

				return
			}

			assertSubjectRefused(t, session, err)
		})
	}
}

func TestTxnTokenSelfSignedToleranceWindowIsConfigurable(t *testing.T) {
	now := time.Now()

	f := newTxnSubjectFixture(t)
	f.selfSignedType.ToleranceWindow = time.Hour

	claims := selfSignedClaims()
	claims[consts.ClaimIssuedAt] = now.Add(-30 * time.Minute).Unix()
	claims[consts.ClaimExpirationTime] = now.Add(30 * time.Minute).Unix()

	_, err := f.exchange(t, f.jwksClient(), consts.TokenTypeRFC8693SelfSigned, f.selfSigned(t, claims, nil))
	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

	f.selfSignedType.ToleranceWindow = time.Minute

	session, err := f.exchange(t, f.jwksClient(), consts.TokenTypeRFC8693SelfSigned, f.selfSigned(t, claims, nil))
	assertSubjectRefused(t, session, err)
}

func TestTxnTokenSelfSignedClockSkewCanBeDisabled(t *testing.T) {
	f := newTxnSubjectFixture(t)
	f.config.JWTClockSkew = -1

	claims := selfSignedClaims()
	claims[consts.ClaimIssuedAt] = time.Now().Add(5 * time.Second).Unix()

	session, err := f.exchange(t, f.jwksClient(), consts.TokenTypeRFC8693SelfSigned, f.selfSigned(t, claims, nil))
	assertSubjectRefused(t, session, err)
}

func TestTxnTokenSelfSignedClaimsRefused(t *testing.T) {
	testCases := []struct {
		name   string
		mutate func(claims map[string]any)
	}{
		{"ShouldRefuseOtherIssuer", func(c map[string]any) { c[consts.ClaimIssuer] = "other-client" }},
		{"ShouldRefuseMissingIssuer", func(c map[string]any) { delete(c, consts.ClaimIssuer) }},
		{"ShouldRefuseNonStringIssuer", func(c map[string]any) { c[consts.ClaimIssuer] = []string{txnClientID} }},
		{"ShouldRefuseOtherAudience", func(c map[string]any) { c[consts.ClaimAudience] = "https://other.example" }},
		{"ShouldRefuseAudienceListWithoutIdentifier", func(c map[string]any) { c[consts.ClaimAudience] = []string{"https://other.example", txnTrustDomain} }},
		{"ShouldRefuseMissingAudience", func(c map[string]any) { delete(c, consts.ClaimAudience) }},
		{"ShouldRefuseMissingSubject", func(c map[string]any) { delete(c, consts.ClaimSubject) }},
		{"ShouldRefuseEmptySubject", func(c map[string]any) { c[consts.ClaimSubject] = "" }},
		{"ShouldRefuseNonStringSubject", func(c map[string]any) { c[consts.ClaimSubject] = 1 }},
		{"ShouldRefuseMissingIssuedAt", func(c map[string]any) { delete(c, consts.ClaimIssuedAt) }},
		{"ShouldRefuseMissingExpiry", func(c map[string]any) { delete(c, consts.ClaimExpirationTime) }},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := newTxnSubjectFixture(t)

			claims := selfSignedClaims()
			tc.mutate(claims)

			session, err := f.exchange(t, f.jwksClient(), consts.TokenTypeRFC8693SelfSigned, f.selfSigned(t, claims, nil))

			assertSubjectRefused(t, session, err)
		})
	}
}

func TestTxnTokenSelfSignedAudienceListWithIdentifierAccepted(t *testing.T) {
	f := newTxnSubjectFixture(t)

	claims := selfSignedClaims()
	claims[consts.ClaimAudience] = []string{"https://other.example", txnIdentifier}

	_, err := f.exchange(t, f.jwksClient(), consts.TokenTypeRFC8693SelfSigned, f.selfSigned(t, claims, nil))

	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
}

func TestTxnTokenSelfSignedTypeHeader(t *testing.T) {
	testCases := []struct {
		name     string
		typ      any
		accepted bool
	}{
		{"ShouldAcceptJWT", "JWT", true},
		{"ShouldAcceptJWTAnyCase", "jwt", true},
		{"ShouldAcceptJWTWithPrefix", "application/jwt", true},
		{"ShouldRefuseRequestObject", consts.JSONWebTokenTypeJWTSecuredAuthorizationRequest, false},
		{"ShouldRefuseLogoutToken", consts.JSONWebTokenTypeLogoutToken, false},
		{"ShouldRefuseSoftwareStatement", consts.JSONWebTokenTypeSoftwareStatement, false},
		{"ShouldRefuseUnknownType", "secevent+jwt", false},
		{"ShouldRefuseEmptyType", "", false},
		{"ShouldRefuseTxnToken", consts.JSONWebTokenTypeTxnToken, false},
		{"ShouldRefuseTxnTokenWithPrefix", "application/" + consts.JSONWebTokenTypeTxnToken, false},
		{"ShouldRefuseTxnTokenAnyCase", "TXNTOKEN+JWT", false},
		{"ShouldRefuseIDJAG", "oauth-id-jag+jwt", false},
		{"ShouldRefuseIDJAGWithPrefix", "application/oauth-id-jag+jwt", false},
		{"ShouldRefuseAccessToken", "at+jwt", false},
		{"ShouldRefuseAccessTokenWithPrefix", "application/at+jwt", false},
		{"ShouldRefuseAccessTokenAnyCase", "AT+JWT", false},
		{"ShouldRefuseClientAuthentication", consts.JSONWebTokenTypeClientAuthentication, false},
		{"ShouldRefuseClientAuthenticationWithPrefix", "application/" + consts.JSONWebTokenTypeClientAuthentication, false},
		{"ShouldRefuseClientAuthenticationAnyCase", "CLIENT-AUTHENTICATION+JWT", false},
		{"ShouldRefuseNonStringType", []string{"JWT"}, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := newTxnSubjectFixture(t)

			session, err := f.exchange(t, f.jwksClient(), consts.TokenTypeRFC8693SelfSigned, f.selfSigned(t, selfSignedClaims(), map[string]any{consts.JSONWebTokenHeaderType: tc.typ}))

			if tc.accepted {
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				return
			}

			assertSubjectRefused(t, session, err)
		})
	}
}

// §11.3: the TTS MUST validate the subject_token, including verifying the signature.
func TestTxnTokenSelfSignedSignatureRefused(t *testing.T) {
	testCases := []struct {
		name  string
		token func(t *testing.T, f *txnSubjectFixture) string
	}{
		{"ShouldRefuseAlgNone", func(t *testing.T, f *txnSubjectFixture) string {
			return unsecuredToken(t, selfSignedClaims())
		}},
		{"ShouldRefuseHS256KeyedWithClientSecret", func(t *testing.T, f *txnSubjectFixture) string {
			return signToken(t, jose.HS256, []byte(txnClientSecret), "", selfSignedClaims(), nil)
		}},
		{"ShouldRefuseJWE", func(t *testing.T, f *txnSubjectFixture) string {
			return encryptToken(t, &f.key.PublicKey, selfSignedClaims())
		}},
		{"ShouldRefuseKeyNotInSet", func(t *testing.T, f *txnSubjectFixture) string {
			return signToken(t, jose.ES256, newTxnKey(t), txnKeyID, selfSignedClaims(), nil)
		}},
		{"ShouldRefuseUnknownKeyID", func(t *testing.T, f *txnSubjectFixture) string {
			return signToken(t, jose.ES256, f.key, "unknown", selfSignedClaims(), nil)
		}},
		{"ShouldRefuseSignatureFromOtherKeyWithoutKeyID", func(t *testing.T, f *txnSubjectFixture) string {
			return signToken(t, jose.ES256, newTxnKey(t), "", selfSignedClaims(), nil)
		}},
		{"ShouldRefuseAMalformedValue", func(t *testing.T, f *txnSubjectFixture) string {
			return "not-a-token"
		}},
		{"ShouldRefuseTamperedPayload", func(t *testing.T, f *txnSubjectFixture) string {
			return tamperPayload(t, f.selfSigned(t, selfSignedClaims(), nil))
		}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := newTxnSubjectFixture(t)

			session, err := f.exchange(t, f.jwksClient(), consts.TokenTypeRFC8693SelfSigned, tc.token(t, f))

			assertSubjectRefused(t, session, err)
		})
	}
}

// §11.3: the TTS MUST validate the subject_token, including verifying the signature.
func TestTxnTokenSelfSignedKeyfuncTimingErrorRefused(t *testing.T) {
	f := newTxnSubjectFixture(t)
	f.config.JWKSFetcherStrategy = &txnJWKSFetcher{err: &jwt.ValidationError{Errors: jwt.ValidationErrorIssuedAt}}

	session, err := f.exchange(t, f.uriClient(), consts.TokenTypeRFC8693SelfSigned, signToken(t, jose.ES256, newTxnKey(t), txnKeyID, selfSignedClaims(), nil))

	assertSubjectRefused(t, session, err)
}

func TestTxnTokenSelfSignedKeyUsage(t *testing.T) {
	f := newTxnSubjectFixture(t)

	client := f.jwksClient()
	client.JSONWebKeys = &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &f.key.PublicKey, KeyID: txnKeyID, Use: "enc"}}}

	session, err := f.exchange(t, client, consts.TokenTypeRFC8693SelfSigned, f.selfSigned(t, selfSignedClaims(), nil))

	assertSubjectRefused(t, session, err)
}

func TestTxnTokenSelfSignedClientKeys(t *testing.T) {
	refusal := errors.New("network unreachable")

	testCases := []struct {
		name     string
		client   func(f *txnSubjectFixture) oauth2.Client
		fetcher  *txnJWKSFetcher
		accepted bool
	}{
		{
			name: "ShouldRefuseClientWithNoKeys",
			client: func(f *txnSubjectFixture) oauth2.Client {
				client := f.jwksClient()
				client.JSONWebKeys = nil

				return client
			},
		},
		{
			name: "ShouldRefuseClientWithEmptyKeySet",
			client: func(f *txnSubjectFixture) oauth2.Client {
				client := f.jwksClient()
				client.JSONWebKeys = &jose.JSONWebKeySet{}

				return client
			},
		},
		{
			name:   "ShouldRefuseClientWithoutJSONWebKeys",
			client: func(f *txnSubjectFixture) oauth2.Client { return f.client },
		},
		{
			name:    "ShouldRefuseFailedFetch",
			client:  func(f *txnSubjectFixture) oauth2.Client { return f.uriClient() },
			fetcher: &txnJWKSFetcher{err: refusal},
		},
		{
			name:    "ShouldRefuseFetchWithoutKeySet",
			client:  func(f *txnSubjectFixture) oauth2.Client { return f.uriClient() },
			fetcher: &txnJWKSFetcher{},
		},
		{
			name:     "ShouldAcceptFetchedKey",
			client:   func(f *txnSubjectFixture) oauth2.Client { return f.uriClient() },
			fetcher:  &txnJWKSFetcher{},
			accepted: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := newTxnSubjectFixture(t)

			if tc.fetcher != nil {
				if tc.accepted {
					tc.fetcher.jwks = &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &f.key.PublicKey, KeyID: txnKeyID}}}
				}

				f.config.JWKSFetcherStrategy = tc.fetcher
			}

			session, err := f.exchange(t, tc.client(f), consts.TokenTypeRFC8693SelfSigned, f.selfSigned(t, selfSignedClaims(), nil))

			if tc.accepted {
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
				assert.Equal(t, "alice", session.GetSubject())
				assert.Equal(t, "https://workload.example/jwks", tc.fetcher.location)
				assert.False(t, tc.fetcher.ignoreCache)

				return
			}

			assertSubjectRefused(t, session, err)

			if tc.fetcher != nil && tc.fetcher.err != nil {
				assert.Contains(t, oauth2.ErrorToDebugRFC6749Error(err).Error(), refusal.Error())
			}
		})
	}
}

func TestTxnTokenSelfSignedRequiresIdentifier(t *testing.T) {
	f := newTxnSubjectFixture(t)
	f.selfSignedType.Identifier = ""

	claims := selfSignedClaims()
	claims[consts.ClaimAudience] = ""

	_, err := f.exchange(t, f.jwksClient(), consts.TokenTypeRFC8693SelfSigned, f.selfSigned(t, claims, nil))

	assert.ErrorIs(t, err, oauth2.ErrServerError)
}

func TestTxnTokenSelfSignedJTI(t *testing.T) {
	for name, store := range txnJTIStores() {
		t.Run(name, func(t *testing.T) {
			t.Run("ShouldRefuseMissingJTI", func(t *testing.T) {
				f := newTxnSubjectFixture(t)
				f.selfSignedType.ValidateJTI = true
				f.subject.JTIStorage = store

				session, err := f.exchange(t, f.jwksClient(), consts.TokenTypeRFC8693SelfSigned, f.selfSigned(t, selfSignedClaims(), nil))

				assertSubjectRefused(t, session, err)
			})

			t.Run("ShouldRefuseNonStringJTI", func(t *testing.T) {
				f := newTxnSubjectFixture(t)
				f.selfSignedType.ValidateJTI = true
				f.subject.JTIStorage = store

				claims := selfSignedClaims()
				claims[consts.ClaimJWTID] = 1

				session, err := f.exchange(t, f.jwksClient(), consts.TokenTypeRFC8693SelfSigned, f.selfSigned(t, claims, nil))

				assertSubjectRefused(t, session, err)
			})

			t.Run("ShouldRefuseSecondUse", func(t *testing.T) {
				f := newTxnSubjectFixture(t)
				f.selfSignedType.ValidateJTI = true
				f.subject.JTIStorage = store

				claims := selfSignedClaims()
				claims[consts.ClaimJWTID] = uuid.New().String()

				token := f.selfSigned(t, claims, nil)

				first := f.subjectRequest(f.jwksClient(), consts.TokenTypeRFC8693SelfSigned, token, nil)

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.handle(t, first)))
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.populate(t, first)))

				second := f.subjectRequest(f.jwksClient(), consts.TokenTypeRFC8693SelfSigned, token, nil)

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.handle(t, second)))

				err := f.populate(t, second)

				require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
				assert.Contains(t, oauth2.ErrorToRFC6749Error(err).HintField, "'jti'")
			})

			t.Run("ShouldScopeTheJTIToTheIssuer", func(t *testing.T) {
				f := newTxnSubjectFixture(t)
				f.selfSignedType.ValidateJTI = true
				f.subject.JTIStorage = store

				jti := uuid.New().String()

				for _, id := range []string{txnClientID, "txn-client-2"} {
					client := f.jwksClient()
					client.ID = id

					claims := selfSignedClaims()
					claims[consts.ClaimIssuer] = id
					claims[consts.ClaimJWTID] = jti

					request := f.subjectRequest(client, consts.TokenTypeRFC8693SelfSigned, f.selfSigned(t, claims, nil), nil)

					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.handle(t, request)))
					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.populate(t, request)))
				}
			})

			t.Run("ShouldNotConsumeWhenNotValidated", func(t *testing.T) {
				f := newTxnSubjectFixture(t)
				f.subject.JTIStorage = store

				claims := selfSignedClaims()
				claims[consts.ClaimJWTID] = uuid.New().String()

				token := f.selfSigned(t, claims, nil)

				for range 2 {
					request := f.subjectRequest(f.jwksClient(), consts.TokenTypeRFC8693SelfSigned, token, nil)

					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.handle(t, request)))
					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.populate(t, request)))
				}
			})
		})
	}
}

// An assertion is used only by a token that was issued, so a request refused during issuance can be retried.
func TestTxnTokenJTINotConsumedWhenIssuanceFails(t *testing.T) {
	failure := errors.New("the policy engine is down")

	testCases := []struct {
		name string
		arm  func(f *txnIssueFixture) (disarm func())
	}{
		{"ShouldKeepItWhenTheHookFails", func(f *txnIssueFixture) func() {
			f.txnType.TranscribeClaims = func(context.Context, oauth2.AccessRequester, *TxnTokenClaimsInput) error { return failure }

			return func() { f.txnType.TranscribeClaims = nil }
		}},
		{"ShouldKeepItWhenSigningFails", func(f *txnIssueFixture) func() {
			strategy := f.txn.Strategy
			f.txn.Strategy = &txnFailingStrategy{Strategy: strategy, err: failure}

			return func() { f.txn.Strategy = strategy }
		}},
		{"ShouldKeepItWhenTheIssuerIsMisconfigured", func(f *txnIssueFixture) func() {
			f.txnType.Issuer = f.cfg.IDTokenIssuer

			return func() { f.txnType.Issuer = "" }
		}},
	}

	for name, store := range txnJTIStores() {
		t.Run(name, func(t *testing.T) {
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					f := newTxnIssueFixture(t, storage.NewExampleStore())
					f.scopes.scopes = []string{"trade.stocks"}
					f.cfg.RFC8693TokenTypes[consts.TokenTypeRFC8693SelfSigned].(*SelfSignedTokenType).ValidateJTI = true
					f.handlers[0].(*TokenExchangeGrantHandler).Storage = store
					f.txn.JTIStorage = store

					claims := selfSignedClaims()
					claims[consts.ClaimJWTID] = uuid.New().String()

					e := txnExchange{subjectType: consts.TokenTypeRFC8693SelfSigned, subjectToken: signToken(t, jose.ES256, f.workloadKey, txnKeyID, claims, nil), scopes: []string{"trade.stocks"}}

					disarm := tc.arm(f)

					_, err := f.exchange(t, e)
					require.Error(t, err)

					disarm()

					response, err := f.exchange(t, e)
					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
					assert.NotEmpty(t, response.GetAccessToken())

					_, err = f.exchange(t, e)
					require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
					assert.Contains(t, oauth2.ErrorToRFC6749Error(err).HintField, "'jti'")
				})
			}
		})
	}
}

// A custom JWT is refused for a second use on a Transaction Token request as well, as the grant handler leaves it to issuance.
func TestTxnTokenJTICustomJWTSubject(t *testing.T) {
	for name, store := range txnJTIStores() {
		t.Run(name, func(t *testing.T) {
			f := newTxnIssueFixture(t, storage.NewExampleStore())
			f.scopes.scopes = []string{"trade.stocks"}
			f.cfg.RFC8693TokenTypes[txnJWTType].(*JWTType).ValidateJTI = true
			f.txn.JTIStorage = store

			e := txnExchange{subjectType: txnJWTType, subjectToken: f.customJWT(t, map[string]any{consts.ClaimJWTID: uuid.New().String()}), scopes: []string{"trade.stocks"}}

			_, err := f.exchange(t, e)
			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

			_, err = f.exchange(t, e)
			require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
			assert.Contains(t, oauth2.ErrorToRFC6749Error(err).HintField, "'jti'")
		})
	}
}

type txnFailingStrategy struct {
	jwt.Strategy

	err error
}

func (s *txnFailingStrategy) Encode(context.Context, jwt.Claims, ...jwt.StrategyOpt) (string, string, error) {
	return "", "", s.err
}

func TestTxnTokenSelfSignedJTIRequiresStorage(t *testing.T) {
	f := newTxnSubjectFixture(t)
	f.selfSignedType.ValidateJTI = true

	claims := selfSignedClaims()
	claims[consts.ClaimJWTID] = uuid.New().String()

	request := f.subjectRequest(f.jwksClient(), consts.TokenTypeRFC8693SelfSigned, f.selfSigned(t, claims, nil), nil)

	assert.ErrorIs(t, f.handle(t, request), oauth2.ErrServerError)
}

func TestTxnTokenUnsignedJSONAccepted(t *testing.T) {
	f := newTxnSubjectFixture(t)

	session, err := f.exchange(t, f.unsignedClient(true), consts.TokenTypeRFC8693UnsignedJSON, `{"sub":"alice","tenant":"a","n":1}`)

	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
	assert.Equal(t, "alice", session.GetSubject())
	assert.Equal(t, map[string]any{consts.ClaimSubject: "alice", "tenant": "a", "n": json.Number("1")}, session.GetSubjectToken())
}

func TestTxnTokenUnsignedJSONRefused(t *testing.T) {
	testCases := []struct {
		name   string
		client func(f *txnSubjectFixture) oauth2.Client
		value  string
	}{
		{"ShouldRefuseClientNotOptedIn", func(f *txnSubjectFixture) oauth2.Client { return f.unsignedClient(false) }, `{"sub":"alice"}`},
		{"ShouldRefuseClientNotImplementing", func(f *txnSubjectFixture) oauth2.Client { return f.client }, `{"sub":"alice"}`},
		{"ShouldRefuseMissingSubject", nil, `{"tenant":"a"}`},
		{"ShouldRefuseEmptySubject", nil, `{"sub":""}`},
		{"ShouldRefuseNullSubject", nil, `{"sub":null}`},
		{"ShouldRefuseNumericSubject", nil, `{"sub":1}`},
		{"ShouldRefuseObjectSubject", nil, `{"sub":{"id":"alice"}}`},
		{"ShouldRefuseArray", nil, `["alice"]`},
		{"ShouldRefuseString", nil, `"alice"`},
		{"ShouldRefuseNull", nil, `null`},
		{"ShouldRefuseNumber", nil, `1`},
		{"ShouldRefuseMalformed", nil, `{"sub":"alice"`},
		{"ShouldRefuseTrailingObject", nil, `{"sub":"alice"} {"sub":"bob"}`},
		{"ShouldRefuseTrailingGarbage", nil, `{"sub":"alice"} x`},
		{"ShouldRefuseCompactJWT", nil, compactJWTValue},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := newTxnSubjectFixture(t)

			var client oauth2.Client = f.unsignedClient(true)

			if tc.client != nil {
				client = tc.client(f)
			}

			session, err := f.exchange(t, client, consts.TokenTypeRFC8693UnsignedJSON, tc.value)

			assertSubjectRefused(t, session, err)
		})
	}
}

func TestTxnTokenUnsignedJSONExpiry(t *testing.T) {
	testCases := []struct {
		name     string
		exp      string
		accepted bool
	}{
		{"ShouldAcceptFuture", strconv.FormatInt(time.Now().Add(time.Minute).Unix(), 10), true},
		{"ShouldAcceptFractional", strconv.FormatInt(time.Now().Add(time.Minute).Unix(), 10) + ".5", true},
		{"ShouldAcceptFarFuture", "253402300799", true},
		{"ShouldRefuseBeyondTheLastDate", "253402300800", false},
		{"ShouldRefuseMaxInt64", "9223372036854775807", false},
		{"ShouldRefuseOverflowingFloat", "1e300", false},
		{"ShouldRefuseUnrepresentable", "1e400", false},
		{"ShouldRefuseZero", "0", false},
		{"ShouldRefuseNegative", "-1", false},
		{"ShouldRefusePast", strconv.FormatInt(time.Now().Add(-time.Minute).Unix(), 10), false},
		{"ShouldRefuseString", `"later"`, false},
		{"ShouldRefuseNumericString", `"9999999999"`, false},
		{"ShouldRefuseNull", "null", false},
		{"ShouldRefuseBoolean", "true", false},
		{"ShouldRefuseObject", "{}", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := newTxnSubjectFixture(t)

			session, err := f.exchange(t, f.unsignedClient(true), consts.TokenTypeRFC8693UnsignedJSON, `{"sub":"alice","exp":`+tc.exp+`}`)

			if tc.accepted {
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				return
			}

			assertSubjectRefused(t, session, err)
		})
	}
}

func TestTxnTokenUnsignedJSONRefusesARealSignedToken(t *testing.T) {
	f := newTxnSubjectFixture(t)

	session, err := f.exchange(t, f.unsignedClient(true), consts.TokenTypeRFC8693UnsignedJSON, f.selfSigned(t, selfSignedClaims(), nil))

	assertSubjectRefused(t, session, err)
}

// RFC 8693 §4.1, §4.4 and RFC 7800: the workload wrote these claims, and each drives delegation or binding once on the
// session.
func TestTxnTokenSubjectRefusesDelegationAndBindingClaims(t *testing.T) {
	values := map[string]any{
		"Object": map[string]any{consts.ClaimSubject: "bob"},
		"Null":   nil,
		"String": "bob",
	}

	for _, claim := range []string{consts.ClaimAuthorizedActor, consts.ClaimActor, consts.ClaimConfirmation} {
		for valueName, value := range values {
			t.Run("ShouldRefuseSelfSigned/"+claim+"/"+valueName, func(t *testing.T) {
				f := newTxnSubjectFixture(t)

				claims := selfSignedClaims()
				claims[claim] = value

				session, err := f.exchange(t, f.jwksClient(), consts.TokenTypeRFC8693SelfSigned, f.selfSigned(t, claims, nil))

				assertSubjectRefused(t, session, err)
			})

			t.Run("ShouldRefuseUnsignedJSON/"+claim+"/"+valueName, func(t *testing.T) {
				f := newTxnSubjectFixture(t)

				encoded, err := json.Marshal(map[string]any{consts.ClaimSubject: "alice", claim: value})
				require.NoError(t, err)

				session, err := f.exchange(t, f.unsignedClient(true), consts.TokenTypeRFC8693UnsignedJSON, string(encoded))

				assertSubjectRefused(t, session, err)
			})
		}
	}
}

func TestTxnTokenSubjectClearsInheritedKeyBinding(t *testing.T) {
	f := newTxnSubjectFixture(t)

	request := f.subjectRequest(f.unsignedClient(true), consts.TokenTypeRFC8693UnsignedJSON, `{"sub":"alice"}`, nil)

	session := request.GetSession().(*DefaultSession)
	session.SetOIDCKeyBindingGranted(true)
	session.SetRequestedDPoPJWKThumbprint("jkt")

	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.handle(t, request)))

	assert.False(t, session.GetOIDCKeyBindingGranted())
	assert.Empty(t, session.GetRequestedDPoPJWKThumbprint())
}

func TestTxnTokenSubjectTypesOnlyForTxnTokenRequests(t *testing.T) {
	cases := map[string]string{
		consts.TokenTypeRFC8693SelfSigned:   "",
		consts.TokenTypeRFC8693UnsignedJSON: `{"sub":"alice"}`,
	}

	for subjectType, value := range cases {
		t.Run("ShouldRefuseAccessTokenRequest/"+subjectType, func(t *testing.T) {
			f := newTxnSubjectFixture(t)

			if value == "" {
				value = f.selfSigned(t, selfSignedClaims(), nil)
			}

			request := f.subjectRequest(f.unsignedClient(true), subjectType, value, url.Values{consts.FormParameterRequestedTokenType: {consts.TokenTypeRFC8693AccessToken}})

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.handle(t, request)))

			session := request.GetSession().(*DefaultSession)

			assert.Nil(t, session.GetSubjectToken())
			assert.Empty(t, session.GetSubject())

			access := f.accessHandler()

			err := access.PopulateTokenEndpointResponse(t.Context(), request, oauth2.NewAccessResponse())

			require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
			assert.Contains(t, oauth2.ErrorToRFC6749Error(err).HintField, consts.FormParameterSubjectTokenType)

			err = (&ActorTokenValidationHandler{}).HandleTokenEndpointRequest(t.Context(), request)

			require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
			assert.Contains(t, oauth2.ErrorToRFC6749Error(err).HintField, consts.FormParameterSubjectTokenType)
		})
	}
}

// A registered subject token type cannot be issued, so asking for one is the client's error.
func TestTxnTokenSubjectTypesNotAcceptedAsRequestedTokenType(t *testing.T) {
	for _, requested := range []string{consts.TokenTypeRFC8693SelfSigned, consts.TokenTypeRFC8693UnsignedJSON} {
		t.Run(requested, func(t *testing.T) {
			f := newTxnSubjectFixture(t)

			request := f.subjectRequest(f.unsignedClient(true), consts.TokenTypeRFC8693UnsignedJSON, `{"sub":"alice"}`, url.Values{consts.FormParameterRequestedTokenType: {requested}})

			err := f.grant.HandleTokenEndpointRequest(t.Context(), request)

			require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
			assert.Contains(t, oauth2.ErrorToRFC6749Error(err).HintField, consts.FormParameterRequestedTokenType)
		})
	}
}

func TestTxnTokenSubjectTypesPresentedAsActor(t *testing.T) {
	cases := map[string]string{
		consts.TokenTypeRFC8693SelfSigned:   "",
		consts.TokenTypeRFC8693UnsignedJSON: `{"sub":"bob"}`,
	}

	for actorType, value := range cases {
		t.Run("ShouldRefuse/"+actorType, func(t *testing.T) {
			f := newTxnSubjectFixture(t)

			if value == "" {
				value = f.selfSigned(t, selfSignedClaims(), nil)
			}

			request := f.subjectRequest(f.unsignedClient(true), consts.TokenTypeRFC8693UnsignedJSON, `{"sub":"alice"}`, url.Values{
				consts.FormParameterActorToken:     {value},
				consts.FormParameterActorTokenType: {actorType},
			})

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.handle(t, request)))

			session := request.GetSession().(*DefaultSession)

			assert.Nil(t, session.GetActorToken())

			err := RequireActorToken(request)

			require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
			assert.Contains(t, oauth2.ErrorToRFC6749Error(err).HintField, consts.FormParameterActorTokenType)

			err = (&ActorTokenValidationHandler{}).HandleTokenEndpointRequest(t.Context(), request)

			require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
			assert.Contains(t, oauth2.ErrorToRFC6749Error(err).HintField, consts.FormParameterActorTokenType)
		})
	}
}

func TestTxnTokenSubjectTypesUnregistered(t *testing.T) {
	f := newTxnSubjectFixture(t)

	delete(f.config.RFC8693TokenTypes, consts.TokenTypeRFC8693SelfSigned)

	request := f.subjectRequest(f.jwksClient(), consts.TokenTypeRFC8693SelfSigned, f.selfSigned(t, selfSignedClaims(), nil), nil)

	err := f.grant.HandleTokenEndpointRequest(t.Context(), request)

	require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
	assert.Contains(t, oauth2.ErrorToRFC6749Error(err).HintField, consts.FormParameterSubjectTokenType)
}

func TestTxnTokenTypeHandlerIgnoresRequestsWithoutTxnType(t *testing.T) {
	f := newTxnSubjectFixture(t)

	delete(f.config.RFC8693TokenTypes, consts.TokenTypeRFC8693TxnToken)

	request := f.subjectRequest(f.jwksClient(), consts.TokenTypeRFC8693AccessToken, "subject", url.Values{consts.FormParameterRequestedTokenType: {consts.TokenTypeRFC8693AccessToken}})

	require.NoError(t, f.subject.HandleTokenEndpointRequest(t.Context(), request))
	assert.Nil(t, request.GetSession().(*DefaultSession).GetSubjectToken())
}

func TestTxnTokenTypeHandlerContract(t *testing.T) {
	f := newTxnSubjectFixture(t)

	unknown := &oauth2.AccessRequest{GrantTypes: oauth2.Arguments{consts.GrantTypeClientCredentials}, Request: oauth2.Request{Form: url.Values{}, Session: newSpecSession("")}}

	assert.False(t, f.subject.CanSkipClientAuth(t.Context(), unknown))
	assert.False(t, f.subject.CanHandleTokenEndpointRequest(t.Context(), unknown))
	assert.ErrorIs(t, f.subject.HandleTokenEndpointRequest(t.Context(), unknown), oauth2.ErrUnknownRequest)

	request := f.subjectRequest(f.jwksClient(), consts.TokenTypeRFC8693SelfSigned, "x", nil)

	assert.True(t, f.subject.CanHandleTokenEndpointRequest(t.Context(), request))
	assert.ErrorIs(t, f.subject.PopulateTokenEndpointResponse(t.Context(), request, oauth2.NewAccessResponse()), oauth2.ErrInvalidRequest)
}

const txnClientSecret = "a-client-secret-of-sufficient-length-for-hs256"

var compactJWTValue = base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256"}`)) + "." +
	base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"alice"}`)) + "." +
	base64.RawURLEncoding.EncodeToString([]byte("signature"))

type txnSubjectFixture struct {
	*txnFixture

	key            *ecdsa.PrivateKey
	selfSignedType *SelfSignedTokenType
	subject        *TxnTokenTypeHandler
	grant          *TokenExchangeGrantHandler
}

func newTxnSubjectFixture(t *testing.T) *txnSubjectFixture {
	t.Helper()

	base := newTxnFixture(t)
	base.client.ClientSecret = oauth2.NewPlainTextClientSecret(txnClientSecret)

	selfSigned := &SelfSignedTokenType{Name: consts.TokenTypeRFC8693SelfSigned, Identifier: txnIdentifier}

	base.config.RFC8693TokenTypes[consts.TokenTypeRFC8693SelfSigned] = selfSigned
	base.config.RFC8693TokenTypes[consts.TokenTypeRFC8693UnsignedJSON] = &UnsignedJSONTokenType{Name: consts.TokenTypeRFC8693UnsignedJSON}

	return &txnSubjectFixture{
		txnFixture:     base,
		key:            newTxnKey(t),
		selfSignedType: selfSigned,
		subject: &TxnTokenTypeHandler{
			Config:   base.config,
			Strategy: &jwt.DefaultStrategy{Config: base.config, Issuer: jwt.NewDefaultIssuerRS256Unverified(key)},
			Storage:  &txnScopeStub{scopes: []string{"photos", "oauth2"}},
		},
		grant: base.handler,
	}
}

func (f *txnSubjectFixture) jwksClient() *txnJWKSClient {
	return &txnJWKSClient{
		DefaultClient: f.clientCopy(),
		JSONWebKeys:   &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &f.key.PublicKey, KeyID: txnKeyID}}},
	}
}

func (f *txnSubjectFixture) uriClient() *txnJWKSClient {
	return &txnJWKSClient{DefaultClient: f.clientCopy(), JSONWebKeysURI: "https://workload.example/jwks"}
}

func (f *txnSubjectFixture) unsignedClient(allow bool) *txnUnsignedClient {
	return &txnUnsignedClient{DefaultClient: f.clientCopy(), allow: allow}
}

func (f *txnSubjectFixture) clientCopy() *oauth2.DefaultClient {
	client := *f.client

	return &client
}

func (f *txnSubjectFixture) accessHandler() *AccessTokenTypeHandler {
	return &AccessTokenTypeHandler{
		Config:               f.config,
		AccessTokenLifespan:  5 * time.Minute,
		RefreshTokenLifespan: 5 * time.Minute,
		CoreStrategy:         &hoauth2.HMACCoreStrategy{Enigma: &hmac.HMACStrategy{Config: f.config}, Config: f.config},
		ScopeStrategy:        oauth2.ExactScopeStrategy,
		Storage:              storage.NewExampleStore(),
	}
}

func (f *txnSubjectFixture) selfSigned(t *testing.T, claims, headers map[string]any) string {
	t.Helper()

	return signToken(t, jose.ES256, f.key, txnKeyID, claims, headers)
}

func (f *txnSubjectFixture) subjectRequest(client oauth2.Client, subjectType, value string, form url.Values) *oauth2.AccessRequest {
	request := f.request(txnRequest{subjectTokenType: subjectType, form: form})
	request.Client = client
	request.Form.Set(consts.FormParameterSubjectToken, value)

	return request
}

func (f *txnSubjectFixture) handle(t *testing.T, request *oauth2.AccessRequest) error {
	t.Helper()

	if err := f.grant.HandleTokenEndpointRequest(t.Context(), request); err != nil {
		return err
	}

	return f.subject.HandleTokenEndpointRequest(t.Context(), request)
}

func (f *txnSubjectFixture) populate(t *testing.T, request *oauth2.AccessRequest) error {
	t.Helper()

	response := oauth2.NewAccessResponse()

	if err := f.grant.PopulateTokenEndpointResponse(t.Context(), request, response); err != nil {
		return err
	}

	return f.subject.PopulateTokenEndpointResponse(t.Context(), request, response)
}

func (f *txnSubjectFixture) exchange(t *testing.T, client oauth2.Client, subjectType, value string) (*DefaultSession, error) {
	t.Helper()

	request := f.subjectRequest(client, subjectType, value, nil)

	err := f.handle(t, request)

	return request.GetSession().(*DefaultSession), err
}

type txnJWKSClient struct {
	*oauth2.DefaultClient

	JSONWebKeys    *jose.JSONWebKeySet
	JSONWebKeysURI string
}

func (c *txnJWKSClient) GetJSONWebKeys() *jose.JSONWebKeySet {
	return c.JSONWebKeys
}

func (c *txnJWKSClient) GetJSONWebKeysURI() string {
	return c.JSONWebKeysURI
}

type txnUnsignedClient struct {
	*oauth2.DefaultClient

	allow bool
}

func (c *txnUnsignedClient) GetAllowUnsignedJSONSubjectToken() bool {
	return c.allow
}

type txnJWKSFetcher struct {
	jwks        *jose.JSONWebKeySet
	err         error
	location    string
	ignoreCache bool
}

func (f *txnJWKSFetcher) Resolve(_ context.Context, location string, ignoreCache bool) (*jose.JSONWebKeySet, error) {
	f.location, f.ignoreCache = location, ignoreCache

	return f.jwks, f.err
}

func txnJTIStores() map[string]CustomJWTStorage {
	return map[string]CustomJWTStorage{
		"ExampleStore":   storage.NewExampleStore(),
		"HydratingStore": storage.NewHydratingMemoryStore(),
	}
}

func assertSubjectRefused(t *testing.T, session *DefaultSession, err error) {
	t.Helper()

	require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
	assert.Nil(t, session.GetSubjectToken())
	assert.Empty(t, session.GetSubject())
}

func selfSignedClaims() map[string]any {
	now := time.Now()

	return map[string]any{
		consts.ClaimIssuer:         txnClientID,
		consts.ClaimSubject:        "alice",
		consts.ClaimAudience:       txnIdentifier,
		consts.ClaimIssuedAt:       now.Unix(),
		consts.ClaimExpirationTime: now.Add(time.Minute).Unix(),
	}
}

func newTxnKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	return key
}

func signToken(t *testing.T, alg jose.SignatureAlgorithm, key any, kid string, claims, headers map[string]any) string {
	t.Helper()

	options := &jose.SignerOptions{}

	if kid != "" {
		options.WithHeader(jose.HeaderKey("kid"), kid)
	}

	for name, value := range headers {
		options.WithHeader(jose.HeaderKey(name), value)
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, options)
	require.NoError(t, err)

	payload, err := json.Marshal(claims)
	require.NoError(t, err)

	signed, err := signer.Sign(payload)
	require.NoError(t, err)

	token, err := signed.CompactSerialize()
	require.NoError(t, err)

	return token
}

func encryptToken(t *testing.T, key *ecdsa.PublicKey, claims map[string]any) string {
	t.Helper()

	encrypter, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{Algorithm: jose.ECDH_ES, Key: key}, nil)
	require.NoError(t, err)

	payload, err := json.Marshal(claims)
	require.NoError(t, err)

	encrypted, err := encrypter.Encrypt(payload)
	require.NoError(t, err)

	token, err := encrypted.CompactSerialize()
	require.NoError(t, err)

	return token
}

func unsecuredToken(t *testing.T, claims map[string]any) string {
	t.Helper()

	payload, err := json.Marshal(claims)
	require.NoError(t, err)

	encoding := base64.RawURLEncoding

	return encoding.EncodeToString([]byte(`{"alg":"none"}`)) + "." + encoding.EncodeToString(payload) + "."
}

func tamperPayload(t *testing.T, token string) string {
	t.Helper()

	object, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES256})
	require.NoError(t, err)

	var claims map[string]any

	require.NoError(t, json.Unmarshal(object.UnsafePayloadWithoutVerification(), &claims))

	claims[consts.ClaimSubject] = "mallory"

	payload, err := json.Marshal(claims)
	require.NoError(t, err)

	parts := strings.Split(token, ".")

	return parts[0] + "." + base64.RawURLEncoding.EncodeToString(payload) + "." + parts[2]
}
