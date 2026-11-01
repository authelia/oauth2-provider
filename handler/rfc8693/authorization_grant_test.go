// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/handler/rfc7523"
	. "authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/hmac"
	"authelia.com/provider/oauth2/token/jwt"
)

const (
	grantIssuer = "https://as.a.example/auth"
	grantTarget = "https://as.b.example/auth"
	grantOther  = "https://as.c.example/auth"
)

func TestAuthorizationGrantClaims(t *testing.T) {
	f := newGrantFixture(t, nil)

	response, err := f.exchange(t, grantExchange{audience: []string{grantTarget}, scopes: []string{"photos"}, subjectScopes: []string{"photos", "oauth2"}})
	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

	assert.Equal(t, oauth2.RFC8693NAToken, response.GetTokenType())
	assert.Equal(t, consts.TokenTypeRFC8693JWT, response.GetExtra(consts.FormParameterIssuedTokenType))

	token, claims := parseGrant(t, response)

	assert.Equal(t, "JWT", token.Header[consts.JSONWebTokenHeaderType])
	assert.Equal(t, grantIssuer, claims[consts.ClaimIssuer])
	assert.Equal(t, "peter", claims[consts.ClaimSubject])
	assert.Equal(t, []any{grantTarget}, claims[consts.ClaimAudience])
	assert.Equal(t, "photos", claims[consts.ClaimScope])
	assert.NotEmpty(t, claims[consts.ClaimJWTID])
	assert.NotZero(t, claims[consts.ClaimIssuedAt])
	assert.NotZero(t, claims[consts.ClaimExpirationTime])

	assert.ElementsMatch(t, []string{
		consts.ClaimIssuer, consts.ClaimSubject, consts.ClaimAudience, consts.ClaimScope,
		consts.ClaimJWTID, consts.ClaimIssuedAt, consts.ClaimExpirationTime,
	}, claimNames(claims), "session claims must not cross the trust domain")
}

func TestAuthorizationGrantIgnoresStaleSessionClaims(t *testing.T) {
	f := newGrantFixture(t, nil)
	session := newSpecSession("peter")
	session.Claims.Issuer = "https://stale.example.com"
	session.Claims.JTI = "stale-jti"
	session.Claims.ExpirationTime = jwt.NewNumericDate(time.Now().Add(-time.Hour))

	response, err := f.exchange(t, grantExchange{audience: []string{grantTarget}, session: session})
	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

	_, claims := parseGrant(t, response)

	assert.Equal(t, grantIssuer, claims[consts.ClaimIssuer])
	assert.NotEqual(t, "stale-jti", claims[consts.ClaimJWTID])
}

func TestAuthorizationGrantOmitsAnEmptyScope(t *testing.T) {
	f := newGrantFixture(t, nil)

	response, err := f.exchange(t, grantExchange{audience: []string{grantTarget}})
	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

	_, claims := parseGrant(t, response)

	assert.NotContains(t, claims, consts.ClaimScope)
}

func TestAuthorizationGrantTarget(t *testing.T) {
	testCases := []struct {
		name     string
		audience []string
		resource []string
		expected error
		aud      []any
	}{
		{name: "ShouldAcceptAnAudience", audience: []string{grantTarget}, aud: []any{grantTarget}},
		{name: "ShouldAcceptAResource", resource: []string{grantTarget}, aud: []any{grantTarget}},
		{name: "ShouldAcceptTheSameAudienceAndResource", audience: []string{grantTarget}, resource: []string{grantTarget}, aud: []any{grantTarget}},
		{name: "ShouldRejectNoTargetDespiteADefaultAudience", expected: oauth2.ErrInvalidRequest},
		{name: "ShouldRejectTwoAudiences", audience: []string{grantTarget, grantOther}, expected: oauth2.ErrInvalidTarget},
		{name: "ShouldRejectTwoResources", resource: []string{grantTarget, grantOther}, expected: oauth2.ErrInvalidTarget},
		{name: "ShouldRejectADifferentAudienceAndResource", audience: []string{grantTarget}, resource: []string{grantOther}, expected: oauth2.ErrInvalidTarget},
		{name: "ShouldRejectAnUnknownAudience", audience: []string{"https://unknown.example/auth"}, expected: oauth2.ErrInvalidTarget},
		{name: "ShouldRejectAnUnknownResource", resource: []string{"https://unknown.example/auth"}, expected: oauth2.ErrInvalidTarget},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := newGrantFixture(t, func(jwtType *JWTType) {
				jwtType.Audience = []string{grantOther}
			})

			response, err := f.exchange(t, grantExchange{audience: tc.audience, resource: tc.resource})

			if tc.expected != nil {
				require.ErrorIs(t, err, tc.expected)

				return
			}

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

			_, claims := parseGrant(t, response)

			assert.Equal(t, tc.aud, claims[consts.ClaimAudience])
		})
	}
}

func TestAuthorizationGrantSubjectToken(t *testing.T) {
	t.Run("ShouldRejectAScopeTheOwnTokenWasNotGranted", func(t *testing.T) {
		f := newGrantFixture(t, nil)

		_, err := f.exchange(t, grantExchange{audience: []string{grantTarget}, scopes: []string{"photos"}, subjectScopes: []string{"oauth2"}})

		require.ErrorIs(t, err, oauth2.ErrInvalidScope)
	})

	t.Run("ShouldStillRejectTheOwnTokenForAnotherJWTType", func(t *testing.T) {
		f := newGrantFixture(t, func(jwtType *JWTType) {
			jwtType.AuthorizationGrant = false
		})

		_, err := f.exchange(t, grantExchange{audience: []string{grantTarget}})

		require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
	})

	t.Run("ShouldStillRejectAPublicClient", func(t *testing.T) {
		f := newGrantFixture(t, nil)
		f.client.Public = true

		_, err := f.exchange(t, grantExchange{audience: []string{grantTarget}})

		require.ErrorIs(t, err, oauth2.ErrInvalidGrant)
	})

	t.Run("ShouldNotOutliveTheSubjectToken", func(t *testing.T) {
		f := newGrantFixture(t, nil)
		limit := time.Now().Add(time.Minute)

		response, err := f.exchange(t, grantExchange{audience: []string{grantTarget}, subjectExpires: limit})
		require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

		_, claims := parseGrant(t, response)

		assert.LessOrEqual(t, toUnix(t, claims[consts.ClaimExpirationTime]), limit.Unix())
	})
}

func TestAuthorizationGrantActor(t *testing.T) {
	prior := map[string]any{consts.ClaimSubject: "prior-service"}

	t.Run("ShouldCarryThePriorActorsOfTheSubjectToken", func(t *testing.T) {
		f := newGrantFixture(t, nil)

		response, err := f.exchange(t, grantExchange{audience: []string{grantTarget}, subjectActor: prior})
		require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

		_, claims := parseGrant(t, response)

		assert.Equal(t, prior, claims[consts.ClaimActor])
	})

	t.Run("ShouldNestThePriorActorsUnderTheActorToken", func(t *testing.T) {
		f := newGrantFixture(t, nil)

		response, err := f.exchange(t, grantExchange{audience: []string{grantTarget}, subjectActor: prior, subjectMayAct: map[string]any{consts.ClaimSubject: "actor"}, actorSubject: "actor"})
		require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

		_, claims := parseGrant(t, response)

		act, ok := claims[consts.ClaimActor].(map[string]any)
		require.True(t, ok)

		assert.Equal(t, "actor", act[consts.ClaimSubject])
		assert.Equal(t, prior, act[consts.ClaimActor])
	})
}

func TestAuthorizationGrantRequiresMayActForAnActor(t *testing.T) {
	f := newGrantFixture(t, nil)

	_, err := f.exchange(t, grantExchange{audience: []string{grantTarget}, actorSubject: "actor"})

	require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
	assert.Contains(t, oauth2.ErrorToDebugRFC6749Error(err).Error(), "no 'may_act' claim")
}

func TestAuthorizationGrantHonoursTheIssuanceDecisionLifespan(t *testing.T) {
	f := newGrantFixture(t, nil)

	response, err := f.exchange(t, grantExchange{
		audience: []string{grantTarget},
		decision: &oauth2.IssuanceDecision{Lifespans: map[oauth2.TokenType]time.Duration{oauth2.ExchangedToken: time.Minute}},
	})
	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

	_, claims := parseGrant(t, response)

	assert.InDelta(t, time.Now().Add(time.Minute).Unix(), claims[consts.ClaimExpirationTime], 2)
}

func TestAuthorizationGrantExpiresTooSoon(t *testing.T) {
	f := newGrantFixture(t, nil)

	time.Sleep(time.Until(time.Now().Truncate(time.Second).Add(time.Second)))

	_, err := f.exchange(t, grantExchange{audience: []string{grantTarget}, subjectExpires: time.Now().Truncate(time.Second).Add(999 * time.Millisecond)})

	require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
}

func TestAuthorizationGrantTranscribeClaims(t *testing.T) {
	t.Run("ShouldDiscardAnInPlaceChangeToTheAudience", func(t *testing.T) {
		f := newGrantFixture(t, func(jwtType *JWTType) {
			jwtType.TranscribeClaims = func(_ context.Context, _ oauth2.AccessRequester, claims map[string]any) error {
				claims[consts.ClaimAudience].([]string)[0] = "https://evil.example"

				return nil
			}
		})

		response, err := f.exchange(t, grantExchange{audience: []string{grantTarget}})
		require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

		_, claims := parseGrant(t, response)

		assert.Equal(t, []any{grantTarget}, claims[consts.ClaimAudience])
	})

	t.Run("ShouldApplyTheChanges", func(t *testing.T) {
		f := newGrantFixture(t, func(jwtType *JWTType) {
			jwtType.TranscribeClaims = func(_ context.Context, _ oauth2.AccessRequester, claims map[string]any) error {
				claims[consts.ClaimSubject] = "doe.john@b.example"
				claims["transaction_limit"] = "10000"
				delete(claims, consts.ClaimScope)

				return nil
			}
		})

		response, err := f.exchange(t, grantExchange{audience: []string{grantTarget}, scopes: []string{"photos"}, subjectScopes: []string{"photos"}})
		require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

		_, claims := parseGrant(t, response)

		assert.Equal(t, "doe.john@b.example", claims[consts.ClaimSubject])
		assert.Equal(t, "10000", claims["transaction_limit"])
		assert.NotContains(t, claims, consts.ClaimScope)
	})

	t.Run("ShouldDiscardChangesToProtectedClaims", func(t *testing.T) {
		f := newGrantFixture(t, func(jwtType *JWTType) {
			jwtType.TranscribeClaims = func(_ context.Context, _ oauth2.AccessRequester, claims map[string]any) error {
				claims[consts.ClaimIssuer] = "https://evil.example"
				claims[consts.ClaimAudience] = []string{"https://evil.example"}
				claims[consts.ClaimExpirationTime] = int64(4102444800)
				claims[consts.ClaimIssuedAt] = int64(1)
				claims[consts.ClaimJWTID] = "fixed"

				return nil
			}
		})

		before := time.Now().Add(-time.Minute).Unix()

		response, err := f.exchange(t, grantExchange{audience: []string{grantTarget}})
		require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

		_, claims := parseGrant(t, response)

		assert.Equal(t, grantIssuer, claims[consts.ClaimIssuer])
		assert.Equal(t, []any{grantTarget}, claims[consts.ClaimAudience])
		assert.Less(t, toUnix(t, claims[consts.ClaimExpirationTime]), int64(4102444800))
		assert.Greater(t, toUnix(t, claims[consts.ClaimIssuedAt]), before)
		assert.NotEqual(t, "fixed", claims[consts.ClaimJWTID])
	})

	t.Run("ShouldRestoreARemovedProtectedClaim", func(t *testing.T) {
		f := newGrantFixture(t, func(jwtType *JWTType) {
			jwtType.TranscribeClaims = func(_ context.Context, _ oauth2.AccessRequester, claims map[string]any) error {
				delete(claims, consts.ClaimAudience)

				return nil
			}
		})

		response, err := f.exchange(t, grantExchange{audience: []string{grantTarget}})
		require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

		_, claims := parseGrant(t, response)

		assert.Equal(t, []any{grantTarget}, claims[consts.ClaimAudience])
	})

	for name, mutate := range map[string]func(map[string]any){
		"ShouldRejectAnEmptySubject":    func(claims map[string]any) { claims[consts.ClaimSubject] = "" },
		"ShouldRejectARemovedSubject":   func(claims map[string]any) { delete(claims, consts.ClaimSubject) },
		"ShouldRejectANonStringSubject": func(claims map[string]any) { claims[consts.ClaimSubject] = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			f := newGrantFixture(t, func(jwtType *JWTType) {
				jwtType.TranscribeClaims = func(_ context.Context, _ oauth2.AccessRequester, claims map[string]any) error {
					mutate(claims)

					return nil
				}
			})

			_, err := f.exchange(t, grantExchange{audience: []string{grantTarget}})

			require.ErrorIs(t, err, oauth2.ErrServerError)
		})
	}

	t.Run("ShouldDenyTheRequestWithTheReturnedError", func(t *testing.T) {
		f := newGrantFixture(t, func(jwtType *JWTType) {
			jwtType.TranscribeClaims = func(_ context.Context, _ oauth2.AccessRequester, _ map[string]any) error {
				return oauth2.ErrInvalidRequest.WithHint("The subject is unknown to the trust domain.")
			}
		})

		_, err := f.exchange(t, grantExchange{audience: []string{grantTarget}})

		require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
		assert.Contains(t, oauth2.ErrorToDebugRFC6749Error(err).Error(), "The subject is unknown to the trust domain.")
	})

	t.Run("ShouldNotBeCalledForAnotherJWTType", func(t *testing.T) {
		called := false

		f := newGrantFixture(t, func(jwtType *JWTType) {
			jwtType.AuthorizationGrant = false
			jwtType.TranscribeClaims = func(_ context.Context, _ oauth2.AccessRequester, _ map[string]any) error {
				called = true

				return errors.New("unexpected")
			}
		})

		_, err := f.exchange(t, grantExchange{audience: []string{grantTarget}, subjectClient: "custom-lifespan-client"})

		require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
		assert.False(t, called)
	})
}

func TestAuthorizationGrantSigning(t *testing.T) {
	t.Run("ShouldIgnoreTheIDTokenConfigurationOfTheClient", func(t *testing.T) {
		f := newGrantFixture(t, nil)
		f.requester = &oauth2.DefaultRegisteredClient{
			DefaultClient:                   f.client,
			TokenExchangeAuthorizationGrant: true,
			IDTokenSignedResponseAlg:        "HS256",
			IDTokenEncryptedResponseAlg:     "dir",
			IDTokenEncryptedResponseEnc:     "A128CBC-HS256",
		}

		response, err := f.exchange(t, grantExchange{audience: []string{grantTarget}})
		require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

		token, _ := parseGrant(t, response)

		assert.Equal(t, "RS256", token.Header[consts.JSONWebTokenHeaderAlgorithm])
	})

	t.Run("ShouldSelectTheIssuerKeyWithTheSigningAlg", func(t *testing.T) {
		f := newGrantFixture(t, func(jwtType *JWTType) {
			jwtType.SigningAlg = "ES256"
		})

		_, err := f.exchange(t, grantExchange{audience: []string{grantTarget}})

		require.Error(t, err, "the fixture has no ES256 key, so the algorithm must have reached the key lookup")
	})

	t.Run("ShouldSignWithTheKeyOfTheSigningAlg", func(t *testing.T) {
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		f := newGrantFixture(t, func(jwtType *JWTType) {
			jwtType.SigningAlg = "ES256"
		})

		f.strategy.Issuer, err = jwt.NewDefaultIssuer(
			jose.JSONWebKey{Key: key, KeyID: "rs", Algorithm: "RS256", Use: "sig"},
			jose.JSONWebKey{Key: ecKey, KeyID: "es", Algorithm: "ES256", Use: "sig"},
		)
		require.NoError(t, err)

		response, err := f.exchange(t, grantExchange{audience: []string{grantTarget}})
		require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

		token, err := jwt.ParseWithClaims(response.GetAccessToken(), jwt.MapClaims{}, func(_ *jwt.Token) (any, error) {
			return ecKey.Public(), nil
		})
		require.NoError(t, err)

		assert.Equal(t, "ES256", token.Header[consts.JSONWebTokenHeaderAlgorithm])
	})

	t.Run("ShouldRejectTheIDTokenIssuer", func(t *testing.T) {
		f := newGrantFixture(t, nil)
		f.cfg.IDTokenIssuer = grantIssuer

		_, err := f.exchange(t, grantExchange{audience: []string{grantTarget}})

		require.ErrorIs(t, err, oauth2.ErrServerError)
	})

	t.Run("ShouldRejectAnEmptyIssuer", func(t *testing.T) {
		f := newGrantFixture(t, func(jwtType *JWTType) {
			jwtType.Issuer = ""
		})

		_, err := f.exchange(t, grantExchange{audience: []string{grantTarget}})

		require.ErrorIs(t, err, oauth2.ErrServerError)
	})
}

func TestAuthorizationGrantResponse(t *testing.T) {
	t.Run("ShouldReportTheLifetimeAndScope", func(t *testing.T) {
		f := newGrantFixture(t, nil)

		response, err := f.exchange(t, grantExchange{audience: []string{grantTarget}, scopes: []string{"photos"}, subjectScopes: []string{"photos"}})
		require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

		assert.Equal(t, "photos", response.GetExtra(consts.AccessResponseScope))
		assert.InDelta(t, 300, response.GetExtra(consts.AccessResponseExpiresIn), 2)
	})

	t.Run("ShouldReportTheTranscribedScope", func(t *testing.T) {
		f := newGrantFixture(t, func(jwtType *JWTType) {
			jwtType.TranscribeClaims = func(_ context.Context, _ oauth2.AccessRequester, claims map[string]any) error {
				delete(claims, consts.ClaimScope)

				return nil
			}
		})

		response, err := f.exchange(t, grantExchange{audience: []string{grantTarget}, scopes: []string{"photos"}, subjectScopes: []string{"photos"}})
		require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

		assert.Nil(t, response.GetExtra(consts.AccessResponseScope))
	})

	t.Run("ShouldIssueTheDefaultRequestedTokenType", func(t *testing.T) {
		f := newGrantFixture(t, nil)
		f.cfg.DefaultRequestedTokenType = consts.TokenTypeRFC8693JWT

		response, err := f.exchange(t, grantExchange{audience: []string{grantTarget}, omitRequestedType: true})
		require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

		_, claims := parseGrant(t, response)

		assert.Equal(t, grantIssuer, claims[consts.ClaimIssuer])
	})
}

// RFC 8725 Section 3.12 and Section 2.3.3: a grant is not a token this server accepts from a client.
func TestAuthorizationGrantIsNotAcceptedBack(t *testing.T) {
	trusting := func(jwtType *JWTType) {
		jwtType.ValidateFunc = func(_ *jwt.Token) (any, error) { return key.PublicKey, nil }
	}

	t.Run("ShouldRejectAGrantAsTheSubjectToken", func(t *testing.T) {
		f := newGrantFixture(t, trusting)

		response, err := f.exchange(t, grantExchange{audience: []string{grantTarget}})
		require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

		_, err = f.exchange(t, grantExchange{audience: []string{grantOther}, subjectToken: response.GetAccessToken(), subjectTokenType: consts.TokenTypeRFC8693JWT})

		require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
		assert.Contains(t, oauth2.ErrorToDebugRFC6749Error(err).Error(), "cannot be exchanged")
	})

	t.Run("ShouldRejectAGrantAsTheActorToken", func(t *testing.T) {
		f := newGrantFixture(t, trusting)

		response, err := f.exchange(t, grantExchange{audience: []string{grantTarget}})
		require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

		_, err = f.exchange(t, grantExchange{audience: []string{grantOther}, actorToken: response.GetAccessToken()})

		require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
		assert.Contains(t, oauth2.ErrorToDebugRFC6749Error(err).Error(), "cannot be exchanged")
	})

	t.Run("ShouldNotIssueWhileAnIDTokenCouldBeAcceptedWithAnyIssuer", func(t *testing.T) {
		f := newGrantFixture(t, nil)
		f.cfg.IDTokenIssuer = ""

		_, err := f.exchange(t, grantExchange{audience: []string{grantTarget}})

		require.ErrorIs(t, err, oauth2.ErrServerError)
	})

	t.Run("ShouldIssueWithoutAnIDTokenIssuerWhenIDTokensAreNotExchanged", func(t *testing.T) {
		f := newGrantFixture(t, nil)
		f.cfg.IDTokenIssuer = ""

		delete(f.cfg.RFC8693TokenTypes, consts.TokenTypeRFC8693IDToken)

		_, err := f.exchange(t, grantExchange{audience: []string{grantTarget}})

		require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
	})
}

func TestAuthorizationGrantSubjectIdentity(t *testing.T) {
	t.Run("ShouldRejectASubjectTokenWithoutASubject", func(t *testing.T) {
		f := newGrantFixture(t, nil)

		_, err := f.exchange(t, grantExchange{audience: []string{grantTarget}, noSubject: true})

		require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
	})

	t.Run("ShouldAcceptASubjectAssignedByTranscription", func(t *testing.T) {
		f := newGrantFixture(t, func(jwtType *JWTType) {
			jwtType.TranscribeClaims = func(_ context.Context, request oauth2.AccessRequester, claims map[string]any) error {
				claims[consts.ClaimSubject] = request.GetClient().GetID()

				return nil
			}
		})

		response, err := f.exchange(t, grantExchange{audience: []string{grantTarget}, noSubject: true})
		require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

		_, claims := parseGrant(t, response)

		assert.Equal(t, "chaining-client", claims[consts.ClaimSubject])
	})
}

func TestAuthorizationGrantPolicyOfOtherClients(t *testing.T) {
	testCases := []struct {
		name      string
		permitted []string
		expected  error
	}{
		{name: "ShouldAcceptAPermittedClient", permitted: []string{"chaining-client"}},
		{name: "ShouldRejectAClientNotPermitted", permitted: []string{"someone-else"}, expected: oauth2.ErrInvalidRequest},
		{name: "ShouldAcceptAnAddressedTokenWithAnEmptyList"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := newGrantFixture(t, nil)

			owner := &oauth2.DefaultRegisteredClient{
				DefaultClient:                   &oauth2.DefaultClient{ID: "owner", GrantTypes: []string{consts.GrantTypeClientCredentials}},
				TokenExchangePermittedClientIDs: tc.permitted,
			}

			_, err := f.exchange(t, grantExchange{audience: []string{grantTarget}, subjectOwner: owner})

			if tc.expected != nil {
				require.ErrorIs(t, err, tc.expected)

				return
			}

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
		})
	}
}

func TestAuthorizationGrantClientOptIn(t *testing.T) {
	testCases := []struct {
		name      string
		requester func(client *oauth2.DefaultClient) oauth2.Client
		expected  error
	}{
		{
			name: "ShouldIssueWhenOptedIn",
			requester: func(client *oauth2.DefaultClient) oauth2.Client {
				return &oauth2.DefaultRegisteredClient{DefaultClient: client, TokenExchangeAuthorizationGrant: true}
			},
		},
		{
			name: "ShouldRefuseAClientWhichHasNotOptedIn",
			requester: func(client *oauth2.DefaultClient) oauth2.Client {
				return &oauth2.DefaultRegisteredClient{DefaultClient: client}
			},
			expected: oauth2.ErrUnauthorizedClient,
		},
		{
			name: "ShouldRefuseAClientWithoutTheInterface",
			requester: func(client *oauth2.DefaultClient) oauth2.Client {
				return client
			},
			expected: oauth2.ErrUnauthorizedClient,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := newGrantFixture(t, nil)
			f.requester = tc.requester(f.client)

			response, err := f.exchange(t, grantExchange{audience: []string{grantTarget}})

			if tc.expected != nil {
				require.ErrorIs(t, err, tc.expected)

				return
			}

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
			assert.NotEmpty(t, response.GetAccessToken())
		})
	}
}

func TestAuthorizationGrantRecordsTheBindingOfTheSubjectToken(t *testing.T) {
	f := newGrantFixture(t, nil)
	session := newSpecSession("")

	_, err := f.exchange(t, grantExchange{audience: []string{grantTarget}, subjectJKT: bindingJKT, session: session})
	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

	assert.Equal(t, bindingJKT, session.GetDPoPJWKThumbprint())
}

func TestAuthorizationGrantHydratingStore(t *testing.T) {
	prior := map[string]any{consts.ClaimSubject: "prior-service"}
	store := storage.NewHydratingMemoryStore()

	f := newGrantFixtureWithStore(t, store, nil)

	response, err := f.exchange(t, grantExchange{audience: []string{grantTarget}, scopes: []string{"photos"}, subjectScopes: []string{"photos"}, subjectActor: prior})
	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

	_, claims := parseGrant(t, response)

	assert.Equal(t, "peter", claims[consts.ClaimSubject])
	assert.Equal(t, "photos", claims[consts.ClaimScope])
	assert.Equal(t, prior, claims[consts.ClaimActor])
	assert.NotContains(t, claims, "email")
}

// Section 2.4: the issued grant is an assertion the RFC 7523 handler of the other trust domain accepts.
func TestAuthorizationGrantRedeemedWithRFC7523(t *testing.T) {
	f := newGrantFixture(t, nil)

	response, err := f.exchange(t, grantExchange{audience: []string{grantTarget}, scopes: []string{"photos"}, subjectScopes: []string{"photos"}})
	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

	token, _ := parseGrant(t, response)
	kid, _ := token.Header[consts.JSONWebTokenHeaderKeyIdentifier].(string)

	store := storage.NewMemoryStore()
	store.IssuerPublicKeys[grantIssuer] = storage.IssuerPublicKeys{
		Issuer: grantIssuer,
		KeysBySub: map[string]storage.SubjectPublicKeys{
			"peter": {Subject: "peter", Keys: map[string]storage.PublicKeyScopes{
				kid: {Key: &jose.JSONWebKey{Key: key.Public(), KeyID: kid, Algorithm: "RS256", Use: "sig"}, Scopes: []string{"photos"}},
			}},
		},
	}

	handler := &rfc7523.Handler{
		Storage: store,
		Config: &oauth2.Config{
			AllowedJWTAssertionAudiences: []string{grantTarget},
			ScopeStrategy:                oauth2.ExactScopeStrategy,
		},
		HandleHelper: &hoauth2.HandleHelper{},
	}

	session := newSpecSession("")
	request := &oauth2.AccessRequest{
		GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthJWTBearer},
		Request: oauth2.Request{
			ID:             uuid.New().String(),
			Client:         &oauth2.DefaultClient{ID: "domain-b-client", GrantTypes: []string{consts.GrantTypeOAuthJWTBearer}, Scopes: []string{"photos"}},
			RequestedScope: oauth2.Arguments{"photos"},
			Form:           url.Values{consts.FormParameterAssertion: {response.GetAccessToken()}},
			Session:        session,
		},
	}

	handler.HandleHelper.Config = &oauth2.Config{AccessTokenLifespan: time.Minute}

	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.HandleTokenEndpointRequest(t.Context(), request)))

	assert.Equal(t, "peter", session.GetSubject())
	assert.Equal(t, oauth2.Arguments{"photos"}, request.GetGrantedScopes())
}

type grantStore interface {
	hoauth2.AccessTokenStorage
	Storage
}

type grantExchange struct {
	decision                                  *oauth2.IssuanceDecision
	audience, resource, scopes, subjectScopes []string
	subjectClient, actorSubject               string
	subjectActor                              map[string]any
	subjectExpires                            time.Time
	subjectMayAct                             map[string]any
	subjectOwner                              oauth2.Client
	subjectToken, subjectTokenType            string
	actorToken, subjectJKT                    string
	noSubject, omitRequestedType              bool
	session                                   *DefaultSession
}

type grantFixture struct {
	cfg       *oauth2.Config
	store     grantStore
	owners    map[string]oauth2.Client
	client    *oauth2.DefaultClient
	requester oauth2.Client
	core      hoauth2.CoreStrategy
	strategy  *jwt.DefaultStrategy
	handlers  []oauth2.TokenEndpointHandler
}

func newGrantFixture(t *testing.T, configure func(jwtType *JWTType)) *grantFixture {
	t.Helper()

	return newGrantFixtureWithStore(t, storage.NewExampleStore(), configure)
}

func newGrantFixtureWithStore(t *testing.T, store grantStore, configure func(jwtType *JWTType)) *grantFixture {
	t.Helper()

	cfg := newSpecConfig(t)

	jwtType := &JWTType{
		Name:   consts.TokenTypeRFC8693JWT,
		Issuer: grantIssuer,
		JWTIssueConfig: JWTIssueConfig{
			AuthorizationGrant: true,
			Expiry:             5 * time.Minute,
		},
	}

	if configure != nil {
		configure(jwtType)
	}

	cfg.RFC8693TokenTypes[consts.TokenTypeRFC8693JWT] = jwtType
	cfg.IDTokenIssuer = "https://op.a.example"

	client := &oauth2.DefaultClient{
		ID:           "chaining-client",
		ClientSecret: oauth2.NewPlainTextClientSecret("secret"),
		GrantTypes:   []string{consts.GrantTypeOAuthTokenExchange},
		Scopes:       []string{"photos", "oauth2"},
		Audience:     []string{grantTarget, grantOther},
		Resource:     []string{grantTarget, grantOther},
	}

	core := &hoauth2.HMACCoreStrategy{Enigma: &hmac.HMACStrategy{Config: cfg}, Config: cfg}
	strategy := &jwt.DefaultStrategy{Config: cfg, Issuer: jwt.NewDefaultIssuerRS256Unverified(key)}

	return &grantFixture{
		cfg:       cfg,
		store:     store,
		owners:    storage.NewExampleStore().Clients,
		client:    client,
		requester: &oauth2.DefaultRegisteredClient{DefaultClient: client, TokenExchangeAuthorizationGrant: true},
		core:      core,
		strategy:  strategy,
		handlers: []oauth2.TokenEndpointHandler{
			&TokenExchangeGrantHandler{Config: cfg, ScopeStrategy: oauth2.ExactScopeStrategy, AudienceStrategy: oauth2.ExactAudienceStrategy, ResourceStrategy: oauth2.ExactAudienceStrategy},
			&AccessTokenTypeHandler{Config: cfg, AccessTokenLifespan: 5 * time.Minute, RefreshTokenLifespan: 5 * time.Minute, CoreStrategy: core, ScopeStrategy: oauth2.ExactScopeStrategy, Storage: store},
			&CustomJWTTypeHandler{Config: cfg, Strategy: strategy, Storage: store},
			&ActorTokenValidationHandler{},
		},
	}
}

func (f *grantFixture) mint(t *testing.T, client oauth2.Client, subject string, scopes []string, act, mayAct map[string]any, jkt string, expires time.Time) string {
	t.Helper()

	session := newSpecSession(subject)
	session.SetExpiresAt(oauth2.AccessToken, expires)
	session.SetDPoPJWKThumbprint(jkt)

	if mayAct != nil {
		session.Extra[consts.ClaimAuthorizedActor] = mayAct
	}

	if act != nil {
		session.SetClaimActor(act)
	}

	request := &oauth2.AccessRequest{
		GrantTypes: oauth2.Arguments{consts.GrantTypeClientCredentials},
		Request:    oauth2.Request{ID: uuid.New().String(), Client: client, Session: session, GrantedScope: scopes},
	}

	grantFixtureAudience(request)

	token, signature, err := f.core.GenerateAccessToken(t.Context(), request)
	require.NoError(t, err)
	require.NoError(t, f.store.CreateAccessTokenSession(t.Context(), signature, request))

	return token
}

func (f *grantFixture) exchange(t *testing.T, e grantExchange) (*oauth2.AccessResponse, error) {
	t.Helper()

	expires := e.subjectExpires
	if expires.IsZero() {
		expires = time.Now().UTC().Add(10 * time.Minute)
	}

	owner := f.requester
	if e.subjectClient != "" {
		owner = permittingOwner(f.owners[e.subjectClient])
	}

	if e.subjectOwner != nil {
		owner = e.subjectOwner
	}

	subject := "peter"
	if e.noSubject {
		subject = ""
	}

	subjectToken, subjectTokenType := e.subjectToken, e.subjectTokenType
	if subjectToken == "" {
		subjectToken = f.mint(t, owner, subject, e.subjectScopes, e.subjectActor, e.subjectMayAct, e.subjectJKT, expires)
		subjectTokenType = consts.TokenTypeRFC8693AccessToken
	}

	form := url.Values{
		consts.FormParameterGrantType:        {consts.GrantTypeOAuthTokenExchange},
		consts.FormParameterSubjectTokenType: {subjectTokenType},
		consts.FormParameterSubjectToken:     {subjectToken},
	}

	if !e.omitRequestedType {
		form.Set(consts.FormParameterRequestedTokenType, consts.TokenTypeRFC8693JWT)
	}

	if e.actorSubject != "" {
		form.Set(consts.FormParameterActorTokenType, consts.TokenTypeRFC8693AccessToken)
		form.Set(consts.FormParameterActorToken, f.mint(t, f.requester, e.actorSubject, nil, nil, nil, "", expires))
	}

	if e.actorToken != "" {
		form.Set(consts.FormParameterActorTokenType, consts.TokenTypeRFC8693JWT)
		form.Set(consts.FormParameterActorToken, e.actorToken)
	}

	session := e.session
	if session == nil {
		session = newSpecSession("")
		session.Claims.Extra = map[string]any{"email": "peter@a.example"}
	}

	request := &oauth2.AccessRequest{
		GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthTokenExchange},
		Request: oauth2.Request{
			ID:                uuid.New().String(),
			Client:            f.requester,
			Form:              form,
			RequestedScope:    e.scopes,
			RequestedAudience: e.audience,
			RequestedResource: e.resource,
			Session:           session,
		},
	}

	ctx := t.Context()
	response := oauth2.NewAccessResponse()

	for _, handler := range f.handlers {
		if err := handler.HandleTokenEndpointRequest(ctx, request); err != nil {
			return nil, err
		}
	}

	if e.decision != nil {
		ctx = context.WithValue(ctx, oauth2.IssuanceDecisionContextKey, e.decision)
	}

	for _, handler := range f.handlers {
		if err := handler.PopulateTokenEndpointResponse(ctx, request, response); err != nil {
			return nil, err
		}
	}

	return response, nil
}

func parseGrant(t *testing.T, response *oauth2.AccessResponse) (*jwt.Token, map[string]any) {
	t.Helper()

	token, err := jwt.ParseWithClaims(response.GetAccessToken(), jwt.MapClaims{}, func(_ *jwt.Token) (any, error) {
		return key.PublicKey, nil
	})
	require.NoError(t, err)

	return token, token.Claims.ToMapClaims()
}

func claimNames(claims map[string]any) (names []string) {
	for name := range claims {
		names = append(names, name)
	}

	return names
}

func toUnix(t *testing.T, claim any) int64 {
	t.Helper()

	switch value := claim.(type) {
	case int64:
		return value
	case float64:
		return int64(value)
	default:
		require.Failf(t, "unexpected claim type", "%T", claim)

		return 0
	}
}
