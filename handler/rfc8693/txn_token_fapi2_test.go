// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

// FAPI 2.0 Security Profile §5.4.1: a JWT is signed with PS256, ES256 or EdDSA.
func TestTxnTokenSigningFAPI2SecurityProfile(t *testing.T) {
	testCases := []struct {
		name     string
		client   bool
		provider bool
		es256    bool
		refused  bool
	}{
		{name: "ShouldSignRS256ForAnOrdinaryClient"},
		{name: "ShouldRefuseRS256ForAProfileClient", client: true, refused: true},
		{name: "ShouldRefuseRS256ForAProfileProvider", provider: true, refused: true},
		{name: "ShouldSignES256ForAProfileClient", client: true, es256: true},
		{name: "ShouldSignES256ForAProfileProvider", provider: true, es256: true},
	}

	for name, store := range txnIssueStores() {
		t.Run(name, func(t *testing.T) {
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					f := newTxnIssueFixture(t, store)
					f.scopes.scopes = []string{"trade.stocks"}
					f.client.fapi2 = tc.client
					f.cfg.FAPI2SecurityProfile = tc.provider

					alg := "RS256"

					if tc.es256 {
						f.issueES256(t)

						alg = "ES256"
					}

					response, err := f.exchange(t, txnExchange{subjectType: consts.TokenTypeRFC8693UnsignedJSON, subjectToken: `{"sub":"alice"}`, scopes: []string{"trade.stocks"}})

					if tc.refused {
						require.ErrorIs(t, err, oauth2.ErrServerError)
						assert.Contains(t, oauth2.ErrorToDebugRFC6749Error(err).Error(), "the signing algorithm 'RS256' is not permitted")

						return
					}

					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

					token, err := jwt.UnsafeParseSignedAny(response.GetAccessToken(), &jwt.MapClaims{})
					require.NoError(t, err)
					require.Len(t, token.Headers, 1)

					assert.Equal(t, alg, token.Headers[0].Algorithm)
				})
			}
		})
	}
}

// FAPI 2.0 Security Profile §5.4.1: a JWT signed with another algorithm is not accepted.
func TestTxnTokenReplacementFAPI2SecurityProfileAlgorithms(t *testing.T) {
	testCases := []struct {
		name     string
		alg      jose.SignatureAlgorithm
		client   bool
		provider bool
		refused  bool
	}{
		{name: "ShouldAcceptRS256FromAnOrdinaryClient", alg: jose.RS256},
		{name: "ShouldRefuseRS256FromAProfileClient", alg: jose.RS256, client: true, refused: true},
		{name: "ShouldRefuseRS256ForAProfileProvider", alg: jose.RS256, provider: true, refused: true},
		{name: "ShouldAcceptPS256FromAProfileClient", alg: jose.PS256, client: true},
		{name: "ShouldAcceptES256FromAProfileClient", alg: jose.ES256, client: true},
		{name: "ShouldAcceptES256ForAProfileProvider", alg: jose.ES256, provider: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := newTxnIssueFixture(t, storage.NewExampleStore())
			f.enableReplacement()
			f.issueES256(t)
			f.client.fapi2 = tc.client
			f.cfg.FAPI2SecurityProfile = tc.provider

			_, err := f.exchange(t, txnReplacementExchange(f.presentedTxnToken(t, tc.alg, time.Now()), "trade.stocks"))

			if tc.refused {
				require.ErrorIs(t, err, oauth2.ErrInvalidRequest)

				return
			}

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
		})
	}
}

// FAPI 2.0 Security Profile §5.3.2.1: an 'iat' up to 10 seconds in the future is accepted.
func TestTxnTokenReplacementFAPI2SecurityProfileClockSkew(t *testing.T) {
	testCases := []struct {
		name    string
		client  bool
		refused bool
	}{
		{name: "ShouldRefuseAFutureIssuedAtFromAnOrdinaryClient", refused: true},
		{name: "ShouldAcceptAFutureIssuedAtFromAProfileClient", client: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := newTxnIssueFixture(t, storage.NewExampleStore())
			f.enableReplacement()
			f.issueES256(t)
			f.client.fapi2 = tc.client
			f.cfg.JWTClockSkew = time.Second

			_, err := f.exchange(t, txnReplacementExchange(f.presentedTxnToken(t, jose.ES256, time.Now().Add(6*time.Second)), "trade.stocks"))

			if tc.refused {
				require.ErrorIs(t, err, oauth2.ErrInvalidRequest)

				return
			}

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
		})
	}
}

// FAPI 2.0 Security Profile §5.4.1: a JWT signed with another algorithm is not accepted.
func TestTxnTokenSelfSignedFAPI2SecurityProfileAlgorithms(t *testing.T) {
	testCases := []struct {
		name     string
		alg      jose.SignatureAlgorithm
		client   bool
		provider bool
		refused  bool
	}{
		{name: "ShouldAcceptRS256FromAnOrdinaryClient", alg: jose.RS256},
		{name: "ShouldRefuseRS256FromAProfileClient", alg: jose.RS256, client: true, refused: true},
		{name: "ShouldRefuseRS256ForAProfileProvider", alg: jose.RS256, provider: true, refused: true},
		{name: "ShouldAcceptPS256FromAProfileClient", alg: jose.PS256, client: true},
		{name: "ShouldAcceptES256FromAProfileClient", alg: jose.ES256, client: true},
		{name: "ShouldAcceptES256ForAProfileProvider", alg: jose.ES256, provider: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := newTxnIssueFixture(t, storage.NewExampleStore())
			f.issueES256(t)
			f.scopes.scopes = []string{"trade.stocks"}
			f.client.fapi2 = tc.client
			f.cfg.FAPI2SecurityProfile = tc.provider

			_, err := f.exchange(t, txnExchange{subjectType: consts.TokenTypeRFC8693SelfSigned, subjectToken: f.selfSignedSubject(t, tc.alg, time.Now()), scopes: []string{"trade.stocks"}})

			if tc.refused {
				require.ErrorIs(t, err, oauth2.ErrInvalidRequest)

				return
			}

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
		})
	}
}

// FAPI 2.0 Security Profile §5.3.2.1: an 'iat' up to 10 seconds in the future is accepted.
func TestTxnTokenSelfSignedFAPI2SecurityProfileClockSkew(t *testing.T) {
	testCases := []struct {
		name    string
		client  bool
		refused bool
	}{
		{name: "ShouldRefuseAFutureIssuedAtFromAnOrdinaryClient", refused: true},
		{name: "ShouldAcceptAFutureIssuedAtFromAProfileClient", client: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := newTxnIssueFixture(t, storage.NewExampleStore())
			f.issueES256(t)
			f.scopes.scopes = []string{"trade.stocks"}
			f.client.fapi2 = tc.client
			f.cfg.JWTClockSkew = time.Second

			_, err := f.exchange(t, txnExchange{subjectType: consts.TokenTypeRFC8693SelfSigned, subjectToken: f.selfSignedSubject(t, jose.ES256, time.Now().Add(6*time.Second)), scopes: []string{"trade.stocks"}})

			if tc.refused {
				require.ErrorIs(t, err, oauth2.ErrInvalidRequest)

				return
			}

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
		})
	}
}

func (f *txnIssueFixture) issueES256(t *testing.T) {
	t.Helper()

	issuer, err := jwt.NewDefaultIssuer(
		jose.JSONWebKey{Key: key, KeyID: "rs", Algorithm: "RS256", Use: "sig"},
		jose.JSONWebKey{Key: newTxnKey(t), KeyID: "es", Algorithm: "ES256", Use: "sig"},
	)
	require.NoError(t, err)

	f.strategy.Issuer = issuer
	f.txnDomain.SigningAlg = "ES256"
}

func (f *txnIssueFixture) signingKey(alg jose.SignatureAlgorithm) (private, public any) {
	if alg == jose.ES256 {
		return f.workloadKey, &f.workloadKey.PublicKey
	}

	return key, &key.PublicKey
}

func (f *txnIssueFixture) presentedTxnToken(t *testing.T, alg jose.SignatureAlgorithm, issued time.Time) string {
	t.Helper()

	private, public := f.signingKey(alg)

	f.txnDomain.Replacement.KeyFunc = func(*jwt.Token) (any, error) { return public, nil }

	claims := map[string]any{
		consts.ClaimIssuedAt:           issued.Unix(),
		consts.ClaimExpirationTime:     issued.Add(time.Minute).Unix(),
		consts.ClaimAudience:           txnTrustDomain,
		consts.ClaimTransaction:        uuid.New().String(),
		consts.ClaimSubject:            "alice",
		consts.ClaimScope:              "trade.stocks",
		consts.ClaimRequestingWorkload: txnClientID,
	}

	return signToken(t, alg, private, "", claims, map[string]any{consts.JSONWebTokenHeaderType: consts.JSONWebTokenTypeTxnToken})
}

func (f *txnIssueFixture) selfSignedSubject(t *testing.T, alg jose.SignatureAlgorithm, issued time.Time) string {
	t.Helper()

	private, public := f.signingKey(alg)

	f.client.jwks = &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: public, KeyID: txnKeyID}}}

	claims := selfSignedClaims()
	claims[consts.ClaimIssuedAt] = issued.Unix()
	claims[consts.ClaimExpirationTime] = issued.Add(time.Minute).Unix()

	return signToken(t, alg, private, txnKeyID, claims, nil)
}
