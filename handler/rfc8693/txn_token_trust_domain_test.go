// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	. "authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal/consts"
)

func TestTxnTokenTrustDomains(t *testing.T) {
	for name, store := range txnIssueStores() {
		t.Run(name, func(t *testing.T) {
			t.Run("ShouldIssueForTheRequestedTrustDomain", func(t *testing.T) {
				f := newTxnTrustDomainFixture(t, store)

				for _, tc := range []struct {
					audience, issuer string
					lifetime         float64
				}{
					{txnTrustDomain, "https://tts-a.example", 300},
					{txnOtherTrustDomain, "https://tts-b.example", 60},
				} {
					f.audience = tc.audience

					response, err := f.exchange(t, f.hookExchange(t, nil))
					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

					claims := txnPayload(t, response)

					assert.Equal(t, tc.audience, claims[consts.ClaimAudience])
					assert.Equal(t, tc.issuer, claims[consts.ClaimIssuer])
					assert.Equal(t, tc.lifetime, claims[consts.ClaimExpirationTime].(float64)-claims[consts.ClaimIssuedAt].(float64))
				}
			})

			t.Run("ShouldRunOnlyTheFunctionsOfTheRequestedTrustDomain", func(t *testing.T) {
				f := newTxnTrustDomainFixture(t, store)

				var mapped, transcribed []string

				other := f.txnType.Domains[txnOtherTrustDomain]
				other.MapScopes = func(_ context.Context, _ oauth2.AccessRequester, trustDomain string, scopes []string) ([]string, error) {
					mapped = append(mapped, trustDomain)

					return scopes, nil
				}
				other.TranscribeClaims = func(_ context.Context, _ oauth2.AccessRequester, input *TxnTokenClaimsInput) error {
					transcribed = append(transcribed, input.TrustDomain)

					return nil
				}

				_, err := f.exchange(t, f.hookExchange(t, nil))
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				assert.Empty(t, mapped)
				assert.Empty(t, transcribed)

				f.audience = txnOtherTrustDomain

				_, err = f.exchange(t, f.hookExchange(t, nil))
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				assert.Equal(t, []string{txnOtherTrustDomain}, mapped)
				assert.Equal(t, []string{txnOtherTrustDomain}, transcribed)
			})

			t.Run("ShouldPassTheTrustDomainToStorage", func(t *testing.T) {
				f := newTxnTrustDomainFixture(t, store)
				f.scopes.scopes = []string{"trade.stocks"}
				f.audience = txnOtherTrustDomain

				_, err := f.exchange(t, txnExchange{subjectType: txnJWTType, subjectToken: f.customJWT(t, nil), scopes: []string{"trade.stocks"}})
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				require.Len(t, f.scopes.calls, 1)
				assert.Equal(t, txnOtherTrustDomain, f.scopes.calls[0].trustDomain)
			})

			t.Run("ShouldRefuseTheIssuerOfThisServerInTheRequestedTrustDomain", func(t *testing.T) {
				f := newTxnTrustDomainFixture(t, store)
				f.txnType.Domains[txnOtherTrustDomain].Issuer = f.cfg.Issuer

				_, err := f.exchange(t, f.hookExchange(t, nil))
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				f.audience = txnOtherTrustDomain

				_, err = f.exchange(t, f.hookExchange(t, nil))
				require.ErrorIs(t, err, oauth2.ErrServerError)
			})
		})
	}
}

func TestTxnTokenTrustDomainRequestRules(t *testing.T) {
	testCases := []struct {
		name     string
		domains  func(f *txnFixture) map[string]*TxnTokenTrustDomain
		audience []string
		method   string
		err      error
	}{
		{"ShouldPassTheOtherTrustDomain", nil, []string{txnOtherTrustDomain}, "", nil},
		{"ShouldRefuseTwoTrustDomains", nil, []string{txnTrustDomain, txnOtherTrustDomain}, "", oauth2.ErrInvalidTarget},
		{"ShouldRefuseAnUnknownTrustDomain", nil, []string{"domain-c.example"}, "", oauth2.ErrInvalidTarget},
		{"ShouldRefuseANilTrustDomain", func(f *txnFixture) map[string]*TxnTokenTrustDomain {
			return map[string]*TxnTokenTrustDomain{txnTrustDomain: f.domain, txnOtherTrustDomain: nil}
		}, []string{txnOtherTrustDomain}, "", oauth2.ErrInvalidTarget},
		{"ShouldRefuseNoTrustDomains", func(*txnFixture) map[string]*TxnTokenTrustDomain { return nil }, []string{txnTrustDomain}, "", oauth2.ErrServerError},
		{"ShouldApplyTheClientAuthenticationMethodsOfTheRequestedTrustDomain", nil, []string{txnTrustDomain}, consts.ClientAuthMethodClientSecretBasic, oauth2.ErrInvalidClient},
		{"ShouldNotApplyTheClientAuthenticationMethodsOfAnotherTrustDomain", nil, []string{txnOtherTrustDomain}, consts.ClientAuthMethodClientSecretBasic, nil},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := newTxnFixture(t)
			f.client.Audience = append(f.client.Audience, txnOtherTrustDomain)
			f.domain.ClientAuthenticationMethods = []string{consts.ClientAuthMethodPrivateKeyJWT}

			txnType := f.config.RFC8693TokenTypes[consts.TokenTypeRFC8693TxnToken].(*TxnTokenType)
			txnType.Domains[txnOtherTrustDomain] = &TxnTokenTrustDomain{}

			if tc.domains != nil {
				txnType.Domains = tc.domains(f)
			}

			request := f.request(txnRequest{audience: tc.audience})
			request.SetClientAuthenticationMethod(tc.method)

			err := f.handler.HandleTokenEndpointRequest(t.Context(), request)

			if tc.err == nil {
				assert.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				return
			}

			assert.ErrorIs(t, err, tc.err)
		})
	}
}

const txnOtherTrustDomain = "domain-b.example"

func newTxnTrustDomainFixture(t *testing.T, store txnIssueStore) *txnIssueFixture {
	t.Helper()

	f := newTxnIssueFixture(t, store)
	f.txnDomain.Issuer = "https://tts-a.example"
	f.txnType.Domains[txnOtherTrustDomain] = &TxnTokenTrustDomain{Issuer: "https://tts-b.example", Expiry: time.Minute}
	f.client.Audience = append(f.client.Audience, txnOtherTrustDomain)

	return f
}
