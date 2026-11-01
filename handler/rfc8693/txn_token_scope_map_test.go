// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2"
	. "authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
)

const txnInternalScope = "orders.write"

func txnMapScopes(result []string, err error) func(context.Context, oauth2.AccessRequester, []string) ([]string, error) {
	return func(context.Context, oauth2.AccessRequester, []string) ([]string, error) { return result, err }
}

func TestTxnTokenMapScopes(t *testing.T) {
	for name, store := range txnIssueStores() {
		t.Run(name, func(t *testing.T) {
			t.Run("ShouldIssueTheMappedScopes", func(t *testing.T) {
				f := newTxnIssueFixture(t, store)
				f.txnType.MapScopes = txnMapScopes([]string{txnInternalScope, "orders.read"}, nil)

				response, err := f.exchange(t, f.hookExchange(t, nil))
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				assert.Equal(t, txnInternalScope+" orders.read", txnPayload(t, response)[consts.ClaimScope])
				assert.Equal(t, txnInternalScope+" orders.read", response.GetExtra(consts.AccessResponseScope))
			})

			t.Run("ShouldLeaveTheScopesWithoutAFunction", func(t *testing.T) {
				f := newTxnIssueFixture(t, store)

				response, err := f.exchange(t, f.hookExchange(t, nil))
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				assert.Equal(t, "trade.stocks trade.bonds", txnPayload(t, response)[consts.ClaimScope])
			})

			t.Run("ShouldReceiveOnlyTheScopesThatPassedTheCeiling", func(t *testing.T) {
				f := newTxnIssueFixture(t, store)

				var received []string

				f.txnType.MapScopes = func(_ context.Context, request oauth2.AccessRequester, scopes []string) ([]string, error) {
					received = scopes

					assert.Equal(t, txnClientID, request.GetClient().GetID())

					return []string{txnInternalScope}, nil
				}

				_, err := f.exchange(t, txnExchange{subjectToken: f.mint(t, txnMint{scopes: []string{"trade.stocks"}}), scopes: []string{"trade.stocks"}, granted: []string{"trade.bonds"}})
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				assert.Equal(t, []string{"trade.stocks"}, received)
			})

			t.Run("ShouldNotRunWhenTheCeilingRefuses", func(t *testing.T) {
				f := newTxnIssueFixture(t, store)

				f.txnType.MapScopes = func(context.Context, oauth2.AccessRequester, []string) ([]string, error) {
					t.Error("MapScopes ran for a refused request")

					return nil, nil
				}

				_, err := f.exchange(t, txnExchange{subjectToken: f.mint(t, txnMint{scopes: []string{"trade.stocks"}}), scopes: []string{"trade.bonds"}})

				require.ErrorIs(t, err, oauth2.ErrInvalidScope)
			})

			t.Run("ShouldDropARepeatedScope", func(t *testing.T) {
				f := newTxnIssueFixture(t, store)
				f.txnType.MapScopes = txnMapScopes([]string{txnInternalScope, txnInternalScope}, nil)

				response, err := f.exchange(t, f.hookExchange(t, nil))
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				assert.Equal(t, txnInternalScope, txnPayload(t, response)[consts.ClaimScope])
			})

			t.Run("ShouldRefuseAnEmptyResult", func(t *testing.T) {
				for _, result := range [][]string{nil, {}} {
					f := newTxnIssueFixture(t, store)
					f.txnType.MapScopes = txnMapScopes(result, nil)

					response, err := f.exchange(t, f.hookExchange(t, nil))

					require.ErrorIs(t, err, oauth2.ErrInvalidScope)
					assert.Nil(t, response)
				}
			})

			t.Run("ShouldReturnTheError", func(t *testing.T) {
				failure := errors.New("the mapping service is down")

				f := newTxnIssueFixture(t, store)
				f.txnType.MapScopes = txnMapScopes([]string{txnInternalScope}, failure)

				response, err := f.exchange(t, f.hookExchange(t, nil))

				require.ErrorIs(t, err, failure)
				assert.Nil(t, response)
			})

			t.Run("ShouldRefuseAnInvalidScopeToken", func(t *testing.T) {
				for _, scope := range []string{"", "orders write", "orders\twrite", `orders"write`, `orders\write`, "orders.wríte"} {
					f := newTxnIssueFixture(t, store)
					f.txnType.MapScopes = txnMapScopes([]string{scope}, nil)

					response, err := f.exchange(t, f.hookExchange(t, nil))

					require.ErrorIs(t, err, oauth2.ErrServerError, scope)
					assert.Nil(t, response)
				}
			})
		})
	}
}

func TestTxnTokenMapScopesCannotChangeTheInput(t *testing.T) {
	f := newTxnIssueFixture(t, storage.NewExampleStore())

	f.txnType.MapScopes = func(_ context.Context, _ oauth2.AccessRequester, scopes []string) ([]string, error) {
		scopes[0] = "tampered"

		return []string{txnInternalScope}, nil
	}

	f.txnType.TranscribeClaims = func(_ context.Context, request oauth2.AccessRequester, _ *TxnTokenClaimsInput) error {
		assert.NotContains(t, request.GetGrantedScopes(), "tampered")
		assert.NotContains(t, request.GetRequestedScopes(), "tampered")

		return nil
	}

	_, err := f.exchange(t, f.hookExchange(t, nil))
	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
}

// The hook keeps its rule against widening, measured against the mapped scopes.
func TestTxnTokenHookNarrowsTheMappedScopes(t *testing.T) {
	testCases := []struct {
		name    string
		scope   string
		want    string
		refused bool
	}{
		{name: "ShouldSeeAndKeepTheMappedScopes", scope: txnInternalScope + " orders.read", want: txnInternalScope + " orders.read"},
		{name: "ShouldNarrowTheMappedScopes", scope: "orders.read", want: "orders.read"},
		{name: "ShouldRefuseRestoringTheExternalScope", scope: "trade.stocks", refused: true},
		{name: "ShouldRefuseAnUnmappedScope", scope: "orders.admin", refused: true},
	}

	for name, store := range txnIssueStores() {
		t.Run(name, func(t *testing.T) {
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					f := newTxnIssueFixture(t, store)
					f.txnType.MapScopes = txnMapScopes([]string{txnInternalScope, "orders.read"}, nil)
					f.txnType.TranscribeClaims = func(_ context.Context, _ oauth2.AccessRequester, input *TxnTokenClaimsInput) error {
						assert.Equal(t, txnInternalScope+" orders.read", input.Claims[consts.ClaimScope])

						input.Claims[consts.ClaimScope] = tc.scope

						return nil
					}

					response, err := f.exchange(t, f.hookExchange(t, nil))

					if tc.refused {
						require.ErrorIs(t, err, oauth2.ErrServerError)

						return
					}

					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
					assert.Equal(t, tc.want, txnPayload(t, response)[consts.ClaimScope])
				})
			}
		})
	}
}

// A refused mapping issues no token, so the assertion can be presented again.
func TestTxnTokenMapScopesFailureKeepsTheJTI(t *testing.T) {
	for name, store := range txnJTIStores() {
		t.Run(name, func(t *testing.T) {
			f := newTxnIssueFixture(t, storage.NewExampleStore())
			f.scopes.scopes = []string{"trade.stocks"}
			f.cfg.RFC8693TokenTypes[consts.TokenTypeRFC8693SelfSigned].(*SelfSignedTokenType).ValidateJTI = true
			f.txn.JTIStorage = store
			f.txnType.MapScopes = txnMapScopes(nil, errors.New("the mapping service is down"))

			claims := selfSignedClaims()
			claims[consts.ClaimJWTID] = uuid.New().String()

			e := txnExchange{subjectType: consts.TokenTypeRFC8693SelfSigned, subjectToken: signToken(t, jose.ES256, f.workloadKey, txnKeyID, claims, nil), scopes: []string{"trade.stocks"}}

			_, err := f.exchange(t, e)
			require.Error(t, err)

			f.txnType.MapScopes = nil

			_, err = f.exchange(t, e)
			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
		})
	}
}
