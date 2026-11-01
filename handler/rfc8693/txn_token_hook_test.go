// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	. "authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal/consts"
)

// §6: without a hook, the request parameters never reach the token.
func TestTxnTokenParametersDoNotReachTheTokenWithoutAHook(t *testing.T) {
	for name, store := range txnIssueStores() {
		t.Run(name, func(t *testing.T) {
			f := newTxnIssueFixture(t, store)

			response, err := f.exchange(t, f.hookExchange(t, txnHookParameters()))
			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

			raw := txnRawPayload(t, response)

			assert.NotContains(t, raw, "req-context-value")
			assert.NotContains(t, raw, "req-details-value")

			claims := txnPayload(t, response)

			assert.NotContains(t, claims, consts.ClaimRequestContext)
			assert.NotContains(t, claims, consts.ClaimTransactionContext)
		})
	}
}

func TestTxnTokenHookInput(t *testing.T) {
	for name, store := range txnIssueStores() {
		t.Run(name, func(t *testing.T) {
			t.Run("ShouldReceiveTheParsedParameters", func(t *testing.T) {
				f := newTxnIssueFixture(t, store)

				var seen *TxnTokenClaimsInput

				f.txnType.TranscribeClaims = func(_ context.Context, _ oauth2.AccessRequester, input *TxnTokenClaimsInput) error {
					seen = input

					return nil
				}

				_, err := f.exchange(t, f.hookExchange(t, txnHookParameters()))
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
				require.NotNil(t, seen)

				assert.Equal(t, map[string]any{"value": "req-context-value"}, seen.RequestContext)
				assert.Equal(t, map[string]any{"value": "req-details-value"}, seen.RequestDetails)
				assert.Equal(t, "alice", seen.Claims[consts.ClaimSubject])
				assert.Equal(t, txnTrustDomain, seen.Claims[consts.ClaimAudience])
				assert.Equal(t, "trade.stocks trade.bonds", seen.Claims[consts.ClaimScope])
				assert.NotEmpty(t, seen.SubjectClaims)
			})

			t.Run("ShouldBeCalledWhenBothParametersAreAbsent", func(t *testing.T) {
				f := newTxnIssueFixture(t, store)

				called := false

				f.txnType.TranscribeClaims = func(_ context.Context, _ oauth2.AccessRequester, input *TxnTokenClaimsInput) error {
					called = true

					assert.Nil(t, input.RequestContext)
					assert.Nil(t, input.RequestDetails)

					return nil
				}

				_, err := f.exchange(t, f.hookExchange(t, nil))
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				assert.True(t, called)
			})

			t.Run("ShouldReceiveTheClaimsOfTheSubjectToken", func(t *testing.T) {
				f := newTxnIssueFixture(t, store)
				f.scopes.scopes = []string{"trade.stocks"}

				var seen map[string]any

				f.txnType.TranscribeClaims = func(_ context.Context, _ oauth2.AccessRequester, input *TxnTokenClaimsInput) error {
					seen = input.SubjectClaims

					return nil
				}

				_, err := f.exchange(t, txnExchange{subjectType: consts.TokenTypeRFC8693UnsignedJSON, subjectToken: `{"sub":"alice","tenant":"acme"}`, scopes: []string{"trade.stocks"}})
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				assert.Equal(t, "acme", seen["tenant"])
			})

			t.Run("ShouldNotMutateTheSubjectTokenOfTheSession", func(t *testing.T) {
				f := newTxnIssueFixture(t, store)
				f.scopes.scopes = []string{"trade.stocks"}

				f.txnType.TranscribeClaims = func(_ context.Context, _ oauth2.AccessRequester, input *TxnTokenClaimsInput) error {
					input.SubjectClaims["tenant"] = "forged"
					input.SubjectClaims["nested"].(map[string]any)["name"] = "forged"

					return nil
				}

				session := newSpecSession("")

				_, err := f.exchange(t, txnExchange{subjectType: consts.TokenTypeRFC8693UnsignedJSON, subjectToken: `{"sub":"alice","tenant":"acme","nested":{"name":"original"}}`, scopes: []string{"trade.stocks"}, session: session})
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				assert.Equal(t, "acme", session.GetSubjectToken()["tenant"])
				assert.Equal(t, "original", session.GetSubjectToken()["nested"].(map[string]any)["name"])
			})
		})
	}
}

// §6: 'rctx' and 'tctx' are objects, set only by the hook, and omitted when empty.
func TestTxnTokenHookContextClaims(t *testing.T) {
	for name, store := range txnIssueStores() {
		t.Run(name, func(t *testing.T) {
			t.Run("ShouldSetFromTheParameters", func(t *testing.T) {
				f := newTxnIssueFixture(t, store)
				f.txnType.TranscribeClaims = txnHookFullCopy

				response, err := f.exchange(t, f.hookExchange(t, txnHookParameters()))
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				claims := txnPayload(t, response)

				assert.Equal(t, map[string]any{"value": "req-context-value"}, claims[consts.ClaimRequestContext])
				assert.Equal(t, map[string]any{"value": "req-details-value"}, claims[consts.ClaimTransactionContext])
			})

			t.Run("ShouldOmitWhenTheParametersAreAbsentOrEmpty", func(t *testing.T) {
				for _, parameters := range []url.Values{
					nil,
					{consts.FormParameterRequestContext: {"{}"}, consts.FormParameterRequestDetails: {"{}"}},
				} {
					f := newTxnIssueFixture(t, store)
					f.txnType.TranscribeClaims = txnHookFullCopy

					response, err := f.exchange(t, f.hookExchange(t, parameters))
					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

					claims := txnPayload(t, response)

					assert.NotContains(t, claims, consts.ClaimRequestContext)
					assert.NotContains(t, claims, consts.ClaimTransactionContext)
				}
			})

			t.Run("ShouldAcceptAnyValueEncodedAsAnObject", func(t *testing.T) {
				f := newTxnIssueFixture(t, store)

				f.txnType.TranscribeClaims = func(_ context.Context, _ oauth2.AccessRequester, input *TxnTokenClaimsInput) error {
					input.Claims[consts.ClaimRequestContext] = map[string]string{"value": "typed"}
					input.Claims[consts.ClaimTransactionContext] = struct {
						Value string `json:"value"`
					}{"typed"}

					return nil
				}

				response, err := f.exchange(t, f.hookExchange(t, nil))
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				claims := txnPayload(t, response)

				assert.Equal(t, map[string]any{"value": "typed"}, claims[consts.ClaimRequestContext])
				assert.Equal(t, map[string]any{"value": "typed"}, claims[consts.ClaimTransactionContext])
			})

			t.Run("ShouldOmitAnEmptyValueOfAnotherType", func(t *testing.T) {
				f := newTxnIssueFixture(t, store)

				f.txnType.TranscribeClaims = func(_ context.Context, _ oauth2.AccessRequester, input *TxnTokenClaimsInput) error {
					input.Claims[consts.ClaimRequestContext] = map[string]string{}
					input.Claims[consts.ClaimTransactionContext] = struct{}{}

					return nil
				}

				response, err := f.exchange(t, f.hookExchange(t, nil))
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				claims := txnPayload(t, response)

				assert.NotContains(t, claims, consts.ClaimRequestContext)
				assert.NotContains(t, claims, consts.ClaimTransactionContext)
			})
		})
	}
}

func TestTxnTokenHookProtectedClaims(t *testing.T) {
	for name, store := range txnIssueStores() {
		t.Run(name, func(t *testing.T) {
			t.Run("ShouldDiscardChanges", func(t *testing.T) {
				f := newTxnIssueFixture(t, store)
				f.txnType.Issuer = "https://tts.example"
				f.client.allowActor = true

				var draft map[string]any

				f.txnType.TranscribeClaims = func(_ context.Context, _ oauth2.AccessRequester, input *TxnTokenClaimsInput) error {
					draft = map[string]any{}

					for name, value := range input.Claims {
						draft[name] = value
					}

					for _, name := range txnHookProtectedClaims() {
						input.Claims[name] = "forged"
					}

					return nil
				}

				exchange := f.hookExchange(t, nil)
				exchange.actorToken = f.mint(t, txnMint{subject: "bob"})

				response, err := f.exchange(t, exchange)
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				claims := txnPayload(t, response)

				assert.Equal(t, draft[consts.ClaimTransaction], claims[consts.ClaimTransaction])
				assert.Equal(t, txnTrustDomain, claims[consts.ClaimAudience])
				assert.Equal(t, draft[consts.ClaimIssuedAt], toUnix(t, claims[consts.ClaimIssuedAt]))
				assert.Equal(t, draft[consts.ClaimExpirationTime], toUnix(t, claims[consts.ClaimExpirationTime]))
				assert.Equal(t, txnClientID, claims[consts.ClaimRequestingWorkload])
				assert.Equal(t, "https://tts.example", claims[consts.ClaimIssuer])
				assert.Equal(t, map[string]any{consts.ClaimSubject: "bob", consts.ClaimClientIdentifier: txnClientID}, claims[consts.ClaimActor])
			})

			t.Run("ShouldRestoreDeletedClaims", func(t *testing.T) {
				f := newTxnIssueFixture(t, store)
				f.txnType.Issuer = "https://tts.example"
				f.client.allowActor = true

				f.txnType.TranscribeClaims = func(_ context.Context, _ oauth2.AccessRequester, input *TxnTokenClaimsInput) error {
					for _, name := range txnHookProtectedClaims() {
						delete(input.Claims, name)
					}

					return nil
				}

				exchange := f.hookExchange(t, nil)
				exchange.actorToken = f.mint(t, txnMint{subject: "bob"})

				response, err := f.exchange(t, exchange)
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				claims := txnPayload(t, response)

				for _, name := range txnHookProtectedClaims() {
					assert.Contains(t, claims, name)
				}
			})

			t.Run("ShouldRemoveAnIssuerOrActorThatWasNotDrafted", func(t *testing.T) {
				f := newTxnIssueFixture(t, store)

				f.txnType.TranscribeClaims = func(_ context.Context, _ oauth2.AccessRequester, input *TxnTokenClaimsInput) error {
					input.Claims[consts.ClaimIssuer] = "https://forged.example"
					input.Claims[consts.ClaimActor] = map[string]any{consts.ClaimSubject: "mallory"}

					return nil
				}

				response, err := f.exchange(t, f.hookExchange(t, nil))
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				claims := txnPayload(t, response)

				assert.NotContains(t, claims, consts.ClaimIssuer)
				assert.NotContains(t, claims, consts.ClaimActor)
			})

			t.Run("ShouldRemoveAConfirmationClaim", func(t *testing.T) {
				f := newTxnIssueFixture(t, store)

				f.txnType.TranscribeClaims = func(_ context.Context, _ oauth2.AccessRequester, input *TxnTokenClaimsInput) error {
					input.Claims[consts.ClaimConfirmation] = map[string]any{consts.ClaimConfirmationJWKThumbprint: "forged"}

					return nil
				}

				response, err := f.exchange(t, f.hookExchange(t, nil))
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				assert.NotContains(t, txnPayload(t, response), consts.ClaimConfirmation)
			})

			t.Run("ShouldDiscardAnActorChangedInPlace", func(t *testing.T) {
				f := newTxnIssueFixture(t, store)
				f.client.allowActor = true

				f.txnType.TranscribeClaims = func(_ context.Context, _ oauth2.AccessRequester, input *TxnTokenClaimsInput) error {
					act := input.Claims[consts.ClaimActor].(map[string]any)
					act[consts.ClaimSubject] = "mallory"
					act[consts.ClaimActor].(map[string]any)[consts.ClaimSubject] = "mallory"

					return nil
				}

				exchange := f.hookExchange(t, nil)
				exchange.subjectToken = f.mint(t, txnMint{scopes: []string{"trade.stocks", "trade.bonds"}, act: map[string]any{consts.ClaimSubject: "carol"}})
				exchange.actorToken = f.mint(t, txnMint{subject: "bob"})

				response, err := f.exchange(t, exchange)
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				assert.Equal(t, map[string]any{consts.ClaimSubject: "bob", consts.ClaimClientIdentifier: txnClientID, consts.ClaimActor: map[string]any{consts.ClaimSubject: "carol"}}, txnPayload(t, response)[consts.ClaimActor])
			})

			t.Run("ShouldRestoreIntoAReplacedClaimsMap", func(t *testing.T) {
				f := newTxnIssueFixture(t, store)

				f.txnType.TranscribeClaims = func(_ context.Context, _ oauth2.AccessRequester, input *TxnTokenClaimsInput) error {
					input.Claims = map[string]any{
						consts.ClaimSubject: "service",
						consts.ClaimScope:   "trade.stocks",
						"tenant":            "acme",
						consts.ClaimIssuer:  "https://forged.example",
					}

					return nil
				}

				response, err := f.exchange(t, f.hookExchange(t, nil))
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				claims := txnPayload(t, response)

				assert.Equal(t, "service", claims[consts.ClaimSubject])
				assert.Equal(t, "acme", claims["tenant"])
				assert.Equal(t, txnTrustDomain, claims[consts.ClaimAudience])
				assert.NotContains(t, claims, consts.ClaimIssuer)
				assert.NotEmpty(t, claims[consts.ClaimTransaction])
			})
		})
	}
}

func TestTxnTokenHookAllowedChanges(t *testing.T) {
	for name, store := range txnIssueStores() {
		t.Run(name, func(t *testing.T) {
			f := newTxnIssueFixture(t, store)

			f.txnType.TranscribeClaims = func(_ context.Context, _ oauth2.AccessRequester, input *TxnTokenClaimsInput) error {
				input.Claims[consts.ClaimSubject] = "service-account"
				input.Claims[consts.ClaimScope] = "trade.bonds"
				input.Claims["tenant"] = "acme"

				return nil
			}

			response, err := f.exchange(t, f.hookExchange(t, nil))
			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

			claims := txnPayload(t, response)

			assert.Equal(t, "service-account", claims[consts.ClaimSubject])
			assert.Equal(t, "trade.bonds", claims[consts.ClaimScope])
			assert.Equal(t, "acme", claims["tenant"])
			assert.Equal(t, "trade.bonds", response.GetExtra(consts.AccessResponseScope))
		})
	}
}

func TestTxnTokenHookScopeIsNormalised(t *testing.T) {
	testCases := []struct {
		name  string
		scope string
		want  string
	}{
		{"ShouldCollapseDuplicates", "trade.bonds trade.bonds", "trade.bonds"},
		{"ShouldIgnoreRepeatedSpaces", "  trade.bonds   trade.stocks ", "trade.bonds trade.stocks"},
		{"ShouldKeepTheFullSet", "trade.stocks trade.bonds", "trade.stocks trade.bonds"},
	}

	for name, store := range txnIssueStores() {
		t.Run(name, func(t *testing.T) {
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					f := newTxnIssueFixture(t, store)

					f.txnType.TranscribeClaims = func(_ context.Context, _ oauth2.AccessRequester, input *TxnTokenClaimsInput) error {
						input.Claims[consts.ClaimScope] = tc.scope

						return nil
					}

					response, err := f.exchange(t, f.hookExchange(t, nil))
					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

					assert.Equal(t, tc.want, txnPayload(t, response)[consts.ClaimScope])
					assert.Equal(t, tc.want, response.GetExtra(consts.AccessResponseScope))
				})
			}
		})
	}
}

func TestTxnTokenHookMisuseIsServerError(t *testing.T) {
	testCases := []struct {
		name string
		hook func(claims map[string]any)
	}{
		{"ShouldRefuseADeletedScope", func(claims map[string]any) { delete(claims, consts.ClaimScope) }},
		{"ShouldRefuseAWidenedScope", func(claims map[string]any) { claims[consts.ClaimScope] = "trade.stocks trade.options" }},
		{"ShouldRefuseAnEmptyScope", func(claims map[string]any) { claims[consts.ClaimScope] = "" }},
		{"ShouldRefuseABlankScope", func(claims map[string]any) { claims[consts.ClaimScope] = "   " }},
		{"ShouldRefuseAnArrayScope", func(claims map[string]any) { claims[consts.ClaimScope] = []string{"trade.stocks"} }},
		{"ShouldRefuseANumberScope", func(claims map[string]any) { claims[consts.ClaimScope] = 1 }},
		{"ShouldRefuseATabDelimitedScope", func(claims map[string]any) { claims[consts.ClaimScope] = "trade.stocks\ttrade.bonds" }},
		{"ShouldRefuseAnEmptySubject", func(claims map[string]any) { claims[consts.ClaimSubject] = "" }},
		{"ShouldRefuseADeletedSubject", func(claims map[string]any) { delete(claims, consts.ClaimSubject) }},
		{"ShouldRefuseANumberSubject", func(claims map[string]any) { claims[consts.ClaimSubject] = 1 }},
		{"ShouldRefuseAStringRequestContext", func(claims map[string]any) { claims[consts.ClaimRequestContext] = "value" }},
		{"ShouldRefuseAnArrayRequestContext", func(claims map[string]any) { claims[consts.ClaimRequestContext] = []any{"value"} }},
		{"ShouldRefuseANullRequestContext", func(claims map[string]any) { claims[consts.ClaimRequestContext] = nil }},
		{"ShouldRefuseAStringTransactionContext", func(claims map[string]any) { claims[consts.ClaimTransactionContext] = "value" }},
		{"ShouldRefuseANumberTransactionContext", func(claims map[string]any) { claims[consts.ClaimTransactionContext] = 1 }},
		{"ShouldRefuseAnUnencodableTransactionContext", func(claims map[string]any) { claims[consts.ClaimTransactionContext] = make(chan int) }},
		{"ShouldRefuseAnUnencodableClaim", func(claims map[string]any) { claims["other"] = make(chan int) }},
	}

	for name, store := range txnIssueStores() {
		t.Run(name, func(t *testing.T) {
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					f := newTxnIssueFixture(t, store)

					f.txnType.TranscribeClaims = func(_ context.Context, _ oauth2.AccessRequester, input *TxnTokenClaimsInput) error {
						tc.hook(input.Claims)

						return nil
					}

					response, err := f.exchange(t, f.hookExchange(t, nil))

					require.ErrorIs(t, err, oauth2.ErrServerError)
					assert.Nil(t, response)
				})
			}

			t.Run("ShouldRefuseAScopeGrantedButNotRequested", func(t *testing.T) {
				f := newTxnIssueFixture(t, store)

				f.txnType.TranscribeClaims = func(_ context.Context, _ oauth2.AccessRequester, input *TxnTokenClaimsInput) error {
					input.Claims[consts.ClaimScope] = "trade.bonds"

					return nil
				}

				exchange := f.hookExchange(t, nil)
				exchange.scopes, exchange.granted = []string{"trade.stocks"}, []string{"trade.bonds"}

				_, err := f.exchange(t, exchange)

				require.ErrorIs(t, err, oauth2.ErrServerError)
			})

			t.Run("ShouldRefuseAScopeGrantedByTheHook", func(t *testing.T) {
				f := newTxnIssueFixture(t, store)

				f.txnType.TranscribeClaims = func(_ context.Context, request oauth2.AccessRequester, input *TxnTokenClaimsInput) error {
					request.AppendRequestedScope("trade.options")
					request.GrantScope("trade.options")

					input.Claims[consts.ClaimScope] = "trade.options"

					return nil
				}

				_, err := f.exchange(t, f.hookExchange(t, nil))

				require.ErrorIs(t, err, oauth2.ErrServerError)
			})

			t.Run("ShouldRefuseNilClaims", func(t *testing.T) {
				f := newTxnIssueFixture(t, store)

				f.txnType.TranscribeClaims = func(_ context.Context, _ oauth2.AccessRequester, input *TxnTokenClaimsInput) error {
					input.Claims = nil

					return nil
				}

				_, err := f.exchange(t, f.hookExchange(t, nil))

				require.ErrorIs(t, err, oauth2.ErrServerError)
			})
		})
	}
}

func TestTxnTokenHookErrorDeniesTheRequest(t *testing.T) {
	failure := errors.New("the policy engine is down")

	testCases := []struct {
		name string
		err  error
	}{
		{"ShouldReturnAProtocolError", oauth2.ErrInvalidRequest.WithHint("The tenant is not permitted.")},
		{"ShouldReturnAnotherError", failure},
	}

	for name, store := range txnIssueStores() {
		t.Run(name, func(t *testing.T) {
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					f := newTxnIssueFixture(t, store)

					f.txnType.TranscribeClaims = func(context.Context, oauth2.AccessRequester, *TxnTokenClaimsInput) error {
						return tc.err
					}

					response, err := f.exchange(t, f.hookExchange(t, nil))

					require.ErrorIs(t, err, tc.err)
					assert.Nil(t, response)
				})
			}
		})
	}
}

func TestTxnTokenHookPanicIsNotRecovered(t *testing.T) {
	for name, store := range txnIssueStores() {
		t.Run(name, func(t *testing.T) {
			f := newTxnIssueFixture(t, store)

			f.txnType.TranscribeClaims = func(context.Context, oauth2.AccessRequester, *TxnTokenClaimsInput) error {
				panic("hook failure")
			}

			exchange := f.hookExchange(t, nil)

			assert.PanicsWithValue(t, "hook failure", func() {
				_, _ = f.exchange(t, exchange)
			})
		})
	}
}

func TestTxnTokenParametersKeepNumberPrecision(t *testing.T) {
	for name, store := range txnIssueStores() {
		t.Run(name, func(t *testing.T) {
			f := newTxnIssueFixture(t, store)
			f.txnType.TranscribeClaims = txnHookFullCopy

			response, err := f.exchange(t, f.hookExchange(t, url.Values{
				consts.FormParameterRequestContext: {`{"precise":0.1234567890123456789012345}`},
				consts.FormParameterRequestDetails: {`{"large":9007199254740993,"nested":{"items":[18446744073709551616]}}`},
			}))
			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

			decoder := json.NewDecoder(strings.NewReader(txnRawPayload(t, response)))
			decoder.UseNumber()

			var claims map[string]any

			require.NoError(t, decoder.Decode(&claims))

			rctx, tctx := claims[consts.ClaimRequestContext].(map[string]any), claims[consts.ClaimTransactionContext].(map[string]any)

			assert.Equal(t, json.Number("0.1234567890123456789012345"), rctx["precise"])
			assert.Equal(t, json.Number("9007199254740993"), tctx["large"])
			assert.Equal(t, []any{json.Number("18446744073709551616")}, tctx["nested"].(map[string]any)["items"])
		})
	}
}

func TestTxnTokenHookClaimsKeepTheirTypes(t *testing.T) {
	for name, store := range txnIssueStores() {
		t.Run(name, func(t *testing.T) {
			f := newTxnIssueFixture(t, store)
			f.scopes.scopes = []string{"trade.stocks"}

			f.txnType.TranscribeClaims = func(_ context.Context, _ oauth2.AccessRequester, input *TxnTokenClaimsInput) error {
				input.Claims["account"] = input.SubjectClaims["account"]
				input.Claims["typed"] = struct {
					Value json.Number `json:"value"`
				}{"9007199254740993"}
				input.Claims[consts.ClaimNotBefore] = int64(1700000000)
				input.Claims["enabled"] = true
				input.Claims["items"] = []string{"a", "b"}
				input.Claims["empty"] = nil

				return nil
			}

			response, err := f.exchange(t, txnExchange{subjectType: consts.TokenTypeRFC8693UnsignedJSON, subjectToken: `{"sub":"alice","account":9007199254740993}`, scopes: []string{"trade.stocks"}})
			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

			decoder := json.NewDecoder(strings.NewReader(txnRawPayload(t, response)))
			decoder.UseNumber()

			var claims map[string]any

			require.NoError(t, decoder.Decode(&claims))

			assert.Equal(t, json.Number("9007199254740993"), claims["account"])
			assert.Equal(t, map[string]any{"value": json.Number("9007199254740993")}, claims["typed"])
			assert.Equal(t, json.Number("1700000000"), claims[consts.ClaimNotBefore])
			assert.Equal(t, true, claims["enabled"])
			assert.Equal(t, []any{"a", "b"}, claims["items"])
			assert.Contains(t, claims, "empty")
			assert.Nil(t, claims["empty"])
		})
	}
}

func TestTxnTokenParametersRefuseTrailingData(t *testing.T) {
	values := []string{`{} x`, `{} {}`, `{}]`, `{"a":1}{"b":2}`}

	for name, store := range txnIssueStores() {
		t.Run(name, func(t *testing.T) {
			for _, parameter := range []string{consts.FormParameterRequestContext, consts.FormParameterRequestDetails} {
				for _, value := range values {
					t.Run(parameter+"/"+value, func(t *testing.T) {
						f := newTxnIssueFixture(t, store)

						_, err := f.exchange(t, f.hookExchange(t, url.Values{parameter: {value}}))

						require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
						assert.Contains(t, oauth2.ErrorToRFC6749Error(err).HintField, parameter)
					})
				}
			}
		})
	}
}

func txnHookFullCopy(_ context.Context, _ oauth2.AccessRequester, input *TxnTokenClaimsInput) error {
	input.Claims[consts.ClaimRequestContext], input.Claims[consts.ClaimTransactionContext] = input.RequestContext, input.RequestDetails

	return nil
}

func txnHookParameters() url.Values {
	return url.Values{
		consts.FormParameterRequestContext: {`{"value":"req-context-value"}`},
		consts.FormParameterRequestDetails: {`{"value":"req-details-value"}`},
	}
}

func txnHookProtectedClaims() []string {
	return []string{
		consts.ClaimTransaction,
		consts.ClaimAudience,
		consts.ClaimIssuedAt,
		consts.ClaimExpirationTime,
		consts.ClaimRequestingWorkload,
		consts.ClaimIssuer,
		consts.ClaimActor,
	}
}

func (f *txnIssueFixture) hookExchange(t *testing.T, form url.Values) txnExchange {
	t.Helper()

	scopes := []string{"trade.stocks", "trade.bonds"}

	return txnExchange{subjectToken: f.mint(t, txnMint{scopes: scopes}), scopes: scopes, form: form}
}

func txnRawPayload(t *testing.T, response *oauth2.AccessResponse) string {
	t.Helper()

	parts := strings.Split(response.GetAccessToken(), ".")
	require.Len(t, parts, 3)

	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)

	return string(raw)
}
