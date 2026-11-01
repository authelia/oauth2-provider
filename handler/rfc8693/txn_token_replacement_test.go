// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693_test

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2"
	. "authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/handler/txntoken"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

const txnSecondWorkload = "txn-client-2"

func (f *txnIssueFixture) enableReplacement() {
	f.client.replacement = true
	f.txnType.Replacement = &TxnTokenReplacement{KeyFunc: func(*jwt.Token) (any, error) { return &key.PublicKey, nil }}
}

func (f *txnIssueFixture) issueForReplacement(t *testing.T, form url.Values) string {
	t.Helper()

	response, err := f.exchange(t, f.hookExchange(t, form))
	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

	return response.GetAccessToken()
}

func txnReplacementExchange(token string, scopes ...string) txnExchange {
	if len(scopes) == 0 {
		scopes = []string{"trade.stocks", "trade.bonds"}
	}

	return txnExchange{subjectType: consts.TokenTypeRFC8693TxnToken, subjectToken: token, scopes: scopes}
}

// §13.15: the 'txn', 'sub' and 'aud' are unchanged and the Call Chain of requesting workloads is maintained.
func TestTxnTokenReplacementClaims(t *testing.T) {
	for name, store := range txnIssueStores() {
		t.Run(name, func(t *testing.T) {
			f := newTxnIssueFixture(t, store)
			f.enableReplacement()
			f.txnType.TranscribeClaims = func(_ context.Context, _ oauth2.AccessRequester, input *TxnTokenClaimsInput) error {
				if _, replacing := input.SubjectClaims[consts.ClaimTransaction]; !replacing {
					input.Claims["department"] = "sales"
					input.Claims[consts.ClaimRequestContext] = input.RequestContext
					input.Claims[consts.ClaimTransactionContext] = input.RequestDetails
				}

				return nil
			}

			first := f.issueForReplacement(t, url.Values{
				consts.FormParameterRequestContext: {`{"req_ip":"192.0.2.1"}`},
				consts.FormParameterRequestDetails: {`{"quantity":9007199254740993,"items":["a"]}`},
			})
			firstClaims := txnPayload(t, &oauth2.AccessResponse{AccessToken: first})

			f.client.ID = txnSecondWorkload

			response, err := f.exchange(t, txnReplacementExchange(first))
			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

			claims := txnPayload(t, response)

			for _, claim := range []string{consts.ClaimTransaction, consts.ClaimSubject, consts.ClaimAudience, consts.ClaimRequestContext, consts.ClaimTransactionContext, "department"} {
				assert.Equal(t, firstClaims[claim], claims[claim], claim)
			}

			assert.Equal(t, txnSecondWorkload, claims[consts.ClaimRequestingWorkload])
			assert.Equal(t, []any{txnClientID}, claims[consts.ClaimRequestingWorkloadChain])
			assert.Contains(t, txnRawPayload(t, response), `"quantity":9007199254740993`)
			assert.Equal(t, oauth2.RFC8693NAToken, response.GetTokenType())
			assert.Equal(t, consts.TokenTypeRFC8693TxnToken, response.GetExtra(consts.FormParameterIssuedTokenType))
			assert.LessOrEqual(t, claims[consts.ClaimExpirationTime], firstClaims[consts.ClaimExpirationTime])

			f.client.ID = "txn-client-3"

			response, err = f.exchange(t, txnReplacementExchange(response.GetAccessToken()))
			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

			claims = txnPayload(t, response)

			assert.Equal(t, "txn-client-3", claims[consts.ClaimRequestingWorkload])
			assert.Equal(t, []any{txnClientID, txnSecondWorkload}, claims[consts.ClaimRequestingWorkloadChain])
			assert.Equal(t, firstClaims[consts.ClaimTransaction], claims[consts.ClaimTransaction])
		})
	}
}

func TestTxnTokenReplacementIsOptIn(t *testing.T) {
	testCases := []struct {
		name string
		arm  func(f *txnIssueFixture)
	}{
		{"ShouldRefuseWithoutTheSetting", func(f *txnIssueFixture) { f.txnType.Replacement = nil }},
		{"ShouldRefuseWithoutTheClientOptIn", func(f *txnIssueFixture) { f.client.replacement = false }},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := newTxnIssueFixture(t, storage.NewExampleStore())
			f.enableReplacement()

			first := f.issueForReplacement(t, nil)

			tc.arm(f)

			_, err := f.exchange(t, txnReplacementExchange(first))

			require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
			assert.Contains(t, oauth2.ErrorToRFC6749Error(err).HintField, consts.FormParameterSubjectTokenType)
		})
	}

	t.Run("ShouldStillNotAcceptItForAnotherRequestedType", func(t *testing.T) {
		f := newTxnIssueFixture(t, storage.NewExampleStore())
		f.enableReplacement()

		first := f.issueForReplacement(t, nil)

		e := txnReplacementExchange(first)
		e.requested = consts.TokenTypeRFC8693AccessToken

		_, err := f.exchange(t, e)

		require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
	})

	t.Run("ShouldRequireAKeyFunction", func(t *testing.T) {
		f := newTxnIssueFixture(t, storage.NewExampleStore())
		f.enableReplacement()

		first := f.issueForReplacement(t, nil)

		f.txnType.Replacement.KeyFunc = nil

		_, err := f.exchange(t, txnReplacementExchange(first))

		require.ErrorIs(t, err, oauth2.ErrServerError)
	})
}

// §13.15: asserted values must not expand the scope of permitted actions.
func TestTxnTokenReplacementScope(t *testing.T) {
	for name, store := range txnIssueStores() {
		t.Run(name, func(t *testing.T) {
			t.Run("ShouldNarrow", func(t *testing.T) {
				f := newTxnIssueFixture(t, store)
				f.enableReplacement()

				response, err := f.exchange(t, txnReplacementExchange(f.issueForReplacement(t, nil), "trade.bonds"))
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				assert.Equal(t, "trade.bonds", txnPayload(t, response)[consts.ClaimScope])
			})

			t.Run("ShouldRefuseWidening", func(t *testing.T) {
				f := newTxnIssueFixture(t, store)
				f.enableReplacement()

				first, err := f.exchange(t, txnExchange{subjectToken: f.mint(t, txnMint{scopes: []string{"trade.stocks"}}), scopes: []string{"trade.stocks"}})
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				_, err = f.exchange(t, txnReplacementExchange(first.GetAccessToken(), "trade.bonds"))

				require.ErrorIs(t, err, oauth2.ErrInvalidScope)
			})

			t.Run("ShouldNotMapAScopeAgain", func(t *testing.T) {
				f := newTxnIssueFixture(t, store)
				f.enableReplacement()

				first := f.issueForReplacement(t, nil)

				f.txnType.MapScopes = func(context.Context, oauth2.AccessRequester, []string) ([]string, error) {
					return nil, errors.New("mapped a replacement")
				}

				_, err := f.exchange(t, txnReplacementExchange(first))

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
			})
		})
	}
}

func TestTxnTokenReplacementRefusesAnInvalidToken(t *testing.T) {
	claims := func(mutate func(map[string]any)) map[string]any {
		now := time.Now()

		value := map[string]any{
			consts.ClaimIssuedAt:           now.Unix(),
			consts.ClaimExpirationTime:     now.Add(time.Minute).Unix(),
			consts.ClaimAudience:           txnTrustDomain,
			consts.ClaimTransaction:        uuid.New().String(),
			consts.ClaimSubject:            "alice",
			consts.ClaimScope:              "trade.stocks",
			consts.ClaimRequestingWorkload: txnClientID,
		}

		if mutate != nil {
			mutate(value)
		}

		return value
	}

	txnTyp := map[string]any{consts.JSONWebTokenHeaderType: consts.JSONWebTokenTypeTxnToken}

	testCases := []struct {
		name    string
		claims  map[string]any
		headers map[string]any
		issuer  string
		chain   int
		ok      bool
	}{
		{name: "ShouldAcceptAValidToken", claims: claims(nil), headers: txnTyp, ok: true},
		{name: "ShouldRefuseExpired", claims: claims(func(c map[string]any) { c[consts.ClaimExpirationTime] = time.Now().Add(-time.Minute).Unix() }), headers: txnTyp},
		{name: "ShouldRefuseAnotherTrustDomain", claims: claims(func(c map[string]any) { c[consts.ClaimAudience] = "other.example" }), headers: txnTyp},
		{name: "ShouldRefuseAnotherType", claims: claims(nil), headers: map[string]any{consts.JSONWebTokenHeaderType: "JWT"}},
		{name: "ShouldRefuseMissingTransaction", claims: claims(func(c map[string]any) { delete(c, consts.ClaimTransaction) }), headers: txnTyp},
		{name: "ShouldRefuseMissingSubject", claims: claims(func(c map[string]any) { delete(c, consts.ClaimSubject) }), headers: txnTyp},
		{name: "ShouldRefuseAConfirmation", claims: claims(func(c map[string]any) { c[consts.ClaimConfirmation] = map[string]any{"jkt": "x"} }), headers: txnTyp},
		{name: "ShouldRefuseAMalformedChain", claims: claims(func(c map[string]any) { c[consts.ClaimRequestingWorkloadChain] = "a" }), headers: txnTyp},
		{name: "ShouldRefuseAChainWithAnEmptyWorkload", claims: claims(func(c map[string]any) { c[consts.ClaimRequestingWorkloadChain] = []any{""} }), headers: txnTyp},
		{name: "ShouldRefuseAnotherIssuer", claims: claims(func(c map[string]any) { c[consts.ClaimIssuer] = "https://other.example" }), headers: txnTyp, issuer: "https://tts.example"},
		{name: "ShouldRefuseAMissingIssuerWhenConfigured", claims: claims(nil), headers: txnTyp, issuer: "https://tts.example"},
		{name: "ShouldAcceptTheConfiguredIssuer", claims: claims(func(c map[string]any) { c[consts.ClaimIssuer] = "https://tts.example" }), headers: txnTyp, issuer: "https://tts.example", ok: true},
		{name: "ShouldAcceptAChainWithinTheLimit", claims: claims(func(c map[string]any) { c[consts.ClaimRequestingWorkloadChain] = []any{"a"} }), headers: txnTyp, chain: 2, ok: true},
		{name: "ShouldRefuseAChainBeyondTheLimit", claims: claims(func(c map[string]any) { c[consts.ClaimRequestingWorkloadChain] = []any{"a", "b"} }), headers: txnTyp, chain: 2},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := newTxnIssueFixture(t, storage.NewExampleStore())
			f.enableReplacement()
			f.txnType.Issuer = tc.issuer
			f.txnType.Replacement.MaxChainLength = tc.chain
			f.txnType.Replacement.KeyFunc = func(*jwt.Token) (any, error) { return &f.workloadKey.PublicKey, nil }

			_, err := f.exchange(t, txnReplacementExchange(signToken(t, jose.ES256, f.workloadKey, txnKeyID, tc.claims, tc.headers), "trade.stocks"))

			if tc.ok {
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				return
			}

			require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
		})
	}

	t.Run("ShouldRefuseAnotherSigner", func(t *testing.T) {
		f := newTxnIssueFixture(t, storage.NewExampleStore())
		f.enableReplacement()

		_, err := f.exchange(t, txnReplacementExchange(signToken(t, jose.ES256, f.workloadKey, txnKeyID, claims(nil), txnTyp), "trade.stocks"))

		require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
	})
}

func TestTxnTokenReplacementDefaultChainLimit(t *testing.T) {
	f := newTxnIssueFixture(t, storage.NewExampleStore())
	f.enableReplacement()

	token := f.issueForReplacement(t, nil)

	for i := range 8 {
		f.client.ID = "workload-" + strconv.Itoa(i)

		response, err := f.exchange(t, txnReplacementExchange(token))
		require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err), i)

		token = response.GetAccessToken()
	}

	_, err := f.exchange(t, txnReplacementExchange(token))

	require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
}

// A carried value is signed as presented, whatever the hook does to the copy it is given.
func TestTxnTokenReplacementHookCannotChangeCarriedClaims(t *testing.T) {
	for name, store := range txnIssueStores() {
		t.Run(name, func(t *testing.T) {
			f := newTxnIssueFixture(t, store)
			f.enableReplacement()
			f.txnType.TranscribeClaims = CopyTxnTokenRequestParameters

			first := f.issueForReplacement(t, url.Values{
				consts.FormParameterRequestContext: {`{"req_ip":"192.0.2.1"}`},
				consts.FormParameterRequestDetails: {`{"items":["a"],"nested":{"k":"v"}}`},
			})
			firstClaims := txnPayload(t, &oauth2.AccessResponse{AccessToken: first})

			f.txnType.TranscribeClaims = func(_ context.Context, _ oauth2.AccessRequester, input *TxnTokenClaimsInput) error {
				tctx := input.Claims[consts.ClaimTransactionContext].(map[string]any)
				tctx["items"].([]any)[0] = "tampered"
				tctx["nested"].(map[string]any)["k"] = "tampered"
				input.Claims[consts.ClaimSubject] = "mallory"
				input.Claims[consts.ClaimTransaction] = "tampered"
				input.Claims[consts.ClaimAudience] = "other.example"
				input.Claims[consts.ClaimRequestContext] = "not an object"
				input.Claims[consts.ClaimRequestingWorkload] = "tampered"
				input.Claims[consts.ClaimRequestingWorkloadChain] = []string{"tampered"}
				input.Claims["added"] = "kept"

				return nil
			}

			response, err := f.exchange(t, txnReplacementExchange(first))
			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

			claims := txnPayload(t, response)

			for _, claim := range []string{consts.ClaimSubject, consts.ClaimTransaction, consts.ClaimAudience, consts.ClaimRequestContext, consts.ClaimTransactionContext} {
				assert.Equal(t, firstClaims[claim], claims[claim], claim)
			}

			assert.Equal(t, txnClientID, claims[consts.ClaimRequestingWorkload])
			assert.Equal(t, []any{txnClientID}, claims[consts.ClaimRequestingWorkloadChain])
			assert.Equal(t, "kept", claims["added"])
		})
	}
}

// With no hook the carried claims still avoid the JOSE encoder, which writes a json.Number as a string.
func TestTxnTokenReplacementKeepsNumbersWithoutAHook(t *testing.T) {
	f := newTxnIssueFixture(t, storage.NewExampleStore())
	f.enableReplacement()
	f.txnType.TranscribeClaims = CopyTxnTokenRequestParameters

	first := f.issueForReplacement(t, url.Values{consts.FormParameterRequestDetails: {`{"quantity":9007199254740993}`}})

	f.txnType.TranscribeClaims = nil

	response, err := f.exchange(t, txnReplacementExchange(first))
	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

	assert.Contains(t, txnRawPayload(t, response), `"quantity":9007199254740993`)
}

// The handler places the presented claims on the session, so it holds the opt-in itself as well as the grant handler.
func TestTxnTokenReplacementHandlerChecksTheOptIn(t *testing.T) {
	f := newTxnIssueFixture(t, storage.NewExampleStore())
	f.enableReplacement()

	first := f.issueForReplacement(t, nil)

	f.client.replacement = false

	request := &oauth2.AccessRequest{
		GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthTokenExchange},
		Request: oauth2.Request{
			Client:  f.client,
			Session: newSpecSession(""),
			Form: url.Values{
				consts.FormParameterRequestedTokenType: {consts.TokenTypeRFC8693TxnToken},
				consts.FormParameterSubjectTokenType:   {consts.TokenTypeRFC8693TxnToken},
				consts.FormParameterSubjectToken:       {first},
			},
		},
	}

	require.ErrorIs(t, f.txn.HandleTokenEndpointRequest(t.Context(), request), oauth2.ErrInvalidRequest)
	assert.Nil(t, request.GetSession().(*DefaultSession).GetSubjectToken())
}

// The token parser refuses a date outside its range, so an overflowing expiry never reaches the cap.
func TestTxnTokenReplacementRefusesAnOverflowingExpiry(t *testing.T) {
	f := newTxnIssueFixture(t, storage.NewExampleStore())
	f.enableReplacement()
	f.txnType.Replacement.KeyFunc = func(*jwt.Token) (any, error) { return &f.workloadKey.PublicKey, nil }

	token := signToken(t, jose.ES256, f.workloadKey, txnKeyID, map[string]any{
		consts.ClaimIssuedAt:           time.Now().Unix(),
		consts.ClaimExpirationTime:     int64(math.MaxInt64 - 1024),
		consts.ClaimAudience:           txnTrustDomain,
		consts.ClaimTransaction:        uuid.New().String(),
		consts.ClaimSubject:            "alice",
		consts.ClaimScope:              "trade.stocks",
		consts.ClaimRequestingWorkload: txnClientID,
	}, map[string]any{consts.JSONWebTokenHeaderType: consts.JSONWebTokenTypeTxnToken})

	_, err := f.exchange(t, txnReplacementExchange(token, "trade.stocks"))

	require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
}

func TestTxnTokenHookCannotForgeTheChain(t *testing.T) {
	f := newTxnIssueFixture(t, storage.NewExampleStore())
	f.txnType.TranscribeClaims = func(_ context.Context, _ oauth2.AccessRequester, input *TxnTokenClaimsInput) error {
		input.Claims[consts.ClaimRequestingWorkloadChain] = []string{"forged"}

		return nil
	}

	response, err := f.exchange(t, f.hookExchange(t, nil))
	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

	assert.NotContains(t, txnPayload(t, response), consts.ClaimRequestingWorkloadChain)
}

func TestTxnTokenReplacementActor(t *testing.T) {
	act := map[string]any{consts.ClaimSubject: "gateway"}

	sign := func(t *testing.T, f *txnIssueFixture) string {
		t.Helper()

		now := time.Now()

		return signToken(t, jose.ES256, f.workloadKey, txnKeyID, map[string]any{
			consts.ClaimIssuedAt:           now.Unix(),
			consts.ClaimExpirationTime:     now.Add(time.Minute).Unix(),
			consts.ClaimAudience:           txnTrustDomain,
			consts.ClaimTransaction:        uuid.New().String(),
			consts.ClaimSubject:            "alice",
			consts.ClaimScope:              "trade.stocks",
			consts.ClaimRequestingWorkload: txnClientID,
			consts.ClaimActor:              act,
		}, map[string]any{consts.JSONWebTokenHeaderType: consts.JSONWebTokenTypeTxnToken})
	}

	t.Run("ShouldCarryTheActWithoutAnActorToken", func(t *testing.T) {
		f := newTxnIssueFixture(t, storage.NewExampleStore())
		f.enableReplacement()
		f.txnType.Replacement.KeyFunc = func(*jwt.Token) (any, error) { return &f.workloadKey.PublicKey, nil }

		response, err := f.exchange(t, txnReplacementExchange(sign(t, f), "trade.stocks"))
		require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

		assert.Equal(t, act, txnPayload(t, response)[consts.ClaimActor])
	})

	t.Run("ShouldRefuseAnActorToken", func(t *testing.T) {
		f := newTxnIssueFixture(t, storage.NewExampleStore())
		f.enableReplacement()
		f.txnType.Replacement.KeyFunc = func(*jwt.Token) (any, error) { return &f.workloadKey.PublicKey, nil }

		e := txnReplacementExchange(sign(t, f), "trade.stocks")
		e.actorToken = f.mint(t, txnMint{scopes: []string{"trade.stocks"}})

		_, err := f.exchange(t, e)

		require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
		assert.Contains(t, oauth2.ErrorToRFC6749Error(err).HintField, consts.FormParameterActorToken)
	})
}

// A workload reads the chain from a validated token.
func TestTxnTokenReplacementChainIsReadable(t *testing.T) {
	f := newTxnIssueFixture(t, storage.NewExampleStore())
	f.enableReplacement()

	first := f.issueForReplacement(t, nil)

	f.client.ID = txnSecondWorkload

	response, err := f.exchange(t, txnReplacementExchange(first))
	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

	claims, err := txntoken.Validate(response.GetAccessToken(), txntoken.Config{TrustDomain: txnTrustDomain, KeyFunc: func(*jwt.Token) (any, error) { return &key.PublicKey, nil }})
	require.NoError(t, err)

	assert.Equal(t, txnSecondWorkload, claims.RequestingWorkload)
	assert.Equal(t, []string{txnClientID}, claims.RequestingWorkloadChain)
	assert.NotContains(t, claims.Extra, consts.ClaimRequestingWorkloadChain)

	raw, err := json.Marshal(claims.RequestingWorkloadChain)
	require.NoError(t, err)
	assert.JSONEq(t, `["`+txnClientID+`"]`, string(raw))
}
