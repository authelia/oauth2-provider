// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693_test

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2"
	. "authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

func txnSignedClaims(extra map[string]any) map[string]any {
	now := time.Now()

	claims := map[string]any{
		consts.ClaimIssuedAt:           now.Unix(),
		consts.ClaimExpirationTime:     now.Add(time.Minute).Unix(),
		consts.ClaimAudience:           txnTrustDomain,
		consts.ClaimTransaction:        uuid.New().String(),
		consts.ClaimSubject:            "alice",
		consts.ClaimScope:              "trade.stocks",
		consts.ClaimRequestingWorkload: txnClientID,
	}

	for name, value := range extra {
		claims[name] = value
	}

	return claims
}

func (f *txnIssueFixture) signTxnToken(t *testing.T, extra map[string]any) string {
	t.Helper()

	f.txnType.Replacement.KeyFunc = func(*jwt.Token) (any, error) { return &f.workloadKey.PublicKey, nil }

	return signToken(t, jose.ES256, f.workloadKey, txnKeyID, txnSignedClaims(extra), map[string]any{consts.JSONWebTokenHeaderType: consts.JSONWebTokenTypeTxnToken})
}

// §13.3: a refresh token must not be used to request a Transaction Token, in either role.
func TestTxnTokenRefusesRefreshTokenActor(t *testing.T) {
	store := storage.NewExampleStore()

	f := newTxnIssueFixture(t, store)
	f.client.allowActor = true
	f.client.refresh = true
	f.client.GrantTypes = append(f.client.GrantTypes, consts.GrantTypeRefreshToken)
	f.handlers = append(f.handlers[:1:1], append([]oauth2.TokenEndpointHandler{newRefreshTokenTypeHandler(f.cfg, store, f.core)}, f.handlers[1:]...)...)

	_, err := f.exchange(t, txnExchange{
		subjectToken:   f.mint(t, txnMint{scopes: []string{"trade.stocks"}}),
		scopes:         []string{"trade.stocks"},
		actorToken:     createExchangeRefreshToken(t, f.core, store, f.client, "bob", "trade.stocks"),
		actorTokenType: consts.TokenTypeRFC8693RefreshToken,
	})

	require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
	assert.Contains(t, oauth2.ErrorToRFC6749Error(err).HintField, consts.FormParameterActorTokenType)
}

// A type under another key is not the requested type, so its token cannot become one of this Trust Domain.
func TestTxnTokenReplacementRefusesAnotherType(t *testing.T) {
	const alias = "urn:example:txn-b"

	f := newTxnIssueFixture(t, storage.NewExampleStore())
	f.enableReplacement()

	f.cfg.RFC8693TokenTypes[alias] = &TxnTokenType{
		Name:        alias,
		TrustDomain: "domain-b.example",
		Replacement: &TxnTokenReplacement{KeyFunc: func(*jwt.Token) (any, error) { return &f.workloadKey.PublicKey, nil }},
	}

	token := signToken(t, jose.ES256, f.workloadKey, txnKeyID, txnSignedClaims(map[string]any{consts.ClaimAudience: "domain-b.example"}), map[string]any{consts.JSONWebTokenHeaderType: consts.JSONWebTokenTypeTxnToken})

	response, err := f.exchange(t, txnExchange{subjectType: alias, subjectToken: token, scopes: []string{"trade.stocks"}})

	require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
	assert.Nil(t, response)
}

// The same type under a second key is still a replacement, so every safeguard applies.
func TestTxnTokenReplacementAppliesUnderAnAlias(t *testing.T) {
	const alias = "urn:example:txn-alias"

	f := newTxnIssueFixture(t, storage.NewExampleStore())
	f.enableReplacement()

	f.cfg.RFC8693TokenTypes[alias] = f.txnType

	first := f.issueForReplacement(t, nil)
	firstClaims := txnPayload(t, &oauth2.AccessResponse{AccessToken: first})

	response, err := f.exchange(t, txnExchange{subjectType: alias, subjectToken: first, scopes: []string{"trade.stocks"}})
	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

	claims := txnPayload(t, response)

	assert.Equal(t, firstClaims[consts.ClaimTransaction], claims[consts.ClaimTransaction])
	assert.Equal(t, []any{txnClientID}, claims[consts.ClaimRequestingWorkloadChain])
}

func TestTxnTokenMayAct(t *testing.T) {
	t.Run("ShouldNotBeSetByAHook", func(t *testing.T) {
		f := newTxnIssueFixture(t, storage.NewExampleStore())
		f.txnType.TranscribeClaims = func(_ context.Context, _ oauth2.AccessRequester, input *TxnTokenClaimsInput) error {
			input.Claims[consts.ClaimAuthorizedActor] = map[string]any{consts.ClaimSubject: "bob"}

			return nil
		}

		response, err := f.exchange(t, f.hookExchange(t, nil))
		require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

		assert.NotContains(t, txnPayload(t, response), consts.ClaimAuthorizedActor)
	})

	t.Run("ShouldBeRefusedOnAPresentedToken", func(t *testing.T) {
		f := newTxnIssueFixture(t, storage.NewExampleStore())
		f.enableReplacement()

		token := f.signTxnToken(t, map[string]any{consts.ClaimAuthorizedActor: map[string]any{consts.ClaimSubject: "bob"}})

		_, err := f.exchange(t, txnReplacementExchange(token, "trade.stocks"))

		require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
		assert.Contains(t, oauth2.ErrorToRFC6749Error(err).HintField, consts.ClaimAuthorizedActor)
	})
}

// §9.2.3: 'tctx' is immutable through the Call Chain, so a replacing workload cannot supply one.
func TestCopyTxnTokenRequestParametersSkipsAReplacement(t *testing.T) {
	f := newTxnIssueFixture(t, storage.NewExampleStore())
	f.enableReplacement()
	f.txnType.TranscribeClaims = CopyTxnTokenRequestParameters

	first := f.issueForReplacement(t, nil)

	e := txnReplacementExchange(first)
	e.form = url.Values{consts.FormParameterRequestContext: {`{"req_ip":"192.0.2.1"}`}, consts.FormParameterRequestDetails: {`{"level":"VIP"}`}}

	response, err := f.exchange(t, e)
	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

	claims := txnPayload(t, response)

	assert.NotContains(t, claims, consts.ClaimRequestContext)
	assert.NotContains(t, claims, consts.ClaimTransactionContext)
}

// §13.15: dropping 'nbf' would make the replacement usable earlier than the token it replaces.
func TestTxnTokenReplacementCarriesNotBefore(t *testing.T) {
	f := newTxnIssueFixture(t, storage.NewExampleStore())
	f.enableReplacement()

	nbf := time.Now().Add(-time.Minute).Unix()

	response, err := f.exchange(t, txnReplacementExchange(f.signTxnToken(t, map[string]any{consts.ClaimNotBefore: nbf, consts.ClaimJWTID: "first"}), "trade.stocks"))
	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

	claims := txnPayload(t, response)

	assert.EqualValues(t, nbf, claims[consts.ClaimNotBefore])
	assert.NotContains(t, claims, consts.ClaimJWTID)
}

// A server that cannot mark a 'jti' is refused before the hook runs and a token is signed.
func TestTxnTokenMissingJTIStorageIsFoundFirst(t *testing.T) {
	f := newTxnIssueFixture(t, storage.NewExampleStore())
	f.scopes.scopes = []string{"trade.stocks"}
	f.cfg.RFC8693TokenTypes[consts.TokenTypeRFC8693SelfSigned].(*SelfSignedTokenType).ValidateJTI = true

	f.txnType.TranscribeClaims = func(context.Context, oauth2.AccessRequester, *TxnTokenClaimsInput) error {
		t.Error("the hook ran")

		return nil
	}

	claims := selfSignedClaims()
	claims[consts.ClaimJWTID] = uuid.New().String()

	_, err := f.exchange(t, txnExchange{subjectType: consts.TokenTypeRFC8693SelfSigned, subjectToken: signToken(t, jose.ES256, f.workloadKey, txnKeyID, claims, nil), scopes: []string{"trade.stocks"}})

	require.ErrorIs(t, err, oauth2.ErrServerError)
}
