// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693_test

import (
	"context"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	. "authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal/consts"
)

func TestCopyTxnTokenRequestParameters(t *testing.T) {
	testCases := []struct {
		name string
		form url.Values
		rctx any
		tctx any
	}{
		{
			name: "ShouldCopyBoth",
			form: url.Values{consts.FormParameterRequestContext: {`{"req_ip":"192.0.2.1"}`}, consts.FormParameterRequestDetails: {`{"action":"BUY","customer":{"geo":"US"}}`}},
			rctx: map[string]any{"req_ip": "192.0.2.1"},
			tctx: map[string]any{"action": "BUY", "customer": map[string]any{"geo": "US"}},
		},
		{
			name: "ShouldCopyOnlyTheRequestContext",
			form: url.Values{consts.FormParameterRequestContext: {`{"req_ip":"192.0.2.1"}`}},
			rctx: map[string]any{"req_ip": "192.0.2.1"},
		},
		{
			name: "ShouldCopyOnlyTheRequestDetails",
			form: url.Values{consts.FormParameterRequestDetails: {`{"action":"BUY"}`}},
			tctx: map[string]any{"action": "BUY"},
		},
		{name: "ShouldOmitAbsentParameters"},
		{
			name: "ShouldOmitEmptyObjects",
			form: url.Values{consts.FormParameterRequestContext: {`{}`}, consts.FormParameterRequestDetails: {`{}`}},
		},
	}

	for name, store := range txnIssueStores() {
		t.Run(name, func(t *testing.T) {
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					f := newTxnIssueFixture(t, store)
					f.txnType.TranscribeClaims = CopyTxnTokenRequestParameters

					response, err := f.exchange(t, f.hookExchange(t, tc.form))
					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

					payload := txnPayload(t, response)

					assertClaimOrAbsent(t, payload, consts.ClaimRequestContext, tc.rctx)
					assertClaimOrAbsent(t, payload, consts.ClaimTransactionContext, tc.tctx)
				})
			}
		})
	}
}

func assertClaimOrAbsent(t *testing.T, payload map[string]any, name string, want any) {
	t.Helper()

	if want == nil {
		assert.NotContains(t, payload, name)

		return
	}

	assert.Equal(t, want, payload[name])
}

func TestCopyTxnTokenRequestParametersKeepsNumberPrecision(t *testing.T) {
	f := newTxnIssueFixture(t, storageForCopyTest())
	f.txnType.TranscribeClaims = CopyTxnTokenRequestParameters

	response, err := f.exchange(t, f.hookExchange(t, url.Values{consts.FormParameterRequestDetails: {`{"quantity":9007199254740993}`}}))
	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

	assert.Contains(t, txnRawPayload(t, response), `"quantity":9007199254740993`)
}

// A parameter that is absent leaves a value the deployer set, and one that is present replaces it.
func TestCopyTxnTokenRequestParametersFromAHook(t *testing.T) {
	f := newTxnIssueFixture(t, storageForCopyTest())
	f.txnType.TranscribeClaims = func(ctx context.Context, request oauth2.AccessRequester, input *TxnTokenClaimsInput) error {
		input.Claims[consts.ClaimRequestContext] = map[string]any{"source": "deployer"}
		input.Claims[consts.ClaimTransactionContext] = map[string]any{"source": "deployer"}

		return CopyTxnTokenRequestParameters(ctx, request, input)
	}

	response, err := f.exchange(t, f.hookExchange(t, url.Values{consts.FormParameterRequestDetails: {`{"source":"workload"}`}}))
	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

	payload := txnPayload(t, response)

	assert.Equal(t, map[string]any{"source": "deployer"}, payload[consts.ClaimRequestContext])
	assert.Equal(t, map[string]any{"source": "workload"}, payload[consts.ClaimTransactionContext])
}

// The helper is opt-in, so nothing is copied unless the deployer sets it.
func TestTxnTokenParametersNotCopiedWithoutTheHelper(t *testing.T) {
	f := newTxnIssueFixture(t, storageForCopyTest())
	f.txnType.TranscribeClaims = func(context.Context, oauth2.AccessRequester, *TxnTokenClaimsInput) error { return nil }

	response, err := f.exchange(t, f.hookExchange(t, url.Values{consts.FormParameterRequestContext: {`{"a":"b"}`}, consts.FormParameterRequestDetails: {`{"a":"b"}`}}))
	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

	payload := txnPayload(t, response)

	assert.NotContains(t, payload, consts.ClaimRequestContext)
	assert.NotContains(t, payload, consts.ClaimTransactionContext)
}

func storageForCopyTest() txnIssueStore {
	return txnIssueStores()["ExampleStore"]
}
