// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"authelia.com/provider/oauth2/internal/consts"
)

func TestCIBAErrors(t *testing.T) {
	testCases := []struct {
		name     string
		err      *RFC6749Error
		expected string
	}{
		{"UnknownUserID", ErrUnknownUserID, "unknown_user_id"},
		{"ExpiredLoginHintToken", ErrExpiredLoginHintToken, "expired_login_hint_token"},
		{"MissingUserCode", ErrMissingUserCode, "missing_user_code"},
		{"InvalidUserCode", ErrInvalidUserCode, "invalid_user_code"},
		{"InvalidBindingMessage", ErrInvalidBindingMessage, "invalid_binding_message"},
		{"TransactionFailed", ErrTransactionFailed, "transaction_failed"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.err.ErrorField)
			assert.Equal(t, http.StatusBadRequest, tc.err.CodeField)
			assert.NotEmpty(t, tc.err.DescriptionField)
		})
	}

	assert.EqualError(t, ErrInvalidatedCIBASession, "CIBA authentication request has been invalidated")
	assert.EqualError(t, ErrCIBADecided, "CIBA authentication request has already been decided")
	assert.Equal(t, GrantType("urn:openid:params:grant-type:ciba"), GrantTypeCIBA)
	assert.Equal(t, TokenType("auth_req_id"), CIBAAuthRequestID)
}

func TestCIBAConstants(t *testing.T) {
	testCases := []struct {
		name     string
		have     string
		expected string
	}{
		{"DiscoveryLoginHintTokenTypes", consts.DiscoveryBackChannelEndpointLoginHintTokenTypesSupported, "backchannel_endpoint_login_hint_token_types_supported"},
		{"GrantType", consts.GrantTypeOpenIDCIBA, "urn:openid:params:grant-type:ciba"},
		{"AuthReqID", consts.FormParameterAuthReqID, "auth_req_id"},
		{"ClientNotificationToken", consts.FormParameterClientNotificationToken, "client_notification_token"},
		{"BindingMessage", consts.FormParameterBindingMessage, "binding_message"},
		{"RequestedExpiry", consts.FormParameterRequestedExpiry, "requested_expiry"},
		{"LoginHintToken", consts.FormParameterLoginHintToken, "login_hint_token"},
		{"ModePoll", consts.CIBAModePoll, "poll"},
		{"ModePing", consts.CIBAModePing, "ping"},
		{"ModePush", consts.CIBAModePush, "push"},
		{"ClaimAuthReqID", consts.ClaimCIBAAuthReqID, "urn:openid:params:jwt:claim:auth_req_id"},
		{"ClaimRefreshTokenHash", consts.ClaimRefreshTokenHash, "urn:openid:params:jwt:claim:rt_hash"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.have)
		})
	}
}
