// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"
)

func TestSecurityEventTokenClaimsEncode(t *testing.T) {
	secret := []byte("foobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoob")

	strategy := &DefaultStrategy{
		Config: &testConfig{},
		Issuer: NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{}),
	}

	client := &testClient{id: "client-id", alg: string(jose.HS256), csigned: true, secret: secret}

	subject, err := NewSubjectIdentifierEmail("john@example.com")
	require.NoError(t, err)

	claims, err := NewSecurityEventTokenClaims("client-id", []string{"aud"}, subject, CAEPSessionRevoked{}, "txn")
	require.NoError(t, err)

	token, _, err := strategy.Encode(t.Context(), claims, WithHeaders(&Headers{Extra: map[string]any{JSONWebTokenHeaderType: JSONWebTokenTypeSecurityEventToken}}), WithClient(client))
	require.NoError(t, err)

	decoded, err := strategy.Decode(t.Context(), token, WithClient(client))
	require.NoError(t, err)

	assert.Equal(t, JSONWebTokenTypeSecurityEventToken, decoded.Header[JSONWebTokenHeaderType])
	assert.Equal(t, claims.JTI, decoded.Claims.ToMapClaims()[ClaimJWTID])
	assert.Equal(t, "txn", decoded.Claims.ToMapClaims()[ClaimTransaction])
	assert.Equal(t, map[string]any{SecurityEventTypeCAEPSessionRevoked: map[string]any{}}, decoded.Claims.ToMapClaims()[ClaimEvents])
	assert.Equal(t, map[string]any{"format": SubjectIdentifierFormatEmail, "email": "john@example.com"}, decoded.Claims.ToMapClaims()[ClaimSubjectIdentifier])
}

func TestSecurityEventTokenClaimsEncodeShouldKeepIntegerPrecision(t *testing.T) {
	secret := []byte("foobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoobarfoob")

	strategy := &DefaultStrategy{
		Config: &testConfig{},
		Issuer: NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{}),
	}

	client := &testClient{id: "client-id", alg: string(jose.HS256), csigned: true, secret: secret}

	subject, err := NewSubjectIdentifierEmail("john@example.com")
	require.NoError(t, err)

	event := RawSecurityEvent{URI: "https://example.com/event", Claims: map[string]any{
		"unsigned": uint64(18446744073709551615),
		"huge":     json.Number("123456789012345678901234567890"),
	}}

	claims, err := NewSecurityEventTokenClaims("client-id", []string{"aud"}, subject, event, "")
	require.NoError(t, err)

	token, _, err := strategy.Encode(t.Context(), claims, WithHeaders(&Headers{Extra: map[string]any{JSONWebTokenHeaderType: JSONWebTokenTypeSecurityEventToken}}), WithClient(client))
	require.NoError(t, err)

	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)

	assert.Contains(t, string(payload), `"unsigned":18446744073709551615`)
	assert.Contains(t, string(payload), `"huge":123456789012345678901234567890`)
}
