// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package jwt_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2/internal/consts"
	. "authelia.com/provider/oauth2/token/jwt"
)

func TestSecurityEventTokenClaims(t *testing.T) {
	subject, err := NewSubjectIdentifierEmail("john@example.com")
	require.NoError(t, err)

	event := CAEPSessionRevoked{SecurityEventCommon: SecurityEventCommon{EventTimestamp: 1700000000}}

	t.Run("ShouldBuildClaims", func(t *testing.T) {
		claims, err := NewSecurityEventTokenClaims("https://issuer.example.com", []string{"https://receiver.example.com"}, subject, event, "txn-1")
		require.NoError(t, err)

		m := claims.ToMap()

		assert.Equal(t, "https://issuer.example.com", m[ClaimIssuer])
		assert.Equal(t, []string{"https://receiver.example.com"}, m[ClaimAudience])
		assert.NotEmpty(t, m[ClaimJWTID])
		assert.NotNil(t, m[ClaimIssuedAt])
		assert.Equal(t, "txn-1", m[ClaimTransaction])
		assert.Equal(t, subject, m[ClaimSubjectIdentifier])
		assert.NotContains(t, m, ClaimSubject)
		assert.NotContains(t, m, ClaimExpirationTime)

		events, ok := m[ClaimEvents].(map[string]any)
		require.True(t, ok)
		require.Len(t, events, 1)
		assert.Contains(t, events, SecurityEventTypeCAEPSessionRevoked)

		sub, err := claims.GetSubject()
		assert.NoError(t, err)
		assert.Empty(t, sub)

		exp, err := claims.GetExpirationTime()
		assert.NoError(t, err)
		assert.Nil(t, exp)

		assert.NoError(t, claims.Valid())
	})

	t.Run("ShouldOmitEmptyTransaction", func(t *testing.T) {
		claims, err := NewSecurityEventTokenClaims("iss", []string{"aud"}, subject, event, "")
		require.NoError(t, err)

		assert.NotContains(t, claims.ToMap(), ClaimTransaction)
	})

	t.Run("ShouldNotCopyExtra", func(t *testing.T) {
		claims, err := NewSecurityEventTokenClaims("iss", []string{"aud"}, subject, event, "")
		require.NoError(t, err)

		claims.Add(ClaimSubject, "x")
		claims.Add(ClaimExpirationTime, 1)

		assert.NotContains(t, claims.ToMap(), ClaimSubject)
		assert.NotContains(t, claims.ToMap(), ClaimExpirationTime)
	})

	t.Run("ShouldRoundTrip", func(t *testing.T) {
		claims, err := NewSecurityEventTokenClaims("iss", []string{"aud"}, subject, event, "txn")
		require.NoError(t, err)

		data, err := json.Marshal(claims.ToMap())
		require.NoError(t, err)

		var parsed SecurityEventTokenClaims

		require.NoError(t, json.Unmarshal(data, &parsed))
		require.NoError(t, parsed.Valid())

		assert.Equal(t, claims.ToMap()[ClaimJWTID], parsed.ToMap()[ClaimJWTID])
		assert.Equal(t, "txn", parsed.ToMap()[ClaimTransaction])

		events, ok := parsed.ToMap()[ClaimEvents].(map[string]any)
		require.True(t, ok)
		assert.Contains(t, events, SecurityEventTypeCAEPSessionRevoked)

		again, err := json.Marshal(parsed.ToMap())
		require.NoError(t, err)
		assert.JSONEq(t, string(data), string(again))
	})

	t.Run("ShouldFailConstruction", func(t *testing.T) {
		_, err := NewSecurityEventTokenClaims("iss", []string{"aud"}, nil, event, "")
		assert.Error(t, err)

		_, err = NewSecurityEventTokenClaims("iss", []string{"aud"}, subject, nil, "")
		assert.Error(t, err)

		_, err = NewSecurityEventTokenClaims("", []string{"aud"}, subject, event, "")
		assert.Error(t, err)

		_, err = NewSecurityEventTokenClaims("iss", []string{"aud"}, &SubjectIdentifier{Format: SubjectIdentifierFormatEmail}, event, "")
		assert.ErrorIs(t, err, ErrInvalidSubjectIdentifier)

		_, err = NewSecurityEventTokenClaims("iss", []string{"aud"}, subject, CAEPTokenClaimsChange{}, "")
		assert.ErrorIs(t, err, ErrInvalidSecurityEvent)

		for _, audience := range [][]string{nil, {}, {""}, {"aud", ""}} {
			_, err = NewSecurityEventTokenClaims("iss", audience, subject, event, "")
			assert.ErrorIs(t, err, ErrInvalidSecurityEvent)
		}

		_, err = NewSecurityEventTokenClaims("iss", []string{"aud"}, subject, RawSecurityEvent{}, "")
		assert.ErrorIs(t, err, ErrInvalidSecurityEvent)
	})

	validBase := func() map[string]any {
		return map[string]any{
			ClaimIssuer:            "iss",
			ClaimAudience:          []string{"aud"},
			ClaimJWTID:             "id",
			ClaimIssuedAt:          time.Now().Unix(),
			ClaimSubjectIdentifier: map[string]any{"format": "email", "email": "a@example.com"},
			ClaimEvents:            map[string]any{SecurityEventTypeCAEPSessionRevoked: map[string]any{}},
		}
	}

	decode := func(t *testing.T, m map[string]any) (claims SecurityEventTokenClaims, err error) {
		data, err := json.Marshal(m)
		require.NoError(t, err)

		err = json.Unmarshal(data, &claims)

		return claims, err
	}

	testCases := []struct {
		name   string
		mutate func(m map[string]any)
		opts   []ClaimValidationOption
		err    bool
	}{
		{"ShouldPassValid", func(m map[string]any) {}, nil, false},
		{"ShouldFailSub", func(m map[string]any) { m[ClaimSubject] = "john" }, nil, true},
		{"ShouldFailSubWithOption", func(m map[string]any) { m[ClaimSubject] = "john" }, []ClaimValidationOption{ValidateSubject("john")}, true},
		{"ShouldFailExp", func(m map[string]any) { m[ClaimExpirationTime] = time.Now().Add(time.Hour).Unix() }, nil, true},
		{"ShouldFailExpWithOption", func(m map[string]any) { m[ClaimExpirationTime] = time.Now().Add(time.Hour).Unix() }, []ClaimValidationOption{ValidateRequireExpiresAt()}, true},
		{"ShouldFailZeroEvents", func(m map[string]any) { m[ClaimEvents] = map[string]any{} }, nil, true},
		{"ShouldFailMissingEvents", func(m map[string]any) { delete(m, ClaimEvents) }, nil, true},
		{"ShouldFailTwoEvents", func(m map[string]any) {
			m[ClaimEvents] = map[string]any{SecurityEventTypeCAEPSessionRevoked: map[string]any{}, SecurityEventTypeCAEPSessionPresented: map[string]any{}}
		}, nil, true},
		{"ShouldFailMissingAudience", func(m map[string]any) { delete(m, ClaimAudience) }, nil, true},
		{"ShouldFailMissingJTI", func(m map[string]any) { delete(m, ClaimJWTID) }, nil, true},
		{"ShouldFailMissingIssuedAt", func(m map[string]any) { delete(m, ClaimIssuedAt) }, nil, true},
		{"ShouldFailMissingIssuer", func(m map[string]any) { delete(m, ClaimIssuer) }, nil, true},
		{"ShouldFailMissingSubjectIdentifier", func(m map[string]any) { delete(m, ClaimSubjectIdentifier) }, nil, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			m := validBase()
			tc.mutate(m)

			claims, err := decode(t, m)
			if err != nil {
				assert.True(t, tc.err)

				return
			}

			if tc.err {
				assert.Error(t, claims.Valid(tc.opts...))
			} else {
				assert.NoError(t, claims.Valid(tc.opts...))
			}
		})
	}

	t.Run("ShouldFailLogoutToken", func(t *testing.T) {
		logout := NewLogoutTokenClaims("john", []string{"aud"}, "sid", nil)
		logout.Issuer = "iss"
		logout.JTI = "id"

		claims, err := decode(t, logout.ToMap())
		require.NoError(t, err)
		assert.Error(t, claims.Valid())
	})

	t.Run("ShouldFailIDToken", func(t *testing.T) {
		id := &IDTokenClaims{Subject: "john", Issuer: "iss", Audience: []string{"aud"}, IssuedAt: Now(), ExpirationTime: NewNumericDate(time.Now().Add(time.Hour))}

		claims, err := decode(t, id.ToMap())
		require.NoError(t, err)
		assert.Error(t, claims.Valid())
	})

	t.Run("ShouldNotGenerateJTIInToMap", func(t *testing.T) {
		assert.NotContains(t, (&SecurityEventTokenClaims{}).ToMap(), ClaimJWTID)
	})

	assert.Equal(t, "secevent+jwt", consts.JSONWebTokenTypeSecurityEventToken)
	assert.Equal(t, "secevent+jwt", JSONWebTokenTypeSecurityEventToken)
}
