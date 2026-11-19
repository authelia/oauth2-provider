// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package jwt_test

import (
	"encoding/json"
	"math/big"
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

func TestNewSecurityEventTokenClaimsStringOrURI(t *testing.T) {
	subject, err := NewSubjectIdentifierEmail("john@example.com")
	require.NoError(t, err)

	testCases := []struct {
		name     string
		issuer   string
		audience []string
		uri      string
		err      string
	}{
		{"ShouldAcceptURIs", "https://issuer.example.com", []string{"https://receiver.example.com", "urn:example:receiver"}, "https://example.com/event", ""},
		{"ShouldAcceptStringIssuerAndAudience", "issuer", []string{"receiver"}, "urn:example:event", ""},
		{"ShouldRejectEventTypeWithoutScheme", "issuer", []string{"receiver"}, "not a uri", "event type"},
		{"ShouldRejectEventTypeString", "issuer", []string{"receiver"}, "session-revoked", "event type"},
		{"ShouldRejectEventTypeWithSpace", "issuer", []string{"receiver"}, "https://example.com/an event", "event type"},
		{"ShouldRejectAudienceNotURI", "issuer", []string{"x:y z"}, "urn:example:event", "'aud'"},
		{"ShouldRejectSecondAudienceNotURI", "issuer", []string{"receiver", "x:y z"}, "urn:example:event", "'aud'"},
		{"ShouldRejectIssuerNotURI", "a:b c", []string{"receiver"}, "urn:example:event", "'iss'"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			claims, err := NewSecurityEventTokenClaims(tc.issuer, tc.audience, subject, RawSecurityEvent{URI: tc.uri}, "")

			if tc.err == "" {
				require.NoError(t, err)
				assert.NoError(t, claims.Valid())

				return
			}

			assert.Nil(t, claims)
			require.ErrorIs(t, err, ErrInvalidSecurityEvent)
			assert.Contains(t, err.Error(), tc.err)
		})
	}
}

func TestSecurityEventTokenClaimsValidEventsAndAudience(t *testing.T) {
	subject, err := NewSubjectIdentifierEmail("john@example.com")
	require.NoError(t, err)

	testCases := []struct {
		name   string
		mutate func(claims *SecurityEventTokenClaims)
		errors uint32
	}{
		{"ShouldPassValid", func(claims *SecurityEventTokenClaims) {}, 0},
		{"ShouldPassEmptyObjectPayload", func(claims *SecurityEventTokenClaims) {
			claims.Events = map[string]any{"urn:example:event": map[string]any{}}
		}, 0},
		{"ShouldFailEventTypeNotURI", func(claims *SecurityEventTokenClaims) {
			claims.Events = map[string]any{"not a uri": map[string]any{}}
		}, ValidationErrorClaimsInvalid},
		{"ShouldFailEmptyEventType", func(claims *SecurityEventTokenClaims) {
			claims.Events = map[string]any{"": map[string]any{}}
		}, ValidationErrorClaimsInvalid},
		{"ShouldFailNilPayload", func(claims *SecurityEventTokenClaims) {
			claims.Events = map[string]any{"urn:example:event": nil}
		}, ValidationErrorClaimsInvalid},
		{"ShouldFailStringPayload", func(claims *SecurityEventTokenClaims) {
			claims.Events = map[string]any{"urn:example:event": "payload"}
		}, ValidationErrorClaimsInvalid},
		{"ShouldFailArrayPayload", func(claims *SecurityEventTokenClaims) {
			claims.Events = map[string]any{"urn:example:event": []any{}}
		}, ValidationErrorClaimsInvalid},
		{"ShouldFailNumberPayload", func(claims *SecurityEventTokenClaims) {
			claims.Events = map[string]any{"urn:example:event": int64(1)}
		}, ValidationErrorClaimsInvalid},
		{"ShouldFailEmptyAudienceValue", func(claims *SecurityEventTokenClaims) { claims.Audience = []string{""} }, ValidationErrorAudience},
		{"ShouldFailEmptySecondAudienceValue", func(claims *SecurityEventTokenClaims) { claims.Audience = []string{"aud", ""} }, ValidationErrorAudience},
		{"ShouldFailAudienceNotURI", func(claims *SecurityEventTokenClaims) { claims.Audience = []string{"x:y z"} }, ValidationErrorAudience},
		{"ShouldFailIssuerNotURI", func(claims *SecurityEventTokenClaims) { claims.Issuer = "a:b c" }, ValidationErrorIssuer},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			claims, err := NewSecurityEventTokenClaims("https://issuer.example.com", []string{"https://receiver.example.com"}, subject, CAEPSessionRevoked{}, "")
			require.NoError(t, err)

			tc.mutate(claims)

			err = claims.Valid()

			if tc.errors == 0 {
				assert.NoError(t, err)

				return
			}

			var vErr *ValidationError

			require.ErrorAs(t, err, &vErr)
			assert.Equal(t, tc.errors, vErr.Errors)
		})
	}

	t.Run("ShouldFailDecodedNonObjectPayload", func(t *testing.T) {
		var claims SecurityEventTokenClaims

		require.NoError(t, json.Unmarshal([]byte(`{"iss":"iss","aud":["aud"],"jti":"id","iat":1700000000,"sub_id":{"format":"opaque","id":"x"},"events":{"urn:example:event":"payload"}}`), &claims))
		assert.Error(t, claims.Valid())
	})
}

func TestNewSecurityEventTokenClaimsNilEvent(t *testing.T) {
	subject, err := NewSubjectIdentifierEmail("john@example.com")
	require.NoError(t, err)

	testCases := []struct {
		name  string
		event SecurityEvent
	}{
		{"ShouldRejectNilInterface", nil},
		{"ShouldRejectNilTypedPointer", (*CAEPSessionRevoked)(nil)},
		{"ShouldRejectNilRawPointer", (*RawSecurityEvent)(nil)},
		{"ShouldRejectNilValidatedPointer", (*CAEPCredentialChange)(nil)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var (
				claims *SecurityEventTokenClaims
				err    error
			)

			require.NotPanics(t, func() {
				claims, err = NewSecurityEventTokenClaims("https://issuer.example.com", []string{"aud"}, subject, tc.event, "")
			})

			assert.Nil(t, claims)
			assert.ErrorIs(t, err, ErrInvalidSecurityEvent)
		})
	}
}

func TestNewSecurityEventTokenClaimsVerificationState(t *testing.T) {
	subject, err := NewSubjectIdentifierOpaque("stream-1")
	require.NoError(t, err)

	testCases := []struct {
		name     string
		event    SecurityEvent
		expected map[string]any
	}{
		{"ShouldEchoState", &SSFVerification{State: new("abc")}, map[string]any{"state": "abc"}},
		{"ShouldEchoEmptyState", &SSFVerification{State: new("")}, map[string]any{"state": ""}},
		{"ShouldOmitNilState", &SSFVerification{}, map[string]any{}},
		{"ShouldEchoEmptyRawState", &RawSecurityEvent{URI: SecurityEventTypeSSFVerification, Claims: map[string]any{"state": ""}}, map[string]any{"state": ""}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			claims, err := NewSecurityEventTokenClaims("https://issuer.example.com", []string{"aud"}, subject, tc.event, "")
			require.NoError(t, err)

			assert.Equal(t, tc.expected, claims.Events[SecurityEventTypeSSFVerification])
			assert.NoError(t, claims.Valid())
		})
	}
}

func TestNewSecurityEventTokenClaimsShouldCopyAudience(t *testing.T) {
	subject, err := NewSubjectIdentifierEmail("john@example.com")
	require.NoError(t, err)

	audience := []string{"https://receiver.example.com", "https://other.example.com"}

	claims, err := NewSecurityEventTokenClaims("https://issuer.example.com", audience, subject, CAEPSessionRevoked{}, "")
	require.NoError(t, err)

	audience[0] = "https://attacker.example.com"

	assert.Equal(t, []string{"https://receiver.example.com", "https://other.example.com"}, claims.Audience)
}

func TestNewSecurityEventTokenClaimsShouldKeepIntegerPrecision(t *testing.T) {
	subject, err := NewSubjectIdentifierEmail("john@example.com")
	require.NoError(t, err)

	huge, ok := new(big.Int).SetString("123456789012345678901234567890", 10)
	require.True(t, ok)

	testCases := []struct {
		name     string
		have     any
		expected any
		literal  string
	}{
		{"ShouldKeepInt64", int64(9007199254740993), int64(9007199254740993), "9007199254740993"},
		{"ShouldKeepNegativeInt64", int64(-9007199254740993), int64(-9007199254740993), "-9007199254740993"},
		{"ShouldKeepUint64", uint64(18446744073709551615), uint64(18446744073709551615), "18446744073709551615"},
		{"ShouldKeepUint64Number", json.Number("18446744073709551615"), uint64(18446744073709551615), "18446744073709551615"},
		{"ShouldKeepLargeNumber", json.Number("123456789012345678901234567890"), huge, "123456789012345678901234567890"},
		{"ShouldKeepLargeNegativeNumber", json.Number("-123456789012345678901234567890"), new(big.Int).Neg(huge), "-123456789012345678901234567890"},
		{"ShouldKeepBigInt", huge, huge, "123456789012345678901234567890"},
		{"ShouldKeepFloat", 1.5, 1.5, "1.5"},
		{"ShouldKeepIntegralExponent", json.Number("1e3"), int64(1000), "1000"},
		{"ShouldKeepLargeExponent", json.Number("1e30"), 1e30, "1e+30"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			event := RawSecurityEvent{URI: "https://example.com/event", Claims: map[string]any{
				"serial": tc.have,
				"nested": map[string]any{"list": []any{tc.have, "x"}},
			}}

			claims, err := NewSecurityEventTokenClaims("https://issuer.example.com", []string{"aud"}, subject, event, "")
			require.NoError(t, err)

			payload, ok := claims.Events["https://example.com/event"].(map[string]any)
			require.True(t, ok)

			assert.Equal(t, tc.expected, payload["serial"])
			assert.Equal(t, map[string]any{"list": []any{tc.expected, "x"}}, payload["nested"])

			data, err := json.Marshal(claims.ToMap()[ClaimEvents])
			require.NoError(t, err)

			assert.Equal(t, `{"https://example.com/event":{"nested":{"list":[`+tc.literal+`,"x"]},"serial":`+tc.literal+`}}`, string(data))
		})
	}

	t.Run("ShouldRejectNumberOutOfRange", func(t *testing.T) {
		event := RawSecurityEvent{URI: "https://example.com/event", Claims: map[string]any{"serial": json.Number("1e999")}}

		_, err := NewSecurityEventTokenClaims("https://issuer.example.com", []string{"aud"}, subject, event, "")
		assert.ErrorIs(t, err, ErrInvalidSecurityEvent)
	})
}
