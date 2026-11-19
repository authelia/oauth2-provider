// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeSecurityEvent(t *testing.T) {
	state := "VGhpcyBpcyBhbiBleGFtcGxl"

	t.Run("ShouldDecodeEachRegisteredType", func(t *testing.T) {
		testCases := []struct {
			uri      string
			payload  map[string]any
			expected SecurityEvent
		}{
			{SecurityEventTypeCAEPSessionRevoked, map[string]any{"event_timestamp": 1615304991, "initiating_entity": "policy", "reason_admin": map[string]any{"en": "Policy"}}, &CAEPSessionRevoked{SecurityEventCommon{EventTimestamp: 1615304991, InitiatingEntity: SecurityEventInitiatingEntityPolicy, ReasonAdmin: map[string]string{"en": "Policy"}}}},
			{SecurityEventTypeCAEPTokenClaimsChange, map[string]any{"claims": map[string]any{"role": "ro-admin"}}, &CAEPTokenClaimsChange{Claims: map[string]any{"role": "ro-admin"}}},
			{SecurityEventTypeCAEPCredentialChange, map[string]any{"credential_type": "fido2-roaming", "change_type": "create", "friendly_name": "Key"}, &CAEPCredentialChange{CredentialType: CAEPCredentialTypeFIDO2Roaming, ChangeType: CAEPChangeTypeCreate, FriendlyName: "Key"}},
			{SecurityEventTypeCAEPAssuranceLevelChange, map[string]any{"namespace": "NIST-AAL", "current_level": "nist-aal2", "previous_level": "nist-aal1", "change_direction": "increase"}, &CAEPAssuranceLevelChange{Namespace: "NIST-AAL", CurrentLevel: "nist-aal2", PreviousLevel: "nist-aal1", ChangeDirection: CAEPChangeDirectionIncrease}},
			{SecurityEventTypeCAEPDeviceComplianceChange, map[string]any{"previous_status": "compliant", "current_status": "not-compliant"}, &CAEPDeviceComplianceChange{PreviousStatus: CAEPDeviceComplianceCompliant, CurrentStatus: CAEPDeviceComplianceNotCompliant}},
			{SecurityEventTypeCAEPSessionEstablished, map[string]any{"fp_ua": "abb0b6e7da81a42233f8f2b1a8ddb1b9a4c81611", "acr": "AAL2", "amr": []any{"otp"}, "ext_id": "12345"}, &CAEPSessionEstablished{FingerprintUserAgent: "abb0b6e7da81a42233f8f2b1a8ddb1b9a4c81611", ACR: "AAL2", AMR: []string{"otp"}, ExternalID: "12345"}},
			{SecurityEventTypeCAEPSessionPresented, map[string]any{"fp_ua": "abb0b6e7da81a42233f8f2b1a8ddb1b9a4c81611", "ext_id": "12345"}, &CAEPSessionPresented{FingerprintUserAgent: "abb0b6e7da81a42233f8f2b1a8ddb1b9a4c81611", ExternalID: "12345"}},
			{SecurityEventTypeCAEPRiskLevelChange, map[string]any{"principal": "USER", "current_level": "LOW", "previous_level": "HIGH", "risk_reason": "PASSWORD_FOUND_IN_DATA_BREACH"}, &CAEPRiskLevelChange{Principal: "USER", CurrentLevel: CAEPRiskLevelLow, PreviousLevel: CAEPRiskLevelHigh, RiskReason: "PASSWORD_FOUND_IN_DATA_BREACH"}},
			{SecurityEventTypeSSFVerification, map[string]any{"state": state}, &SSFVerification{State: &state}},
			{SecurityEventTypeSSFStreamUpdated, map[string]any{"status": "paused", "reason": "License is not valid"}, &SSFStreamUpdated{Status: SSFStreamStatusPaused, Reason: "License is not valid"}},
			{SecurityEventTypeRISCAccountCredentialChangeRequired, map[string]any{}, &RISCAccountCredentialChangeRequired{}},
			{SecurityEventTypeRISCAccountPurged, map[string]any{}, &RISCAccountPurged{}},
			{SecurityEventTypeRISCAccountDisabled, map[string]any{"reason": "hijacking"}, &RISCAccountDisabled{Reason: RISCAccountDisabledReasonHijacking}},
			{SecurityEventTypeRISCAccountEnabled, map[string]any{}, &RISCAccountEnabled{}},
			{SecurityEventTypeRISCIdentifierChanged, map[string]any{"new-value": "john.roe@example.com"}, &RISCIdentifierChanged{NewValue: "john.roe@example.com"}},
			{SecurityEventTypeRISCIdentifierRecycled, nil, &RISCIdentifierRecycled{}},
			{SecurityEventTypeRISCCredentialCompromise, map[string]any{"credential_type": "password", "event_timestamp": json.Number("1615304991")}, &RISCCredentialCompromise{CredentialType: "password", EventTimestamp: 1615304991}},
			{SecurityEventTypeRISCOptIn, map[string]any{}, &RISCOptIn{}},
			{SecurityEventTypeRISCOptOutInitiated, map[string]any{}, &RISCOptOutInitiated{}},
			{SecurityEventTypeRISCOptOutCancelled, map[string]any{}, &RISCOptOutCancelled{}},
			{SecurityEventTypeRISCOptOutEffective, map[string]any{}, &RISCOptOutEffective{}},
			{SecurityEventTypeRISCRecoveryActivated, map[string]any{}, &RISCRecoveryActivated{}},
			{SecurityEventTypeRISCRecoveryInformationChanged, map[string]any{}, &RISCRecoveryInformationChanged{}},
		}

		seen := map[string]struct{}{}

		for _, tc := range testCases {
			seen[tc.uri] = struct{}{}

			t.Run(tc.uri, func(t *testing.T) {
				actual, err := DecodeSecurityEvent(tc.uri, tc.payload)

				require.NoError(t, err)
				assert.Equal(t, tc.expected, actual)
				assert.Equal(t, tc.uri, actual.SecurityEventType())
			})
		}

		for uri := range securityEventTypes {
			if uri == SecurityEventTypeRISCSessionsRevoked {
				continue
			}

			assert.Contains(t, seen, uri)
		}
	})

	t.Run("ShouldKeepIntegerPrecisionOfTokenClaims", func(t *testing.T) {
		payload := map[string]any{"claims": map[string]any{
			"account_id": json.Number("9007199254740993"), "groups": []any{json.Number("9007199254740995")}, "ratio": json.Number("1.5"),
			"decimal": json.Number("9007199254740993.0"), "exponent": json.Number("90071992547409.93e2"), "small": json.Number("1E-2"),
		}}

		actual, err := DecodeSecurityEvent(SecurityEventTypeCAEPTokenClaimsChange, payload)

		require.NoError(t, err)
		assert.Equal(t, &CAEPTokenClaimsChange{Claims: map[string]any{
			"account_id": int64(9007199254740993), "groups": []any{int64(9007199254740995)}, "ratio": 1.5,
			"decimal": int64(9007199254740993), "exponent": int64(9007199254740993), "small": 0.01,
		}}, actual)
	})

	t.Run("ShouldReturnRawForUnknownType", func(t *testing.T) {
		payload := map[string]any{"change_type": "rotate", "count": json.Number("9007199254740993")}

		actual, err := DecodeSecurityEvent("https://example.com/event", payload)

		require.NoError(t, err)
		assert.Equal(t, RawSecurityEvent{URI: "https://example.com/event", Claims: map[string]any{"change_type": "rotate", "count": json.Number("9007199254740993")}}, actual)

		payload["change_type"] = "mutated"

		assert.Equal(t, "rotate", actual.(RawSecurityEvent).Claims["change_type"])
	})

	t.Run("ShouldReturnRawForRISCSessionsRevoked", func(t *testing.T) {
		actual, err := DecodeSecurityEvent(SecurityEventTypeRISCSessionsRevoked, map[string]any{})

		require.NoError(t, err)
		assert.Equal(t, RawSecurityEvent{URI: SecurityEventTypeRISCSessionsRevoked, Claims: map[string]any{}}, actual)
	})

	t.Run("ShouldKeepFractionalEventTimestamp", func(t *testing.T) {
		testCases := []struct {
			name     string
			uri      string
			payload  map[string]any
			expected SecurityEvent
		}{
			{"Float", SecurityEventTypeCAEPSessionRevoked, map[string]any{"event_timestamp": 1615304991.643}, &CAEPSessionRevoked{SecurityEventCommon{EventTimestamp: 1615304991}}},
			{"NumberLiteral", SecurityEventTypeCAEPSessionRevoked, map[string]any{"event_timestamp": json.Number("1615304991.643")}, &CAEPSessionRevoked{SecurityEventCommon{EventTimestamp: 1615304991}}},
			{"Exponent", SecurityEventTypeCAEPSessionRevoked, map[string]any{"event_timestamp": json.Number("1.615304991e9")}, &CAEPSessionRevoked{SecurityEventCommon{EventTimestamp: 1615304991}}},
			{"FractionWhichRoundsUp", SecurityEventTypeCAEPSessionRevoked, map[string]any{"event_timestamp": json.Number("1700000000.999999999")}, &CAEPSessionRevoked{SecurityEventCommon{EventTimestamp: 1700000000}}},
			{"NegativeFraction", SecurityEventTypeCAEPSessionRevoked, map[string]any{"event_timestamp": json.Number("-1.9")}, &CAEPSessionRevoked{SecurityEventCommon{EventTimestamp: -1}}},
			{"FractionPastTheExponentBound", SecurityEventTypeCAEPSessionRevoked, map[string]any{"event_timestamp": json.Number("199999999999999999" + strings.Repeat("0", 984) + "e-1001")}, &CAEPSessionRevoked{SecurityEventCommon{EventTimestamp: 1}}},
			{"ExponentBelowAnyDigit", SecurityEventTypeCAEPSessionRevoked, map[string]any{"event_timestamp": json.Number("-5e-99999999999999999999")}, &CAEPSessionRevoked{}},
			{"ZeroWithLargeExponent", SecurityEventTypeCAEPSessionRevoked, map[string]any{"event_timestamp": json.Number("0.0e99999")}, &CAEPSessionRevoked{}},
			{"LargestInt64WithFraction", SecurityEventTypeCAEPSessionRevoked, map[string]any{"event_timestamp": json.Number("9223372036854775807.9")}, &CAEPSessionRevoked{SecurityEventCommon{EventTimestamp: 9223372036854775807}}},
			{"OutOfRangeWithFraction", SecurityEventTypeCAEPSessionRevoked, map[string]any{"event_timestamp": json.Number("9223372036854775808.5")}, &CAEPSessionRevoked{}},
			{"OutOfRangeExponent", SecurityEventTypeCAEPSessionRevoked, map[string]any{"event_timestamp": json.Number("1e99999999999999999999")}, &CAEPSessionRevoked{}},
			{"Integer", SecurityEventTypeCAEPSessionRevoked, map[string]any{"event_timestamp": int64(1615304991)}, &CAEPSessionRevoked{SecurityEventCommon{EventTimestamp: 1615304991}}},
			{"RISC", SecurityEventTypeRISCCredentialCompromise, map[string]any{"credential_type": "password", "event_timestamp": 1615304991.5}, &RISCCredentialCompromise{CredentialType: "password", EventTimestamp: 1615304991}},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				have := tc.payload["event_timestamp"]

				actual, err := DecodeSecurityEvent(tc.uri, tc.payload)

				require.NoError(t, err)
				assert.Equal(t, tc.expected, actual)
				assert.Equal(t, have, tc.payload["event_timestamp"])
			})
		}
	})

	t.Run("ShouldIgnoreUnknownMembers", func(t *testing.T) {
		actual, err := DecodeSecurityEvent(SecurityEventTypeCAEPCredentialChange, map[string]any{"credential_type": "password", "change_type": "update", "https://example.com/extra": map[string]any{"a": true}, "extra": 5})

		require.NoError(t, err)
		assert.Equal(t, &CAEPCredentialChange{CredentialType: CAEPCredentialTypePassword, ChangeType: CAEPChangeTypeUpdate}, actual)
	})

	t.Run("ShouldRejectInvalidKnownPayload", func(t *testing.T) {
		testCases := []struct {
			name    string
			uri     string
			payload map[string]any
			err     string
		}{
			{"MissingRequiredMember", SecurityEventTypeCAEPCredentialChange, map[string]any{"change_type": "create"}, "credential_type"},
			{"BadValue", SecurityEventTypeCAEPCredentialChange, map[string]any{"credential_type": "password", "change_type": "rotate"}, "change_type"},
			{"BadMemberType", SecurityEventTypeCAEPSessionRevoked, map[string]any{"reason_admin": "Policy"}, "session-revoked"},
			{"StringTimestamp", SecurityEventTypeCAEPSessionRevoked, map[string]any{"event_timestamp": "now"}, "session-revoked"},
			{"NullTimestamp", SecurityEventTypeCAEPSessionRevoked, map[string]any{"event_timestamp": nil}, "event_timestamp"},
			{"EmptyReason", SecurityEventTypeCAEPSessionRevoked, map[string]any{"reason_user": map[string]any{}}, "reason_user"},
			{"MissingStatus", SecurityEventTypeSSFStreamUpdated, map[string]any{}, "status"},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				actual, err := DecodeSecurityEvent(tc.uri, tc.payload)

				require.ErrorIs(t, err, ErrInvalidSecurityEvent)
				assert.ErrorContains(t, err, tc.err)
				assert.Nil(t, actual)
			})
		}
	})
}
