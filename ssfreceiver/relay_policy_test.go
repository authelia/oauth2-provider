// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package ssfreceiver

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2/token/jwt"
)

// riscSessionsRevoked is the deprecated RISC sessions revoked event type, which is received as a raw event.
const riscSessionsRevoked = "https://schemas.openid.net/secevent/risc/event-type/sessions-revoked"

// testRelayCommon returns the common claims of an upstream event, reasons included.
func testRelayCommon() jwt.SecurityEventCommon {
	return jwt.SecurityEventCommon{
		EventTimestamp:   1615304991,
		InitiatingEntity: jwt.SecurityEventInitiatingEntityPolicy,
		ReasonAdmin:      map[string]string{"en": "Upstream policy 7 violated by an operator"},
		ReasonUser:       map[string]string{"en": "Contact the upstream help desk"},
	}
}

// testRelayJSON returns the event as the object placed in the 'events' claim.
func testRelayJSON(t *testing.T, event jwt.SecurityEvent) string {
	t.Helper()

	data, err := json.Marshal(event)
	require.NoError(t, err)

	return string(data)
}

func TestSanitizeRelayEvent(t *testing.T) {
	replacement := map[string]string{"en": "Relayed by the authorization server"}

	testCases := []struct {
		name        string
		have        jwt.SecurityEvent
		reasonAdmin map[string]string
		expected    string
		err         error
	}{
		{
			name:     "ShouldKeepEventTimestamp",
			have:     &jwt.CAEPSessionRevoked{SecurityEventCommon: jwt.SecurityEventCommon{EventTimestamp: 1615304991}},
			expected: `{"event_timestamp":1615304991}`,
		},
		{
			name:     "ShouldNotInventEventTimestamp",
			have:     &jwt.CAEPSessionRevoked{},
			expected: `{}`,
		},
		{
			name:     "ShouldKeepInitiatingEntity",
			have:     &jwt.CAEPSessionRevoked{SecurityEventCommon: jwt.SecurityEventCommon{InitiatingEntity: jwt.SecurityEventInitiatingEntityAdmin}},
			expected: `{"initiating_entity":"admin"}`,
		},
		{
			name:     "ShouldDropReasons",
			have:     &jwt.CAEPSessionRevoked{SecurityEventCommon: testRelayCommon()},
			expected: `{"event_timestamp":1615304991,"initiating_entity":"policy"}`,
		},
		{
			name:        "ShouldUseConfiguredReasonAdmin",
			have:        &jwt.CAEPSessionRevoked{SecurityEventCommon: testRelayCommon()},
			reasonAdmin: replacement,
			expected:    `{"event_timestamp":1615304991,"initiating_entity":"policy","reason_admin":{"en":"Relayed by the authorization server"}}`,
		},
		{
			name:        "ShouldIgnoreEmptyConfiguredReasonAdmin",
			have:        &jwt.CAEPSessionRevoked{SecurityEventCommon: testRelayCommon()},
			reasonAdmin: map[string]string{},
			expected:    `{"event_timestamp":1615304991,"initiating_entity":"policy"}`,
		},
		{
			name:     "ShouldAcceptEventByValue",
			have:     jwt.CAEPSessionRevoked{SecurityEventCommon: testRelayCommon()},
			expected: `{"event_timestamp":1615304991,"initiating_entity":"policy"}`,
		},
		{
			name: "ShouldDropCredentialFingerprintMembers",
			have: &jwt.CAEPCredentialChange{
				SecurityEventCommon: testRelayCommon(),
				CredentialType:      jwt.CAEPCredentialTypeFIDO2Roaming,
				ChangeType:          jwt.CAEPChangeTypeCreate,
				FriendlyName:        "Jane's USB authenticator",
				X509Issuer:          "CN=Upstream CA",
				X509Serial:          "0a1b2c",
				FIDO2AAGUID:         "accced6a-63f5-490a-9eea-e59bc1896cfc",
			},
			expected: `{"event_timestamp":1615304991,"initiating_entity":"policy","credential_type":"fido2-roaming","change_type":"create"}`,
		},
		{
			name: "ShouldSanitizeAssuranceLevelChange",
			have: &jwt.CAEPAssuranceLevelChange{
				SecurityEventCommon: testRelayCommon(),
				Namespace:           "NIST-AAL",
				CurrentLevel:        "nist-aal2",
				PreviousLevel:       "nist-aal1",
				ChangeDirection:     jwt.CAEPChangeDirectionIncrease,
			},
			expected: `{"event_timestamp":1615304991,"initiating_entity":"policy","namespace":"NIST-AAL","current_level":"nist-aal2","previous_level":"nist-aal1","change_direction":"increase"}`,
		},
		{
			name: "ShouldSanitizeDeviceComplianceChange",
			have: &jwt.CAEPDeviceComplianceChange{
				SecurityEventCommon: testRelayCommon(),
				PreviousStatus:      jwt.CAEPDeviceComplianceCompliant,
				CurrentStatus:       jwt.CAEPDeviceComplianceNotCompliant,
			},
			expected: `{"event_timestamp":1615304991,"initiating_entity":"policy","previous_status":"compliant","current_status":"not-compliant"}`,
		},
		{
			name: "ShouldDropSessionEstablishedMembers",
			have: &jwt.CAEPSessionEstablished{
				SecurityEventCommon:  testRelayCommon(),
				FingerprintUserAgent: "abb0b6e7da81a42233f8f2b1a8ddb1b9a4c81611",
				ACR:                  "AAL2",
				AMR:                  []string{"otp"},
				ExternalID:           "12345",
			},
			expected: `{"event_timestamp":1615304991,"initiating_entity":"policy"}`,
		},
		{
			name: "ShouldDropSessionPresentedMembers",
			have: &jwt.CAEPSessionPresented{
				SecurityEventCommon:  testRelayCommon(),
				FingerprintUserAgent: "abb0b6e7da81a42233f8f2b1a8ddb1b9a4c81611",
				ExternalID:           "12345",
			},
			expected: `{"event_timestamp":1615304991,"initiating_entity":"policy"}`,
		},
		{
			name: "ShouldDropRiskReason",
			have: &jwt.CAEPRiskLevelChange{
				SecurityEventCommon: testRelayCommon(),
				RiskReason:          "PASSWORD_FOUND_IN_DATA_BREACH",
				Principal:           "USER",
				CurrentLevel:        jwt.CAEPRiskLevelHigh,
				PreviousLevel:       jwt.CAEPRiskLevelLow,
			},
			expected: `{"event_timestamp":1615304991,"initiating_entity":"policy","principal":"USER","current_level":"HIGH","previous_level":"LOW"}`,
		},
		{
			name:        "ShouldSanitizeAccountCredentialChangeRequired",
			have:        &jwt.RISCAccountCredentialChangeRequired{},
			reasonAdmin: replacement,
			expected:    `{}`,
		},
		{name: "ShouldSanitizeAccountPurged", have: &jwt.RISCAccountPurged{}, expected: `{}`},
		{
			name:     "ShouldKeepAccountDisabledReason",
			have:     &jwt.RISCAccountDisabled{Reason: jwt.RISCAccountDisabledReasonHijacking},
			expected: `{"reason":"hijacking"}`,
		},
		{name: "ShouldSanitizeAccountEnabled", have: &jwt.RISCAccountEnabled{}, expected: `{}`},
		{
			name:     "ShouldDropIdentifierChangedNewValue",
			have:     &jwt.RISCIdentifierChanged{NewValue: "new@example.com"},
			expected: `{}`,
		},
		{name: "ShouldSanitizeIdentifierRecycled", have: &jwt.RISCIdentifierRecycled{}, expected: `{}`},
		{
			name: "ShouldDropCredentialCompromiseReasons",
			have: &jwt.RISCCredentialCompromise{
				CredentialType: jwt.CAEPCredentialTypePassword,
				EventTimestamp: 1615304991,
				ReasonAdmin:    map[string]string{"en": "Found in an upstream breach corpus"},
				ReasonUser:     map[string]string{"en": "Contact the upstream help desk"},
			},
			expected: `{"credential_type":"password","event_timestamp":1615304991}`,
		},
		{
			name:        "ShouldUseConfiguredReasonAdminForCredentialCompromise",
			have:        jwt.RISCCredentialCompromise{CredentialType: jwt.CAEPCredentialTypePassword},
			reasonAdmin: replacement,
			expected:    `{"credential_type":"password","reason_admin":{"en":"Relayed by the authorization server"}}`,
		},
		{name: "ShouldSanitizeOptIn", have: &jwt.RISCOptIn{}, expected: `{}`},
		{name: "ShouldSanitizeOptOutInitiated", have: &jwt.RISCOptOutInitiated{}, expected: `{}`},
		{name: "ShouldSanitizeOptOutCancelled", have: &jwt.RISCOptOutCancelled{}, expected: `{}`},
		{name: "ShouldSanitizeOptOutEffective", have: &jwt.RISCOptOutEffective{}, expected: `{}`},
		{name: "ShouldSanitizeRecoveryActivated", have: &jwt.RISCRecoveryActivated{}, expected: `{}`},
		{name: "ShouldSanitizeRecoveryInformationChanged", have: &jwt.RISCRecoveryInformationChanged{}, expected: `{}`},
		{
			name: "ShouldRefuseTokenClaimsChange",
			have: &jwt.CAEPTokenClaimsChange{SecurityEventCommon: testRelayCommon(), Claims: map[string]any{"role": "admin"}},
			err:  ErrRelayEventNotSanitizable,
		},
		{
			name: "ShouldRefuseRawEvent",
			have: jwt.RawSecurityEvent{URI: "https://example.com/event-type/proprietary", Claims: map[string]any{"secret": "value"}},
			err:  ErrRelayEventNotSanitizable,
		},
		{
			name: "ShouldRefuseDeprecatedSessionsRevoked",
			have: jwt.RawSecurityEvent{URI: riscSessionsRevoked},
			err:  ErrRelayEventNotSanitizable,
		},
		{name: "ShouldRefuseVerification", have: &jwt.SSFVerification{}, err: ErrRelayEventNotSanitizable},
		{
			name: "ShouldRefuseStreamUpdated",
			have: &jwt.SSFStreamUpdated{Status: jwt.SSFStreamStatusPaused},
			err:  ErrRelayEventNotSanitizable,
		},
		{name: "ShouldRefuseNilEvent", err: ErrRelayEventNotSanitizable},
		{name: "ShouldRefuseNilPointerEvent", have: (*jwt.CAEPSessionRevoked)(nil), err: ErrRelayEventNotSanitizable},
		{
			name: "ShouldRefuseInvalidEvent",
			have: &jwt.CAEPCredentialChange{CredentialType: jwt.CAEPCredentialTypePassword, ChangeType: "rotate"},
			err:  jwt.ErrInvalidSecurityEvent,
		},
		{
			name:        "ShouldRefuseInvalidConfiguredReasonAdmin",
			have:        &jwt.CAEPSessionRevoked{},
			reasonAdmin: map[string]string{"not_a_tag": "Relayed"},
			err:         jwt.ErrInvalidSecurityEvent,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var before string

			if tc.err == nil {
				before = testRelayJSON(t, tc.have)
			}

			actual, err := SanitizeRelayEvent(tc.have, tc.reasonAdmin)

			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
				assert.Nil(t, actual)

				return
			}

			require.NoError(t, err)
			require.NotNil(t, actual)

			assert.Equal(t, tc.have.SecurityEventType(), actual.SecurityEventType())
			assert.JSONEq(t, tc.expected, testRelayJSON(t, actual))
			assert.Equal(t, before, testRelayJSON(t, tc.have))
		})
	}

	t.Run("ShouldNotAliasConfiguredReasonAdmin", func(t *testing.T) {
		reason := map[string]string{"en": "Relayed"}

		actual, err := SanitizeRelayEvent(&jwt.CAEPSessionRevoked{}, reason)
		require.NoError(t, err)

		reason["en"] = "Changed"

		assert.JSONEq(t, `{"reason_admin":{"en":"Relayed"}}`, testRelayJSON(t, actual))
	})

	t.Run("ShouldNotMutateInput", func(t *testing.T) {
		have := &jwt.CAEPSessionRevoked{SecurityEventCommon: testRelayCommon()}

		_, err := SanitizeRelayEvent(have, map[string]string{"en": "Relayed"})
		require.NoError(t, err)

		assert.Equal(t, testRelayCommon(), have.SecurityEventCommon)
	})

	// Every registered event type either has a rule or is refused, never passed through unsanitised.
	t.Run("ShouldCoverEveryRegisteredEventType", func(t *testing.T) {
		payloads := map[string]map[string]any{
			jwt.SecurityEventTypeCAEPSessionRevoked:         {},
			jwt.SecurityEventTypeCAEPCredentialChange:       {"credential_type": "password", "change_type": "update"},
			jwt.SecurityEventTypeCAEPAssuranceLevelChange:   {"namespace": "NIST-AAL", "current_level": "nist-aal2"},
			jwt.SecurityEventTypeCAEPDeviceComplianceChange: {"previous_status": "compliant", "current_status": "not-compliant"},
			jwt.SecurityEventTypeCAEPSessionEstablished:     {},
			jwt.SecurityEventTypeCAEPSessionPresented:       {},
			jwt.SecurityEventTypeCAEPRiskLevelChange:        {"principal": "USER", "current_level": "HIGH"},
			jwt.SecurityEventTypeRISCCredentialCompromise:   {"credential_type": "password"},
			jwt.SecurityEventTypeCAEPTokenClaimsChange:      {"claims": map[string]any{"role": "admin"}},
			jwt.SecurityEventTypeSSFVerification:            {},
			jwt.SecurityEventTypeSSFStreamUpdated:           {"status": "paused"},
			riscSessionsRevoked:                             {},
			"https://example.com/event-type/proprietary":    {"secret": "value"},
		}

		refused := []string{
			jwt.SecurityEventTypeCAEPTokenClaimsChange,
			jwt.SecurityEventTypeSSFVerification,
			jwt.SecurityEventTypeSSFStreamUpdated,
			riscSessionsRevoked,
			"https://example.com/event-type/proprietary",
		}

		for _, uri := range jwt.SecurityEventTypesRISC() {
			if _, ok := payloads[uri]; !ok {
				payloads[uri] = map[string]any{}
			}
		}

		for uri, payload := range payloads {
			payload["reason_admin"] = map[string]any{"en": "Upstream"}
			payload["reason_user"] = map[string]any{"en": "Upstream"}

			event, err := jwt.DecodeSecurityEvent(uri, payload)
			require.NoError(t, err, uri)

			actual, err := SanitizeRelayEvent(event, nil)
			if err != nil {
				assert.ErrorIs(t, err, ErrRelayEventNotSanitizable, uri)
				assert.Contains(t, refused, uri)

				continue
			}

			assert.NotContains(t, refused, uri)
			assert.Equal(t, uri, actual.SecurityEventType())
			assert.NotContains(t, testRelayJSON(t, actual), "reason_")
		}
	})
}

func TestRelayEventTypes(t *testing.T) {
	ctx := context.Background()

	t.Run("ShouldRelayListedTypeSanitized", func(t *testing.T) {
		policy := RelayEventTypes(jwt.SecurityEventTypeCAEPSessionRevoked, jwt.SecurityEventTypeCAEPCredentialChange)

		out, relay, err := policy(ctx, &RelayEvent{Event: &jwt.CAEPSessionRevoked{SecurityEventCommon: testRelayCommon()}}, map[string]string{"en": "Relayed"})

		require.NoError(t, err)
		assert.True(t, relay)
		assert.JSONEq(t, `{"event_timestamp":1615304991,"initiating_entity":"policy","reason_admin":{"en":"Relayed"}}`, testRelayJSON(t, out))
	})

	t.Run("ShouldNotRelayUnlistedType", func(t *testing.T) {
		policy := RelayEventTypes(jwt.SecurityEventTypeCAEPCredentialChange)

		out, relay, err := policy(ctx, &RelayEvent{Event: &jwt.CAEPSessionRevoked{}}, nil)

		require.NoError(t, err)
		assert.False(t, relay)
		assert.Nil(t, out)
	})

	t.Run("ShouldNotRelayWithoutTypes", func(t *testing.T) {
		out, relay, err := RelayEventTypes()(ctx, &RelayEvent{Event: &jwt.CAEPSessionRevoked{}}, nil)

		require.NoError(t, err)
		assert.False(t, relay)
		assert.Nil(t, out)
	})

	t.Run("ShouldNotRelayTokenClaimsChangeByDefault", func(t *testing.T) {
		policy := RelayEventTypes(jwt.SecurityEventTypeCAEPTokenClaimsChange)

		out, relay, err := policy(ctx, &RelayEvent{Event: &jwt.CAEPTokenClaimsChange{Claims: map[string]any{"role": "admin"}}}, nil)

		require.NoError(t, err)
		assert.False(t, relay)
		assert.Nil(t, out)
	})

	t.Run("ShouldNotRelayRawEventByDefault", func(t *testing.T) {
		uri := "https://example.com/event-type/proprietary"

		out, relay, err := RelayEventTypes(uri)(ctx, &RelayEvent{Event: jwt.RawSecurityEvent{URI: uri, Claims: map[string]any{"secret": "value"}}}, nil)

		require.NoError(t, err)
		assert.False(t, relay)
		assert.Nil(t, out)
	})

	t.Run("ShouldNotRelayStreamEvent", func(t *testing.T) {
		out, relay, err := RelayEventTypes(jwt.SecurityEventTypeSSFVerification)(ctx, &RelayEvent{Event: &jwt.SSFVerification{}}, nil)

		require.NoError(t, err)
		assert.False(t, relay)
		assert.Nil(t, out)
	})

	t.Run("ShouldNotRelayNilEvent", func(t *testing.T) {
		policy := RelayEventTypes(jwt.SecurityEventTypeCAEPSessionRevoked)

		for _, event := range []*RelayEvent{nil, {}, {Event: (*jwt.CAEPSessionRevoked)(nil)}} {
			out, relay, err := policy(ctx, event, nil)

			require.NoError(t, err)
			assert.False(t, relay)
			assert.Nil(t, out)
		}
	})

	t.Run("ShouldReturnInvalidEventError", func(t *testing.T) {
		policy := RelayEventTypes(jwt.SecurityEventTypeCAEPCredentialChange)

		out, relay, err := policy(ctx, &RelayEvent{Event: &jwt.CAEPCredentialChange{}}, nil)

		require.ErrorIs(t, err, jwt.ErrInvalidSecurityEvent)
		assert.False(t, relay)
		assert.Nil(t, out)
	})

	t.Run("ShouldNotAliasTypes", func(t *testing.T) {
		types := []string{jwt.SecurityEventTypeCAEPSessionRevoked}
		policy := RelayEventTypes(types...)

		types[0] = jwt.SecurityEventTypeCAEPCredentialChange

		_, relay, err := policy(ctx, &RelayEvent{Event: &jwt.CAEPSessionRevoked{}}, nil)

		require.NoError(t, err)
		assert.True(t, relay)
	})
}

func TestRelayPolicyDecide(t *testing.T) {
	ctx := context.Background()
	event := &RelayEvent{Event: &jwt.CAEPSessionRevoked{SecurityEventCommon: testRelayCommon()}}

	t.Run("ShouldRelayNothingWithoutPolicy", func(t *testing.T) {
		var policy RelayPolicy

		out, relay, err := policy.decide(ctx, event, map[string]string{"en": "Relayed"})

		require.NoError(t, err)
		assert.False(t, relay)
		assert.Nil(t, out)
	})

	t.Run("ShouldRelayPolicyReplacementEvent", func(t *testing.T) {
		replacement := &jwt.RISCAccountDisabled{}

		policy := RelayPolicy(func(_ context.Context, have *RelayEvent, reasonAdmin map[string]string) (jwt.SecurityEvent, bool, error) {
			assert.Equal(t, event, have)
			assert.NotSame(t, event, have)
			assert.Equal(t, map[string]string{"en": "Relayed"}, reasonAdmin)

			return replacement, true, nil
		})

		out, relay, err := policy.decide(ctx, event, map[string]string{"en": "Relayed"})

		require.NoError(t, err)
		assert.True(t, relay)
		assert.Same(t, replacement, out)
	})

	t.Run("ShouldNotReturnEventWhenPolicyDeclines", func(t *testing.T) {
		policy := RelayPolicy(func(_ context.Context, have *RelayEvent, _ map[string]string) (jwt.SecurityEvent, bool, error) {
			return have.Event, false, nil
		})

		out, relay, err := policy.decide(ctx, event, nil)

		require.NoError(t, err)
		assert.False(t, relay)
		assert.Nil(t, out)
	})

	t.Run("ShouldReturnPolicyError", func(t *testing.T) {
		bad := errors.New("policy failed")

		policy := RelayPolicy(func(context.Context, *RelayEvent, map[string]string) (jwt.SecurityEvent, bool, error) {
			return &jwt.CAEPSessionRevoked{}, true, bad
		})

		out, relay, err := policy.decide(ctx, event, nil)

		require.ErrorIs(t, err, bad)
		assert.False(t, relay)
		assert.Nil(t, out)
	})

	t.Run("ShouldRefuseRelayWithoutEvent", func(t *testing.T) {
		policy := RelayPolicy(func(context.Context, *RelayEvent, map[string]string) (jwt.SecurityEvent, bool, error) {
			return nil, true, nil
		})

		out, relay, err := policy.decide(ctx, event, nil)

		require.ErrorIs(t, err, ErrRelayPolicyEvent)
		assert.False(t, relay)
		assert.Nil(t, out)
	})

	t.Run("ShouldRefuseNilPointerReplacement", func(t *testing.T) {
		policy := RelayPolicy(func(context.Context, *RelayEvent, map[string]string) (jwt.SecurityEvent, bool, error) {
			return (*jwt.CAEPSessionRevoked)(nil), true, nil
		})

		out, relay, err := policy.decide(ctx, event, nil)

		require.ErrorIs(t, err, ErrRelayPolicyEvent)
		assert.False(t, relay)
		assert.Nil(t, out)
	})

	t.Run("ShouldNotAskPolicyWithoutEvent", func(t *testing.T) {
		policy := RelayPolicy(func(context.Context, *RelayEvent, map[string]string) (jwt.SecurityEvent, bool, error) {
			t.Fatal("the policy was asked")

			return nil, false, nil
		})

		for _, have := range []*RelayEvent{nil, {}, {Event: (*jwt.CAEPSessionRevoked)(nil)}} {
			out, relay, err := policy.decide(ctx, have, nil)

			require.NoError(t, err)
			assert.False(t, relay)
			assert.Nil(t, out)
		}
	})

	t.Run("ShouldNotAskPolicyForStreamEvent", func(t *testing.T) {
		policy := RelayPolicy(func(_ context.Context, have *RelayEvent, _ map[string]string) (jwt.SecurityEvent, bool, error) {
			t.Error("the policy was asked")

			return &jwt.CAEPSessionRevoked{}, true, nil
		})

		for _, have := range []jwt.SecurityEvent{
			&jwt.SSFVerification{},
			jwt.SSFVerification{},
			&jwt.SSFStreamUpdated{Status: jwt.SSFStreamStatusPaused},
			jwt.RawSecurityEvent{URI: jwt.SecurityEventTypeSSFStreamUpdated, Claims: map[string]any{}},
		} {
			out, relay, err := policy.decide(ctx, &RelayEvent{Event: have}, nil)

			require.NoError(t, err)
			assert.False(t, relay)
			assert.Nil(t, out)
		}
	})

	t.Run("ShouldRefuseStreamEventReplacement", func(t *testing.T) {
		policy := RelayPolicy(func(context.Context, *RelayEvent, map[string]string) (jwt.SecurityEvent, bool, error) {
			return &jwt.SSFStreamUpdated{Status: jwt.SSFStreamStatusDisabled}, true, nil
		})

		out, relay, err := policy.decide(ctx, event, nil)

		require.ErrorIs(t, err, ErrRelayPolicyEvent)
		assert.False(t, relay)
		assert.Nil(t, out)
	})
}
