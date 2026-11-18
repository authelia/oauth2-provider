// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package jwt_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	. "authelia.com/provider/oauth2/token/jwt"
)

func TestRISCSecurityEventTypes(t *testing.T) {
	testCases := []struct {
		name     string
		event    SecurityEvent
		uri      string
		expected string
		err      string
	}{
		{"AccountCredentialChangeRequired", &RISCAccountCredentialChangeRequired{}, riscEventType + "account-credential-change-required", `{}`, ""},
		{"AccountPurged", &RISCAccountPurged{}, riscEventType + "account-purged", `{}`, ""},
		{"AccountDisabled", &RISCAccountDisabled{}, riscEventType + "account-disabled", `{}`, ""},
		{"AccountDisabledHijacking", &RISCAccountDisabled{Reason: RISCAccountDisabledReasonHijacking}, riscEventType + "account-disabled", `{"reason":"hijacking"}`, ""},
		{"AccountDisabledBulkAccount", &RISCAccountDisabled{Reason: RISCAccountDisabledReasonBulkAccount}, riscEventType + "account-disabled", `{"reason":"bulk-account"}`, ""},
		{"AccountDisabledBadReason", &RISCAccountDisabled{Reason: "nope"}, riscEventType + "account-disabled", `{"reason":"nope"}`, "reason"},
		{"AccountEnabled", &RISCAccountEnabled{}, riscEventType + "account-enabled", `{}`, ""},
		{"IdentifierChanged", &RISCIdentifierChanged{}, riscEventType + "identifier-changed", `{}`, ""},
		{"IdentifierChangedNewValue", &RISCIdentifierChanged{NewValue: "john.roe@example.com"}, riscEventType + "identifier-changed", `{"new-value":"john.roe@example.com"}`, ""},
		{"IdentifierRecycled", &RISCIdentifierRecycled{}, riscEventType + "identifier-recycled", `{}`, ""},
		{"CredentialCompromise", &RISCCredentialCompromise{CredentialType: CAEPCredentialTypePassword}, riscEventType + "credential-compromise", `{"credential_type":"password"}`, ""},
		{"CredentialCompromiseAllMembers", &RISCCredentialCompromise{CredentialType: "custom", EventTimestamp: 1508184845, ReasonAdmin: map[string]string{"en": "Leaked"}, ReasonUser: map[string]string{"en-AU": "Change it"}}, riscEventType + "credential-compromise", `{"credential_type":"custom","event_timestamp":1508184845,"reason_admin":{"en":"Leaked"},"reason_user":{"en-AU":"Change it"}}`, ""},
		{"CredentialCompromiseNoType", &RISCCredentialCompromise{}, riscEventType + "credential-compromise", `{"credential_type":""}`, "credential_type"},
		{"CredentialCompromiseBadAdminTag", &RISCCredentialCompromise{CredentialType: "pin", ReasonAdmin: map[string]string{"": "Leaked"}}, riscEventType + "credential-compromise", `{"credential_type":"pin","reason_admin":{"":"Leaked"}}`, "reason_admin"},
		{"CredentialCompromiseBadUserTag", &RISCCredentialCompromise{CredentialType: "pin", ReasonUser: map[string]string{"not a tag!": "Leaked"}}, riscEventType + "credential-compromise", `{"credential_type":"pin","reason_user":{"not a tag!":"Leaked"}}`, "reason_user"},
		{"OptIn", &RISCOptIn{}, riscEventType + "opt-in", `{}`, ""},
		{"OptOutInitiated", &RISCOptOutInitiated{}, riscEventType + "opt-out-initiated", `{}`, ""},
		{"OptOutCancelled", &RISCOptOutCancelled{}, riscEventType + "opt-out-cancelled", `{}`, ""},
		{"OptOutEffective", &RISCOptOutEffective{}, riscEventType + "opt-out-effective", `{}`, ""},
		{"RecoveryActivated", &RISCRecoveryActivated{}, riscEventType + "recovery-activated", `{}`, ""},
		{"RecoveryInformationChanged", &RISCRecoveryInformationChanged{}, riscEventType + "recovery-information-changed", `{}`, ""},
	}

	subject, err := NewSubjectIdentifierEmail("john.doe@example.com")
	require.NoError(t, err)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.uri, tc.event.SecurityEventType())

			data, err := json.Marshal(tc.event)
			require.NoError(t, err)
			assert.JSONEq(t, tc.expected, string(data))

			claims, err := NewSecurityEventTokenClaims("https://idp.example.com/", []string{"636C69656E745F6964"}, subject, tc.event, "")

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

func TestSecurityEventTypesRISC(t *testing.T) {
	expected := []string{
		riscEventType + "account-credential-change-required",
		riscEventType + "account-purged",
		riscEventType + "account-disabled",
		riscEventType + "account-enabled",
		riscEventType + "identifier-changed",
		riscEventType + "identifier-recycled",
		riscEventType + "credential-compromise",
		riscEventType + "opt-in",
		riscEventType + "opt-out-initiated",
		riscEventType + "opt-out-cancelled",
		riscEventType + "opt-out-effective",
		riscEventType + "recovery-activated",
		riscEventType + "recovery-information-changed",
	}

	actual := SecurityEventTypesRISC()

	assert.Equal(t, expected, actual)

	actual[0] = "changed"

	assert.Equal(t, expected, SecurityEventTypesRISC())
}

func TestCAEPCredentialTypes(t *testing.T) {
	assert.Equal(t,
		[]string{"password", "pin", "x509", "fido2-platform", "fido2-roaming", "fido-u2f", "verifiable-credential", "phone-voice", "phone-sms", "app"},
		[]string{CAEPCredentialTypePassword, CAEPCredentialTypePIN, CAEPCredentialTypeX509, CAEPCredentialTypeFIDO2Platform, CAEPCredentialTypeFIDO2Roaming, CAEPCredentialTypeFIDOU2F, CAEPCredentialTypeVerifiableCredential, CAEPCredentialTypePhoneVoice, CAEPCredentialTypePhoneSMS, CAEPCredentialTypeApp},
	)
}

func TestRISCIdentifierEventSubjects(t *testing.T) {
	email := &SubjectIdentifier{Format: SubjectIdentifierFormatEmail, Email: "john.doe@example.com"}
	phone := &SubjectIdentifier{Format: SubjectIdentifierFormatPhoneNumber, PhoneNumber: "+12065550100"}
	issuerSubject := &SubjectIdentifier{Format: SubjectIdentifierFormatIssuerSubject, Issuer: "https://idp.example.com/", Subject: "7375626A656374"}
	opaque := &SubjectIdentifier{Format: SubjectIdentifierFormatOpaque, ID: "abc"}
	aliases := &SubjectIdentifier{Format: SubjectIdentifierFormatAliases, Identifiers: []SubjectIdentifier{*email, *phone}}
	complexUser := &SubjectIdentifier{Format: SubjectIdentifierFormatComplex, SubjectIdentifierComplexMembers: SubjectIdentifierComplexMembers{User: email}}

	testCases := []struct {
		name    string
		event   SecurityEvent
		subject *SubjectIdentifier
		err     string
	}{
		{"ShouldAcceptChangedEmail", &RISCIdentifierChanged{NewValue: "john.roe@example.com"}, email, ""},
		{"ShouldAcceptChangedPhoneNumber", &RISCIdentifierChanged{}, phone, ""},
		{"ShouldRejectChangedIssuerSubject", &RISCIdentifierChanged{}, issuerSubject, "'iss_sub'"},
		{"ShouldRejectChangedOpaque", &RISCIdentifierChanged{}, opaque, "'opaque'"},
		{"ShouldRejectChangedAliases", &RISCIdentifierChanged{}, aliases, "'aliases'"},
		{"ShouldRejectChangedComplex", &RISCIdentifierChanged{}, complexUser, "'complex'"},
		{"ShouldAcceptRecycledEmail", &RISCIdentifierRecycled{}, email, ""},
		{"ShouldAcceptRecycledPhoneNumber", &RISCIdentifierRecycled{}, phone, ""},
		{"ShouldRejectRecycledIssuerSubject", &RISCIdentifierRecycled{}, issuerSubject, "'iss_sub'"},
		{"ShouldRejectRecycledOpaque", &RISCIdentifierRecycled{}, opaque, "'opaque'"},
		{"ShouldAcceptRawChangedEmail", RawSecurityEvent{URI: riscEventType + "identifier-changed", Claims: map[string]any{"new-value": "john.roe@example.com"}}, email, ""},
		{"ShouldRejectRawChangedIssuerSubject", RawSecurityEvent{URI: riscEventType + "identifier-changed"}, issuerSubject, "'iss_sub'"},
		{"ShouldAcceptRawRecycledPhoneNumber", RawSecurityEvent{URI: riscEventType + "identifier-recycled"}, phone, ""},
		{"ShouldRejectRawRecycledOpaque", RawSecurityEvent{URI: riscEventType + "identifier-recycled"}, opaque, "'opaque'"},
		{"ShouldNotRestrictOtherEvents", &RISCAccountPurged{}, issuerSubject, ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			claims, err := NewSecurityEventTokenClaims("https://idp.example.com/", []string{"636C69656E745F6964"}, tc.subject, tc.event, "")

			if tc.err == "" {
				require.NoError(t, err)
				assert.NoError(t, claims.Valid())

				return
			}

			assert.Nil(t, claims)
			require.ErrorIs(t, err, ErrInvalidSecurityEvent)
			assert.Contains(t, err.Error(), tc.err)
			assert.Contains(t, err.Error(), tc.event.SecurityEventType())
		})
	}

	t.Run("ShouldRejectInValid", func(t *testing.T) {
		claims, err := NewSecurityEventTokenClaims("https://idp.example.com/", []string{"636C69656E745F6964"}, email, &RISCIdentifierRecycled{}, "")
		require.NoError(t, err)

		claims.SubjectIdentifier = opaque

		var vErr *ValidationError

		require.ErrorAs(t, claims.Valid(), &vErr)
		assert.Equal(t, ValidationErrorClaimsInvalid, vErr.Errors)
		assert.ErrorIs(t, vErr.Inner, ErrInvalidSecurityEvent)
	})

	t.Run("ShouldRejectNilSubject", func(t *testing.T) {
		assert.ErrorIs(t, RISCIdentifierChanged{}.ValidateSubject(nil), ErrInvalidSecurityEvent)
		assert.ErrorIs(t, RISCIdentifierRecycled{}.ValidateSubject(nil), ErrInvalidSecurityEvent)
	})
}

func TestRISCSessionsRevokedRefused(t *testing.T) {
	const uri = riscEventType + "sessions-revoked"

	subject, err := NewSubjectIdentifierIssuerSubject("https://idp.example.com/", "7375626A656374")
	require.NoError(t, err)

	testCases := []struct {
		name  string
		event SecurityEvent
	}{
		{"ShouldRefuseRawEvent", RawSecurityEvent{URI: uri}},
		{"ShouldRefuseRawEventPointer", &RawSecurityEvent{URI: uri, Claims: map[string]any{}}},
		{"ShouldRefuseCustomEvent", sessionsRevokedEvent{}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			claims, err := NewSecurityEventTokenClaims("https://idp.example.com/", []string{"636C69656E745F6964"}, subject, tc.event, "")

			assert.Nil(t, claims)
			require.ErrorIs(t, err, ErrInvalidSecurityEvent)
			assert.Contains(t, err.Error(), uri)
			assert.Contains(t, err.Error(), "deprecated")
			assert.Contains(t, err.Error(), SecurityEventTypeCAEPSessionRevoked)
		})
	}

	t.Run("ShouldRefuseInValid", func(t *testing.T) {
		claims, err := NewSecurityEventTokenClaims("https://idp.example.com/", []string{"636C69656E745F6964"}, subject, &CAEPSessionRevoked{}, "")
		require.NoError(t, err)
		require.NoError(t, claims.Valid())

		claims.Events = map[string]any{uri: map[string]any{}}

		var vErr *ValidationError

		require.ErrorAs(t, claims.Valid(), &vErr)
		assert.Equal(t, ValidationErrorClaimsInvalid, vErr.Errors)
		assert.ErrorIs(t, vErr.Inner, ErrInvalidSecurityEvent)
		assert.Contains(t, vErr.Inner.Error(), SecurityEventTypeCAEPSessionRevoked)
	})

	t.Run("ShouldNotListEventType", func(t *testing.T) {
		assert.NotContains(t, SecurityEventTypesRISC(), uri)
	})
}

func TestRISCRawSecurityEvents(t *testing.T) {
	testCases := []struct {
		name   string
		uri    string
		claims map[string]any
		err    string
	}{
		{"ShouldAcceptAccountCredentialChangeRequired", riscEventType + "account-credential-change-required", nil, ""},
		{"ShouldAcceptAccountDisabledWithoutReason", riscEventType + "account-disabled", map[string]any{}, ""},
		{"ShouldAcceptAccountDisabledHijacking", riscEventType + "account-disabled", map[string]any{"reason": "hijacking"}, ""},
		{"ShouldRejectAccountDisabledUnknownReason", riscEventType + "account-disabled", map[string]any{"reason": "nope"}, "reason"},
		{"ShouldRejectAccountDisabledReasonType", riscEventType + "account-disabled", map[string]any{"reason": 1}, "not valid"},
		{"ShouldAcceptCredentialCompromise", riscEventType + "credential-compromise", map[string]any{"credential_type": "password"}, ""},
		{"ShouldRejectCredentialCompromiseWithoutCredentialType", riscEventType + "credential-compromise", map[string]any{}, "credential_type"},
		{"ShouldRejectCredentialCompromiseStringReason", riscEventType + "credential-compromise", map[string]any{"credential_type": "password", "reason_admin": "Leaked"}, "not valid"},
		{"ShouldRejectCredentialCompromiseStringTimestamp", riscEventType + "credential-compromise", map[string]any{"credential_type": "password", "event_timestamp": "now"}, "not valid"},
		{"ShouldRejectCredentialCompromiseReasonTag", riscEventType + "credential-compromise", map[string]any{"credential_type": "password", "reason_user": map[string]any{"not a tag!": "Leaked"}}, "reason_user"},
	}

	subject, err := NewSubjectIdentifierIssuerSubject("https://idp.example.com/", "7375626A656374")
	require.NoError(t, err)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			claims, err := NewSecurityEventTokenClaims("https://idp.example.com/", []string{"636C69656E745F6964"}, subject, RawSecurityEvent{URI: tc.uri, Claims: tc.claims}, "")

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

const riscEventType = "https://schemas.openid.net/secevent/risc/event-type/"

type sessionsRevokedEvent struct{}

func (sessionsRevokedEvent) SecurityEventType() string { return riscEventType + "sessions-revoked" }
