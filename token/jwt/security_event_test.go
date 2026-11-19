// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package jwt_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	. "authelia.com/provider/oauth2/token/jwt"
)

func TestSecurityEventTypes(t *testing.T) {
	const (
		caep = "https://schemas.openid.net/secevent/caep/event-type/"
		ssf  = "https://schemas.openid.net/secevent/ssf/event-type/"
		risc = "https://schemas.openid.net/secevent/risc/event-type/"
	)

	testCases := []struct {
		name     string
		event    SecurityEvent
		uri      string
		expected string
		err      string
	}{
		{"SessionRevoked", &CAEPSessionRevoked{}, caep + "session-revoked", `{}`, ""},
		{"SessionRevokedCommon", &CAEPSessionRevoked{SecurityEventCommon: SecurityEventCommon{EventTimestamp: 1615304991, InitiatingEntity: SecurityEventInitiatingEntityPolicy, ReasonAdmin: map[string]string{"en": "Policy"}, ReasonUser: map[string]string{"en": "Denied"}}}, caep + "session-revoked", `{"event_timestamp":1615304991,"initiating_entity":"policy","reason_admin":{"en":"Policy"},"reason_user":{"en":"Denied"}}`, ""},
		{"SessionRevokedBadEntity", &CAEPSessionRevoked{SecurityEventCommon: SecurityEventCommon{InitiatingEntity: "robot"}}, caep + "session-revoked", `{"initiating_entity":"robot"}`, "initiating_entity"},
		{"TokenClaimsChange", &CAEPTokenClaimsChange{Claims: map[string]any{"trust_level": "0"}}, caep + "token-claims-change", `{"claims":{"trust_level":"0"}}`, ""},
		{"TokenClaimsChangeMissing", &CAEPTokenClaimsChange{}, caep + "token-claims-change", `{"claims":null}`, "claims"},
		{"CredentialChange", &CAEPCredentialChange{CredentialType: "fido2-roaming", ChangeType: "create", FriendlyName: "Key", X509Issuer: "CN=a", X509Serial: "1", FIDO2AAGUID: "g"}, caep + "credential-change", `{"credential_type":"fido2-roaming","change_type":"create","friendly_name":"Key","x509_issuer":"CN=a","x509_serial":"1","fido2_aaguid":"g"}`, ""},
		{"CredentialChangeNoType", &CAEPCredentialChange{ChangeType: "create"}, caep + "credential-change", `{"credential_type":"","change_type":"create"}`, "credential_type"},
		{"CredentialChangeBadChange", &CAEPCredentialChange{CredentialType: "password", ChangeType: "rotate"}, caep + "credential-change", `{"credential_type":"password","change_type":"rotate"}`, "change_type"},
		{"AssuranceLevelChange", &CAEPAssuranceLevelChange{Namespace: "NIST-AAL", CurrentLevel: "nist-aal2", PreviousLevel: "nist-aal1", ChangeDirection: "increase"}, caep + "assurance-level-change", `{"namespace":"NIST-AAL","current_level":"nist-aal2","previous_level":"nist-aal1","change_direction":"increase"}`, ""},
		{"AssuranceLevelChangeNoNamespace", &CAEPAssuranceLevelChange{CurrentLevel: "x"}, caep + "assurance-level-change", `{"namespace":"","current_level":"x"}`, "namespace"},
		{"AssuranceLevelChangeNoLevel", &CAEPAssuranceLevelChange{Namespace: "RFC8176"}, caep + "assurance-level-change", `{"namespace":"RFC8176","current_level":""}`, "current_level"},
		{"AssuranceLevelChangeBadDirection", &CAEPAssuranceLevelChange{Namespace: "RFC8176", CurrentLevel: "x", ChangeDirection: "sideways"}, caep + "assurance-level-change", `{"namespace":"RFC8176","current_level":"x","change_direction":"sideways"}`, "change_direction"},
		{"DeviceComplianceChange", &CAEPDeviceComplianceChange{PreviousStatus: "compliant", CurrentStatus: "not-compliant"}, caep + "device-compliance-change", `{"previous_status":"compliant","current_status":"not-compliant"}`, ""},
		{"DeviceComplianceChangeBadPrevious", &CAEPDeviceComplianceChange{PreviousStatus: "unknown", CurrentStatus: "compliant"}, caep + "device-compliance-change", `{"previous_status":"unknown","current_status":"compliant"}`, "previous_status"},
		{"DeviceComplianceChangeBadCurrent", &CAEPDeviceComplianceChange{PreviousStatus: "compliant"}, caep + "device-compliance-change", `{"previous_status":"compliant","current_status":""}`, "current_status"},
		{"SessionEstablished", &CAEPSessionEstablished{FingerprintUserAgent: "abb0", ACR: "AAL2", AMR: []string{"otp"}, ExternalID: "1"}, caep + "session-established", `{"fp_ua":"abb0","acr":"AAL2","amr":["otp"],"ext_id":"1"}`, ""},
		{"SessionPresented", &CAEPSessionPresented{FingerprintUserAgent: "abb0", ExternalID: "1"}, caep + "session-presented", `{"fp_ua":"abb0","ext_id":"1"}`, ""},
		{"RiskLevelChange", &CAEPRiskLevelChange{Principal: "USER", CurrentLevel: "LOW", PreviousLevel: "HIGH", RiskReason: "BREACH"}, caep + "risk-level-change", `{"risk_reason":"BREACH","principal":"USER","current_level":"LOW","previous_level":"HIGH"}`, ""},
		{"RiskLevelChangeNoPrincipal", &CAEPRiskLevelChange{CurrentLevel: "LOW"}, caep + "risk-level-change", `{"principal":"","current_level":"LOW"}`, "principal"},
		{"RiskLevelChangeBadCurrent", &CAEPRiskLevelChange{Principal: "USER", CurrentLevel: "low"}, caep + "risk-level-change", `{"principal":"USER","current_level":"low"}`, "current_level"},
		{"RiskLevelChangeBadPrevious", &CAEPRiskLevelChange{Principal: "USER", CurrentLevel: "LOW", PreviousLevel: "EXTREME"}, caep + "risk-level-change", `{"principal":"USER","current_level":"LOW","previous_level":"EXTREME"}`, "previous_level"},
		{"Verification", &SSFVerification{State: new("abc")}, ssf + "verification", `{"state":"abc"}`, ""},
		{"VerificationEmptyState", &SSFVerification{State: new("")}, ssf + "verification", `{"state":""}`, ""},
		{"VerificationNoState", &SSFVerification{}, ssf + "verification", `{}`, ""},
		{"StreamUpdated", &SSFStreamUpdated{Status: "paused", Reason: "Internal error"}, ssf + "stream-updated", `{"status":"paused","reason":"Internal error"}`, ""},
		{"StreamUpdatedNoStatus", &SSFStreamUpdated{}, ssf + "stream-updated", `{"status":""}`, "status"},
		{"StreamUpdatedBadStatus", &SSFStreamUpdated{Status: "gone"}, ssf + "stream-updated", `{"status":"gone"}`, "status"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.uri, tc.event.SecurityEventType())

			data, err := json.Marshal(tc.event)
			require.NoError(t, err)
			assert.JSONEq(t, tc.expected, string(data))

			v, ok := tc.event.(interface{ Validate() error })
			require.True(t, ok)

			err = v.Validate()
			if tc.err == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.ErrorIs(t, err, ErrInvalidSecurityEvent)
				assert.Contains(t, err.Error(), tc.err)
			}
		})
	}
}

func TestSecurityEventCommonReasonLanguageTags(t *testing.T) {
	subject, err := NewSubjectIdentifierEmail("john@example.com")
	require.NoError(t, err)

	testCases := []struct {
		name string
		tag  string
		err  bool
	}{
		{"ShouldAcceptLanguage", "en", false},
		{"ShouldAcceptLanguageRegion", "en-US", false},
		{"ShouldAcceptLanguageNumericRegion", "es-410", false},
		{"ShouldAcceptLanguageScriptRegion", "zh-Hant-TW", false},
		{"ShouldAcceptVariant", "de-CH-1996", false},
		{"ShouldAcceptExtension", "en-u-ca-gregory", false},
		{"ShouldAcceptPrivateUse", "x-private", false},
		{"ShouldAcceptGrandfathered", "i-klingon", false},
		{"ShouldAcceptAnyCase", "EN-us", false},
		{"ShouldAcceptWellFormedUnregistered", "qq-ZZ", false},
		{"ShouldRejectEmpty", "", true},
		{"ShouldRejectWords", "not a tag!", true},
		{"ShouldRejectPunctuation", "!!", true},
		{"ShouldRejectUnderscore", "en_US", true},
		{"ShouldRejectLeadingSpace", " en", true},
		{"ShouldRejectTrailingHyphen", "en-", true},
		{"ShouldRejectEmptySubtag", "en--US", true},
		{"ShouldRejectLongSubtag", "abcdefghi", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reasons := map[string]string{"en": "First", tc.tag: "Reason"}

			for claim, common := range map[string]SecurityEventCommon{
				"reason_admin": {ReasonAdmin: reasons},
				"reason_user":  {ReasonUser: reasons},
			} {
				err := common.Validate()

				_, cerr := NewSecurityEventTokenClaims("https://issuer.example.com", []string{"aud"}, subject, CAEPSessionRevoked{SecurityEventCommon: common}, "")

				if !tc.err {
					assert.NoError(t, err)
					assert.NoError(t, cerr)

					continue
				}

				require.ErrorIs(t, err, ErrInvalidSecurityEvent)
				assert.Contains(t, err.Error(), claim)
				assert.ErrorIs(t, cerr, ErrInvalidSecurityEvent)
			}
		})
	}
}

func TestRawSecurityEventKnownType(t *testing.T) {
	const (
		caep = "https://schemas.openid.net/secevent/caep/event-type/"
		ssf  = "https://schemas.openid.net/secevent/ssf/event-type/"
		risc = "https://schemas.openid.net/secevent/risc/event-type/"
	)

	testCases := []struct {
		name   string
		uri    string
		claims map[string]any
		err    string
	}{
		{"ShouldAcceptUnknownType", "https://example.com/event", map[string]any{"change_type": "rotate", "reason_admin": "text"}, ""},
		{"ShouldAcceptSessionRevoked", caep + "session-revoked", nil, ""},
		{"ShouldAcceptSessionRevokedCommon", caep + "session-revoked", map[string]any{"event_timestamp": 1615304991, "initiating_entity": "policy", "reason_admin": map[string]any{"en": "Policy"}}, ""},
		{"ShouldAcceptAdditionalMember", caep + "session-revoked", map[string]any{"https://example.com/extra": true}, ""},
		{"ShouldRejectSessionRevokedStringReason", caep + "session-revoked", map[string]any{"reason_admin": "Policy"}, "session-revoked"},
		{"ShouldRejectSessionRevokedBadReasonKey", caep + "session-revoked", map[string]any{"reason_user": map[string]any{"not a tag!": "x"}}, "reason_user"},
		{"ShouldRejectSessionRevokedBadEntity", caep + "session-revoked", map[string]any{"initiating_entity": "robot"}, "initiating_entity"},
		{"ShouldRejectSessionRevokedStringTimestamp", caep + "session-revoked", map[string]any{"event_timestamp": "now"}, "session-revoked"},
		{"ShouldAcceptSessionRevokedFractionalTimestamp", caep + "session-revoked", map[string]any{"event_timestamp": 1615304991.643}, ""},
		{"ShouldAcceptSessionRevokedNumberLiteralTimestamp", caep + "session-revoked", map[string]any{"event_timestamp": json.Number("1615304991.643")}, ""},
		{"ShouldAcceptCredentialChangeFractionalTimestamp", caep + "credential-change", map[string]any{"credential_type": "password", "change_type": "update", "event_timestamp": 1615304991.5}, ""},
		{"ShouldAcceptCredentialCompromiseFractionalTimestamp", risc + "credential-compromise", map[string]any{"credential_type": "password", "event_timestamp": 1615304991.5}, ""},
		{"ShouldRejectSessionRevokedBooleanTimestamp", caep + "session-revoked", map[string]any{"event_timestamp": true}, "session-revoked"},
		{"ShouldRejectSessionRevokedObjectTimestamp", caep + "session-revoked", map[string]any{"event_timestamp": map[string]any{"seconds": 1615304991}}, "session-revoked"},
		{"ShouldRejectSessionRevokedNumericStringTimestamp", caep + "session-revoked", map[string]any{"event_timestamp": "1615304991.643"}, "session-revoked"},
		{"ShouldRejectSessionRevokedNullTimestamp", caep + "session-revoked", map[string]any{"event_timestamp": nil}, "session-revoked"},
		{"ShouldRejectSessionRevokedEmptyReasonAdmin", caep + "session-revoked", map[string]any{"reason_admin": map[string]any{}}, "reason_admin"},
		{"ShouldRejectSessionRevokedEmptyReasonUser", caep + "session-revoked", map[string]any{"reason_user": map[string]any{}}, "reason_user"},
		{"ShouldRejectSessionRevokedEmptyTypedReasonAdmin", caep + "session-revoked", map[string]any{"reason_admin": map[string]string{}}, "reason_admin"},
		{"ShouldRejectCredentialChangeEmptyReasonUser", caep + "credential-change", map[string]any{"credential_type": "password", "change_type": "update", "reason_user": map[string]any{}}, "reason_user"},
		{"ShouldAcceptSessionRevokedReasonUserOnly", caep + "session-revoked", map[string]any{"reason_user": map[string]any{"en": "Policy"}}, ""},
		{"ShouldAcceptCredentialChange", caep + "credential-change", map[string]any{"credential_type": "password", "change_type": "update"}, ""},
		{"ShouldRejectCredentialChangeBadChangeType", caep + "credential-change", map[string]any{"credential_type": "password", "change_type": "rotate"}, "change_type"},
		{"ShouldRejectCredentialChangeMissingCredentialType", caep + "credential-change", map[string]any{"change_type": "create"}, "credential_type"},
		{"ShouldRejectCredentialChangeMemberCase", caep + "credential-change", map[string]any{"credential_type": "password", "Change_Type": "create"}, "change_type"},
		{"ShouldRejectCredentialChangeEmpty", caep + "credential-change", nil, "credential_type"},
		{"ShouldAcceptTokenClaimsChange", caep + "token-claims-change", map[string]any{"claims": map[string]any{"role": "ro-admin"}}, ""},
		{"ShouldRejectTokenClaimsChangeMissingClaims", caep + "token-claims-change", map[string]any{}, "claims"},
		{"ShouldRejectTokenClaimsChangeStringClaims", caep + "token-claims-change", map[string]any{"claims": "role"}, "token-claims-change"},
		{"ShouldRejectAssuranceLevelChangeBadDirection", caep + "assurance-level-change", map[string]any{"namespace": "NIST-AAL", "current_level": "nist-aal2", "change_direction": "sideways"}, "change_direction"},
		{"ShouldRejectDeviceComplianceChangeBadStatus", caep + "device-compliance-change", map[string]any{"previous_status": "compliant", "current_status": "unknown"}, "current_status"},
		{"ShouldAcceptSessionEstablished", caep + "session-established", map[string]any{"amr": []any{"otp"}, "acr": "AAL2"}, ""},
		{"ShouldRejectSessionEstablishedStringAMR", caep + "session-established", map[string]any{"amr": "otp"}, "session-established"},
		{"ShouldRejectSessionPresentedNumberExternalID", caep + "session-presented", map[string]any{"ext_id": 1}, "session-presented"},
		{"ShouldRejectRiskLevelChangeBadLevel", caep + "risk-level-change", map[string]any{"principal": "USER", "current_level": "low"}, "current_level"},
		{"ShouldAcceptVerification", ssf + "verification", map[string]any{"state": "abc"}, ""},
		{"ShouldRejectVerificationNumberState", ssf + "verification", map[string]any{"state": 1}, "verification"},
		{"ShouldAcceptStreamUpdated", ssf + "stream-updated", map[string]any{"status": "paused"}, ""},
		{"ShouldRejectStreamUpdatedBadStatus", ssf + "stream-updated", map[string]any{"status": "gone"}, "status"},
		{"ShouldRejectStreamUpdatedMissingStatus", ssf + "stream-updated", nil, "status"},
	}

	subject, err := NewSubjectIdentifierOpaque("abc")
	require.NoError(t, err)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for name, event := range map[string]SecurityEvent{
				"Value":   RawSecurityEvent{URI: tc.uri, Claims: tc.claims},
				"Pointer": &RawSecurityEvent{URI: tc.uri, Claims: tc.claims},
			} {
				t.Run(name, func(t *testing.T) {
					claims, err := NewSecurityEventTokenClaims("https://issuer.example.com", []string{"aud"}, subject, event, "")

					if tc.err != "" {
						assert.Nil(t, claims)
						require.ErrorIs(t, err, ErrInvalidSecurityEvent)
						assert.Contains(t, err.Error(), tc.err)

						return
					}

					require.NoError(t, err)
					require.NoError(t, claims.Valid())

					expected, err := json.Marshal(RawSecurityEvent{Claims: tc.claims})
					require.NoError(t, err)

					actual, err := json.Marshal(claims.Events[tc.uri])
					require.NoError(t, err)

					assert.JSONEq(t, string(expected), string(actual))
				})
			}
		})
	}
}

func TestSecurityEventSubjectValidator(t *testing.T) {
	email, err := NewSubjectIdentifierEmail("john@example.com")
	require.NoError(t, err)

	opaque, err := NewSubjectIdentifierOpaque("abc")
	require.NoError(t, err)

	testCases := []struct {
		name    string
		subject *SubjectIdentifier
		event   SecurityEvent
		err     bool
	}{
		{"ShouldAcceptPermittedSubject", email, emailOnlyEvent{}, false},
		{"ShouldAcceptPermittedSubjectPointer", email, &emailOnlyEvent{}, false},
		{"ShouldRejectOtherSubject", opaque, emailOnlyEvent{}, true},
		{"ShouldRejectOtherSubjectPointer", opaque, &emailOnlyEvent{}, true},
		{"ShouldNotRestrictOtherEvents", opaque, CAEPSessionRevoked{}, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			claims, err := NewSecurityEventTokenClaims("https://issuer.example.com", []string{"aud"}, tc.subject, tc.event, "")

			if tc.err {
				assert.Nil(t, claims)
				assert.ErrorIs(t, err, ErrInvalidSecurityEvent)
				assert.ErrorIs(t, err, errEmailOnly)

				return
			}

			require.NoError(t, err)
			assert.NoError(t, claims.Valid())
		})
	}
}

func TestSecurityEventTokenClaimsValidKnownType(t *testing.T) {
	subject, err := NewSubjectIdentifierOpaque("abc")
	require.NoError(t, err)

	testCases := []struct {
		name   string
		events map[string]any
		err    bool
	}{
		{"ShouldPassKnownType", map[string]any{SecurityEventTypeCAEPCredentialChange: map[string]any{"credential_type": "password", "change_type": "create"}}, false},
		{"ShouldPassUnknownType", map[string]any{"https://example.com/event": map[string]any{"change_type": "rotate"}}, false},
		{"ShouldFailKnownTypeBadValue", map[string]any{SecurityEventTypeCAEPCredentialChange: map[string]any{"credential_type": "password", "change_type": "rotate"}}, true},
		{"ShouldFailKnownTypeBadMemberType", map[string]any{SecurityEventTypeCAEPSessionRevoked: map[string]any{"reason_admin": "Policy"}}, true},
		{"ShouldFailKnownTypeMissingMember", map[string]any{SecurityEventTypeSSFStreamUpdated: map[string]any{}}, true},
		{"ShouldPassKnownTypeFractionalTimestamp", map[string]any{SecurityEventTypeCAEPSessionRevoked: map[string]any{"event_timestamp": 1615304991.643}}, false},
		{"ShouldPassKnownTypeIntegralTimestamp", map[string]any{SecurityEventTypeCAEPSessionRevoked: map[string]any{"event_timestamp": int64(1615304991)}}, false},
		{"ShouldFailKnownTypeStringTimestamp", map[string]any{SecurityEventTypeCAEPSessionRevoked: map[string]any{"event_timestamp": "1615304991"}}, true},
		{"ShouldFailKnownTypeNullTimestamp", map[string]any{SecurityEventTypeCAEPSessionRevoked: map[string]any{"event_timestamp": nil}}, true},
		{"ShouldFailKnownTypeEmptyReasonAdmin", map[string]any{SecurityEventTypeCAEPSessionRevoked: map[string]any{"reason_admin": map[string]any{}}}, true},
		{"ShouldFailKnownTypeEmptyReasonUser", map[string]any{SecurityEventTypeCAEPSessionRevoked: map[string]any{"reason_user": map[string]any{}}}, true},
		{"ShouldPassKnownTypeOmittedReasons", map[string]any{SecurityEventTypeCAEPSessionRevoked: map[string]any{"initiating_entity": "policy"}}, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			claims, err := NewSecurityEventTokenClaims("https://issuer.example.com", []string{"aud"}, subject, CAEPSessionRevoked{}, "")
			require.NoError(t, err)

			claims.Events = tc.events

			err = claims.Valid()

			if !tc.err {
				assert.NoError(t, err)

				return
			}

			var vErr *ValidationError

			require.ErrorAs(t, err, &vErr)
			assert.Equal(t, ValidationErrorClaimsInvalid, vErr.Errors)
			assert.ErrorIs(t, vErr.Inner, ErrInvalidSecurityEvent)
		})
	}
}

func TestSecurityEventURIConstants(t *testing.T) {
	assert.Equal(t, "https://schemas.openid.net/secevent/caep/event-type/session-revoked", SecurityEventTypeCAEPSessionRevoked)
	assert.Equal(t, "https://schemas.openid.net/secevent/ssf/event-type/stream-updated", SecurityEventTypeSSFStreamUpdated)
}

func TestRawSecurityEvent(t *testing.T) {
	raw := RawSecurityEvent{URI: "https://schemas.openid.net/secevent/risc/event-type/account-disabled", Claims: map[string]any{"reason": "hijacking"}}

	assert.Equal(t, raw.URI, raw.SecurityEventType())

	data, err := json.Marshal(raw)
	require.NoError(t, err)
	assert.JSONEq(t, `{"reason":"hijacking"}`, string(data))

	data, err = json.Marshal(&raw)
	require.NoError(t, err)
	assert.JSONEq(t, `{"reason":"hijacking"}`, string(data))

	data, err = json.Marshal(RawSecurityEvent{URI: "x"})
	require.NoError(t, err)
	assert.JSONEq(t, `{}`, string(data))
}

var errEmailOnly = errors.New("the subject must be an email")

type emailOnlyEvent struct{}

func (emailOnlyEvent) SecurityEventType() string { return "https://example.com/event/email-only" }

func (emailOnlyEvent) ValidateSubject(subject *SubjectIdentifier) error {
	if subject.Format != SubjectIdentifierFormatEmail {
		return errEmailOnly
	}

	return nil
}
