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

func TestSecurityEventTypes(t *testing.T) {
	const (
		caep = "https://schemas.openid.net/secevent/caep/event-type/"
		ssf  = "https://schemas.openid.net/secevent/ssf/event-type/"
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
		{"Verification", &SSFVerification{State: "abc"}, ssf + "verification", `{"state":"abc"}`, ""},
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
