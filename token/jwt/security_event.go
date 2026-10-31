// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"encoding/json"
	"errors"
	"fmt"
)

const (
	SecurityEventTypeCAEPSessionRevoked         = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
	SecurityEventTypeCAEPTokenClaimsChange      = "https://schemas.openid.net/secevent/caep/event-type/token-claims-change"
	SecurityEventTypeCAEPCredentialChange       = "https://schemas.openid.net/secevent/caep/event-type/credential-change"
	SecurityEventTypeCAEPAssuranceLevelChange   = "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change"
	SecurityEventTypeCAEPDeviceComplianceChange = "https://schemas.openid.net/secevent/caep/event-type/device-compliance-change"
	SecurityEventTypeCAEPSessionEstablished     = "https://schemas.openid.net/secevent/caep/event-type/session-established"
	SecurityEventTypeCAEPSessionPresented       = "https://schemas.openid.net/secevent/caep/event-type/session-presented"
	SecurityEventTypeCAEPRiskLevelChange        = "https://schemas.openid.net/secevent/caep/event-type/risk-level-change"
	SecurityEventTypeSSFVerification            = "https://schemas.openid.net/secevent/ssf/event-type/verification"
	SecurityEventTypeSSFStreamUpdated           = "https://schemas.openid.net/secevent/ssf/event-type/stream-updated"
)

// The initiating_entity values (CAEP 1.0 §2).
const (
	SecurityEventInitiatingEntityAdmin  = "admin"
	SecurityEventInitiatingEntityUser   = "user"
	SecurityEventInitiatingEntityPolicy = "policy"
	SecurityEventInitiatingEntitySystem = "system"
)

// The change_type values (CAEP 1.0 §3.3.1).
const (
	CAEPChangeTypeCreate = "create"
	CAEPChangeTypeRevoke = "revoke"
	CAEPChangeTypeUpdate = "update"
	CAEPChangeTypeDelete = "delete"
)

// The change_direction values (CAEP 1.0 §3.4.1).
const (
	CAEPChangeDirectionIncrease = "increase"
	CAEPChangeDirectionDecrease = "decrease"
)

// The device compliance status values (CAEP 1.0 §3.5.1).
const (
	CAEPDeviceComplianceCompliant    = "compliant"
	CAEPDeviceComplianceNotCompliant = "not-compliant"
)

// The risk level values (CAEP 1.0 §3.8.1).
const (
	CAEPRiskLevelLow    = "LOW"
	CAEPRiskLevelMedium = "MEDIUM"
	CAEPRiskLevelHigh   = "HIGH"
)

// The stream status values (SSF 1.0 §8.1.2).
const (
	SSFStreamStatusEnabled  = "enabled"
	SSFStreamStatusPaused   = "paused"
	SSFStreamStatusDisabled = "disabled"
)

// ErrInvalidSecurityEvent is returned for an event payload that is missing a required claim or has an invalid value.
var ErrInvalidSecurityEvent = errors.New("invalid security event")

// SecurityEvent is the payload of one event in the events claim of a SET (RFC 8417 §2.2).
type SecurityEvent interface {
	SecurityEventType() (uri string)
}

// SecurityEventCommon are the optional claims shared by CAEP 1.0 events (CAEP 1.0 §2). Reasons are objects keyed by
// BCP47 language tag.
type SecurityEventCommon struct {
	EventTimestamp   int64             `json:"event_timestamp,omitempty"`
	InitiatingEntity string            `json:"initiating_entity,omitempty"`
	ReasonAdmin      map[string]string `json:"reason_admin,omitempty"`
	ReasonUser       map[string]string `json:"reason_user,omitempty"`
}

// Validate checks initiating_entity (CAEP 1.0 §2).
func (c SecurityEventCommon) Validate() (err error) {
	switch c.InitiatingEntity {
	case "", SecurityEventInitiatingEntityAdmin, SecurityEventInitiatingEntityUser, SecurityEventInitiatingEntityPolicy, SecurityEventInitiatingEntitySystem:
		return nil
	default:
		return securityEventInvalid("initiating_entity", c.InitiatingEntity)
	}
}

func securityEventInvalid(claim, value string) (err error) {
	return fmt.Errorf("%w: the '%s' claim value '%s' is not valid", ErrInvalidSecurityEvent, claim, value)
}

func securityEventRequire(claim, value string) (err error) {
	if value == "" {
		return fmt.Errorf("%w: the '%s' claim is required", ErrInvalidSecurityEvent, claim)
	}

	return nil
}

func securityEventOneOf(claim, value string, optional bool, allowed ...string) (err error) {
	if value == "" {
		if optional {
			return nil
		}

		return securityEventRequire(claim, value)
	}

	for _, a := range allowed {
		if value == a {
			return nil
		}
	}

	return securityEventInvalid(claim, value)
}

// CAEPSessionRevoked is the session-revoked event (CAEP 1.0 §3.1).
type CAEPSessionRevoked struct {
	SecurityEventCommon
}

func (CAEPSessionRevoked) SecurityEventType() (uri string) {
	return SecurityEventTypeCAEPSessionRevoked
}

// CAEPTokenClaimsChange is the token-claims-change event (CAEP 1.0 §3.2).
type CAEPTokenClaimsChange struct {
	SecurityEventCommon

	Claims map[string]any `json:"claims"`
}

func (CAEPTokenClaimsChange) SecurityEventType() (uri string) {
	return SecurityEventTypeCAEPTokenClaimsChange
}

// Validate requires claims (CAEP 1.0 §3.2.1).
func (e CAEPTokenClaimsChange) Validate() (err error) {
	if err = e.SecurityEventCommon.Validate(); err != nil {
		return err
	}

	if len(e.Claims) == 0 {
		return fmt.Errorf("%w: the 'claims' claim is required", ErrInvalidSecurityEvent)
	}

	return nil
}

// CAEPCredentialChange is the credential-change event (CAEP 1.0 §3.3).
type CAEPCredentialChange struct {
	SecurityEventCommon

	CredentialType string `json:"credential_type"`
	ChangeType     string `json:"change_type"`
	FriendlyName   string `json:"friendly_name,omitempty"`
	X509Issuer     string `json:"x509_issuer,omitempty"`
	X509Serial     string `json:"x509_serial,omitempty"`
	FIDO2AAGUID    string `json:"fido2_aaguid,omitempty"`
}

func (CAEPCredentialChange) SecurityEventType() (uri string) {
	return SecurityEventTypeCAEPCredentialChange
}

// Validate requires credential_type and change_type (CAEP 1.0 §3.3.1).
func (e CAEPCredentialChange) Validate() (err error) {
	if err = e.SecurityEventCommon.Validate(); err != nil {
		return err
	}

	if err = securityEventRequire("credential_type", e.CredentialType); err != nil {
		return err
	}

	return securityEventOneOf("change_type", e.ChangeType, false, CAEPChangeTypeCreate, CAEPChangeTypeRevoke, CAEPChangeTypeUpdate, CAEPChangeTypeDelete)
}

// CAEPAssuranceLevelChange is the assurance-level-change event (CAEP 1.0 §3.4).
type CAEPAssuranceLevelChange struct {
	SecurityEventCommon

	Namespace       string `json:"namespace"`
	CurrentLevel    string `json:"current_level"`
	PreviousLevel   string `json:"previous_level,omitempty"`
	ChangeDirection string `json:"change_direction,omitempty"`
}

func (CAEPAssuranceLevelChange) SecurityEventType() (uri string) {
	return SecurityEventTypeCAEPAssuranceLevelChange
}

// Validate requires namespace and current_level (CAEP 1.0 §3.4.1).
func (e CAEPAssuranceLevelChange) Validate() (err error) {
	if err = e.SecurityEventCommon.Validate(); err != nil {
		return err
	}

	if err = securityEventRequire("namespace", e.Namespace); err != nil {
		return err
	}

	if err = securityEventRequire("current_level", e.CurrentLevel); err != nil {
		return err
	}

	return securityEventOneOf("change_direction", e.ChangeDirection, true, CAEPChangeDirectionIncrease, CAEPChangeDirectionDecrease)
}

// CAEPDeviceComplianceChange is the device-compliance-change event (CAEP 1.0 §3.5).
type CAEPDeviceComplianceChange struct {
	SecurityEventCommon

	PreviousStatus string `json:"previous_status"`
	CurrentStatus  string `json:"current_status"`
}

func (CAEPDeviceComplianceChange) SecurityEventType() (uri string) {
	return SecurityEventTypeCAEPDeviceComplianceChange
}

// Validate requires previous_status and current_status (CAEP 1.0 §3.5.1).
func (e CAEPDeviceComplianceChange) Validate() (err error) {
	if err = e.SecurityEventCommon.Validate(); err != nil {
		return err
	}

	if err = securityEventOneOf("previous_status", e.PreviousStatus, false, CAEPDeviceComplianceCompliant, CAEPDeviceComplianceNotCompliant); err != nil {
		return err
	}

	return securityEventOneOf("current_status", e.CurrentStatus, false, CAEPDeviceComplianceCompliant, CAEPDeviceComplianceNotCompliant)
}

// CAEPSessionEstablished is the session-established event (CAEP 1.0 §3.6).
type CAEPSessionEstablished struct {
	SecurityEventCommon

	FingerprintUserAgent string   `json:"fp_ua,omitempty"`
	ACR                  string   `json:"acr,omitempty"`
	AMR                  []string `json:"amr,omitempty"`
	ExternalID           string   `json:"ext_id,omitempty"`
}

func (CAEPSessionEstablished) SecurityEventType() (uri string) {
	return SecurityEventTypeCAEPSessionEstablished
}

// CAEPSessionPresented is the session-presented event (CAEP 1.0 §3.7).
type CAEPSessionPresented struct {
	SecurityEventCommon

	FingerprintUserAgent string `json:"fp_ua,omitempty"`
	ExternalID           string `json:"ext_id,omitempty"`
}

func (CAEPSessionPresented) SecurityEventType() (uri string) {
	return SecurityEventTypeCAEPSessionPresented
}

// CAEPRiskLevelChange is the risk-level-change event (CAEP 1.0 §3.8).
type CAEPRiskLevelChange struct {
	SecurityEventCommon

	RiskReason    string `json:"risk_reason,omitempty"`
	Principal     string `json:"principal"`
	CurrentLevel  string `json:"current_level"`
	PreviousLevel string `json:"previous_level,omitempty"`
}

func (CAEPRiskLevelChange) SecurityEventType() (uri string) {
	return SecurityEventTypeCAEPRiskLevelChange
}

// Validate requires principal and current_level (CAEP 1.0 §3.8.1).
func (e CAEPRiskLevelChange) Validate() (err error) {
	if err = e.SecurityEventCommon.Validate(); err != nil {
		return err
	}

	if err = securityEventRequire("principal", e.Principal); err != nil {
		return err
	}

	if err = securityEventOneOf("current_level", e.CurrentLevel, false, CAEPRiskLevelLow, CAEPRiskLevelMedium, CAEPRiskLevelHigh); err != nil {
		return err
	}

	return securityEventOneOf("previous_level", e.PreviousLevel, true, CAEPRiskLevelLow, CAEPRiskLevelMedium, CAEPRiskLevelHigh)
}

// SSFVerification is the verification event (SSF 1.0 §8.1.4.1). The top-level sub_id is an opaque subject holding the
// stream_id.
type SSFVerification struct {
	State string `json:"state,omitempty"`
}

func (SSFVerification) SecurityEventType() (uri string) { return SecurityEventTypeSSFVerification }

// Validate always succeeds as state is optional (SSF 1.0 §8.1.4.1).
func (SSFVerification) Validate() (err error) { return nil }

// SSFStreamUpdated is the stream-updated event (SSF 1.0 §8.1.5). The top-level sub_id is an opaque subject holding the
// stream_id.
type SSFStreamUpdated struct {
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

func (SSFStreamUpdated) SecurityEventType() (uri string) { return SecurityEventTypeSSFStreamUpdated }

// Validate requires status (SSF 1.0 §8.1.5).
func (e SSFStreamUpdated) Validate() (err error) {
	return securityEventOneOf("status", e.Status, false, SSFStreamStatusEnabled, SSFStreamStatusPaused, SSFStreamStatusDisabled)
}

// RawSecurityEvent carries an event type without a typed payload, such as a RISC event. Only Claims is marshaled.
type RawSecurityEvent struct {
	URI    string
	Claims map[string]any
}

func (e RawSecurityEvent) SecurityEventType() (uri string) { return e.URI }

func (e RawSecurityEvent) MarshalJSON() (data []byte, err error) {
	if e.Claims == nil {
		return []byte("{}"), nil
	}

	return json.Marshal(e.Claims)
}
