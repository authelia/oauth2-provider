// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/text/language"

	jjson "authelia.com/provider/jose/json"
)

const (
	// SecurityEventTypeCAEPSessionRevoked is the event type URI of the CAEP session revoked security event.
	SecurityEventTypeCAEPSessionRevoked = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
	// SecurityEventTypeCAEPTokenClaimsChange is the event type URI of the CAEP token claims change security event.
	SecurityEventTypeCAEPTokenClaimsChange = "https://schemas.openid.net/secevent/caep/event-type/token-claims-change" //nolint:gosec // G101: event type URI, not a credential.
	// SecurityEventTypeCAEPCredentialChange is the event type URI of the CAEP credential change security event.
	SecurityEventTypeCAEPCredentialChange = "https://schemas.openid.net/secevent/caep/event-type/credential-change" //nolint:gosec // G101: event type URI, not a credential.
	// SecurityEventTypeCAEPAssuranceLevelChange is the event type URI of the CAEP assurance level change security event.
	SecurityEventTypeCAEPAssuranceLevelChange = "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change" //nolint:gosec // G101: event type URI, not a credential.
	// SecurityEventTypeCAEPDeviceComplianceChange is the event type URI of the CAEP device compliance change security event.
	SecurityEventTypeCAEPDeviceComplianceChange = "https://schemas.openid.net/secevent/caep/event-type/device-compliance-change"
	// SecurityEventTypeCAEPSessionEstablished is the event type URI of the CAEP session established security event.
	SecurityEventTypeCAEPSessionEstablished = "https://schemas.openid.net/secevent/caep/event-type/session-established"
	// SecurityEventTypeCAEPSessionPresented is the event type URI of the CAEP session presented security event.
	SecurityEventTypeCAEPSessionPresented = "https://schemas.openid.net/secevent/caep/event-type/session-presented"
	// SecurityEventTypeCAEPRiskLevelChange is the event type URI of the CAEP risk level change security event.
	SecurityEventTypeCAEPRiskLevelChange = "https://schemas.openid.net/secevent/caep/event-type/risk-level-change"
	// SecurityEventTypeSSFVerification is the event type URI of the SSF verification security event.
	SecurityEventTypeSSFVerification = "https://schemas.openid.net/secevent/ssf/event-type/verification"
	// SecurityEventTypeSSFStreamUpdated is the event type URI of the SSF stream updated security event.
	SecurityEventTypeSSFStreamUpdated = "https://schemas.openid.net/secevent/ssf/event-type/stream-updated"
)

// The initiating_entity values (CAEP 1.0 §2).
const (
	// SecurityEventInitiatingEntityAdmin means an administrative action triggered the event (CAEP 1.0 §2).
	SecurityEventInitiatingEntityAdmin = "admin"
	// SecurityEventInitiatingEntityUser means an end-user action triggered the event (CAEP 1.0 §2).
	SecurityEventInitiatingEntityUser = "user"
	// SecurityEventInitiatingEntityPolicy means a policy evaluation triggered the event (CAEP 1.0 §2).
	SecurityEventInitiatingEntityPolicy = "policy"
	// SecurityEventInitiatingEntitySystem means a system or platform assertion triggered the event (CAEP 1.0 §2).
	SecurityEventInitiatingEntitySystem = "system"
)

// The credential_type values (CAEP 1.0 §3.3.1). The set is open to any other value the Transmitter and the Receiver
// both support.
const (
	// CAEPCredentialTypePassword is the credential_type value for a password (CAEP 1.0 §3.3.1).
	CAEPCredentialTypePassword = "password"
	// CAEPCredentialTypePIN is the credential_type value for a PIN (CAEP 1.0 §3.3.1).
	CAEPCredentialTypePIN = "pin"
	// CAEPCredentialTypeX509 is the credential_type value for an X.509 certificate (CAEP 1.0 §3.3.1).
	CAEPCredentialTypeX509 = "x509"
	// CAEPCredentialTypeFIDO2Platform is the credential_type value for a FIDO2 platform authenticator (CAEP 1.0
	// §3.3.1).
	CAEPCredentialTypeFIDO2Platform = "fido2-platform"
	// CAEPCredentialTypeFIDO2Roaming is the credential_type value for a FIDO2 roaming authenticator (CAEP 1.0 §3.3.1).
	CAEPCredentialTypeFIDO2Roaming = "fido2-roaming"
	// CAEPCredentialTypeFIDOU2F is the credential_type value for a FIDO U2F authenticator (CAEP 1.0 §3.3.1).
	CAEPCredentialTypeFIDOU2F = "fido-u2f"
	// CAEPCredentialTypeVerifiableCredential is the credential_type value for a verifiable credential (CAEP 1.0
	// §3.3.1).
	CAEPCredentialTypeVerifiableCredential = "verifiable-credential" //nolint:gosec // G101: credential type name, not a credential.
	// CAEPCredentialTypePhoneVoice is the credential_type value for a phone voice call (CAEP 1.0 §3.3.1).
	CAEPCredentialTypePhoneVoice = "phone-voice"
	// CAEPCredentialTypePhoneSMS is the credential_type value for a phone text message (CAEP 1.0 §3.3.1).
	CAEPCredentialTypePhoneSMS = "phone-sms"
	// CAEPCredentialTypeApp is the credential_type value for an application (CAEP 1.0 §3.3.1).
	CAEPCredentialTypeApp = "app"
)

// The change_type values (CAEP 1.0 §3.3.1).
const (
	// CAEPChangeTypeCreate is the change_type value for a credential that was created (CAEP 1.0 §3.3.1).
	CAEPChangeTypeCreate = "create"
	// CAEPChangeTypeRevoke is the change_type value for a credential that was revoked (CAEP 1.0 §3.3.1).
	CAEPChangeTypeRevoke = "revoke"
	// CAEPChangeTypeUpdate is the change_type value for a credential that was updated (CAEP 1.0 §3.3.1).
	CAEPChangeTypeUpdate = "update"
	// CAEPChangeTypeDelete is the change_type value for a credential that was deleted (CAEP 1.0 §3.3.1).
	CAEPChangeTypeDelete = "delete"
)

// The change_direction values (CAEP 1.0 §3.4.1).
const (
	// CAEPChangeDirectionIncrease is the change_direction value for an assurance level that increased (CAEP 1.0 §3.4.1).
	CAEPChangeDirectionIncrease = "increase"
	// CAEPChangeDirectionDecrease is the change_direction value for an assurance level that decreased (CAEP 1.0 §3.4.1).
	CAEPChangeDirectionDecrease = "decrease"
)

// The device compliance status values (CAEP 1.0 §3.5.1).
const (
	// CAEPDeviceComplianceCompliant is the status value for a device that is compliant (CAEP 1.0 §3.5.1).
	CAEPDeviceComplianceCompliant = "compliant"
	// CAEPDeviceComplianceNotCompliant is the status value for a device that is not compliant (CAEP 1.0 §3.5.1).
	CAEPDeviceComplianceNotCompliant = "not-compliant"
)

// The risk level values (CAEP 1.0 §3.8.1).
const (
	// CAEPRiskLevelLow is the risk level value 'LOW' (CAEP 1.0 §3.8.1).
	CAEPRiskLevelLow = "LOW"
	// CAEPRiskLevelMedium is the risk level value 'MEDIUM' (CAEP 1.0 §3.8.1).
	CAEPRiskLevelMedium = "MEDIUM"
	// CAEPRiskLevelHigh is the risk level value 'HIGH' (CAEP 1.0 §3.8.1).
	CAEPRiskLevelHigh = "HIGH"
)

// The stream status values (SSF 1.0 §8.1.2).
const (
	// SSFStreamStatusEnabled means the Transmitter delivers events on the stream (SSF 1.0 §8.1.2).
	SSFStreamStatusEnabled = "enabled"
	// SSFStreamStatusPaused means the Transmitter withholds events on the stream and should keep them (SSF 1.0 §8.1.2).
	SSFStreamStatusPaused = "paused"
	// SSFStreamStatusDisabled means the Transmitter neither delivers nor holds events on the stream (SSF 1.0 §8.1.2).
	SSFStreamStatusDisabled = "disabled"
)

const (
	securityEventTypePrefixCAEP = "https://schemas.openid.net/secevent/caep/event-type/"

	claimSecurityEventTimestamp   = "event_timestamp"
	jsonNull                      = "null"
	claimSecurityEventReasonAdmin = "reason_admin"
	claimSecurityEventReasonUser  = "reason_user"
)

// ErrInvalidSecurityEvent is returned for an event payload that is missing a required claim or has an invalid value.
var ErrInvalidSecurityEvent = errors.New("invalid security event")

// SecurityEvent is the payload of one event in the events claim of a SET (RFC 8417 §2.2). An event type an application
// defines describes its primary subject with the 'sub_id' claim of the SET and has no 'subject' member (SSF 1.0
// §3.1.2). Any other subject member it defines refers to exactly one subject (SSF 1.0 §3.1.4).
type SecurityEvent interface {
	// SecurityEventType returns the event type URI of the event, which should be a stable value such as the permanent
	// URL of the specification of the event (RFC 8417 §2.2).
	SecurityEventType() (uri string)
}

// SecurityEventSubjectValidator is implemented by a SecurityEvent that restricts the subject identifier of its SET.
// NewSecurityEventTokenClaims and SecurityEventTokenClaims.Valid call it with the 'sub_id' claim.
type SecurityEventSubjectValidator interface {
	// ValidateSubject returns an error when the event must not be about the subject.
	ValidateSubject(subject *SubjectIdentifier) (err error)
}

var securityEventTypes = map[string]func() SecurityEvent{}

func init() {
	registerSecurityEventTypes(
		func() SecurityEvent { return &CAEPSessionRevoked{} },
		func() SecurityEvent { return &CAEPTokenClaimsChange{} },
		func() SecurityEvent { return &CAEPCredentialChange{} },
		func() SecurityEvent { return &CAEPAssuranceLevelChange{} },
		func() SecurityEvent { return &CAEPDeviceComplianceChange{} },
		func() SecurityEvent { return &CAEPSessionEstablished{} },
		func() SecurityEvent { return &CAEPSessionPresented{} },
		func() SecurityEvent { return &CAEPRiskLevelChange{} },
		func() SecurityEvent { return &SSFVerification{} },
		func() SecurityEvent { return &SSFStreamUpdated{} },
	)
}

func registerSecurityEventTypes(factories ...func() SecurityEvent) {
	for _, factory := range factories {
		securityEventTypes[factory().SecurityEventType()] = factory
	}
}

func validateSecurityEvent(event SecurityEvent, subject *SubjectIdentifier) (err error) {
	if v, ok := event.(interface{ Validate() error }); ok {
		if err = v.Validate(); err != nil {
			return securityEventError(err)
		}
	}

	if v, ok := event.(SecurityEventSubjectValidator); ok && subject != nil {
		if err = v.ValidateSubject(subject); err != nil {
			return securityEventError(err)
		}
	}

	return nil
}

func validateSecurityEventPayload(uri string, payload map[string]any, subject *SubjectIdentifier) (err error) {
	var event SecurityEvent

	if event, err = decodeSecurityEventPayload(uri, payload); err != nil || event == nil {
		return err
	}

	return validateSecurityEvent(event, subject)
}

// DecodeSecurityEvent returns the event of a received payload as a pointer to the type this package defines for the
// event type URI, which is validated. A member the type does not define is ignored (SSF 1.0 §4.2.3), and the fraction
// of an event_timestamp is dropped. Any other event type, and the deprecated RISC sessions-revoked event type (RISC 1.0
// §2.11), gives a RawSecurityEvent with a copy of the payload.
func DecodeSecurityEvent(uri string, payload map[string]any) (event SecurityEvent, err error) {
	if uri != SecurityEventTypeRISCSessionsRevoked {
		if event, err = decodeSecurityEventPayload(uri, payload); err != nil {
			return nil, err
		}
	}

	if event == nil {
		return RawSecurityEvent{URI: uri, Claims: maps.Clone(payload)}, nil
	}

	if err = validateSecurityEvent(event, nil); err != nil {
		return nil, err
	}

	return event, nil
}

// decodeSecurityEventPayload returns nil for an event type this package does not define.
func decodeSecurityEventPayload(uri string, payload map[string]any) (event SecurityEvent, err error) {
	factory, ok := securityEventTypes[uri]
	if !ok {
		return nil, nil
	}

	if strings.HasPrefix(uri, securityEventTypePrefixCAEP) {
		// CAEP 1.0 §2: a reason object contains one or more key/value pairs.
		for _, claim := range []string{claimSecurityEventReasonAdmin, claimSecurityEventReasonUser} {
			if securityEventMemberJSON(payload, claim) == "{}" {
				return nil, fmt.Errorf("%w: the '%s' claim must contain one or more key/value pairs", ErrInvalidSecurityEvent, claim)
			}
		}
	}

	// CAEP 1.0 §2, RISC 1.0 §2.7: event_timestamp is a JSON number, which may have a fraction (RFC 8259 §6).
	literal := securityEventMemberJSON(payload, claimSecurityEventTimestamp)

	if literal == jsonNull {
		return nil, fmt.Errorf("%w: the '%s' event payload is not valid: the '%s' claim is not a number", ErrInvalidSecurityEvent, uri, claimSecurityEventTimestamp)
	}

	if literal != "" && (literal[0] == '-' || (literal[0] >= '0' && literal[0] <= '9')) {
		payload = maps.Clone(payload)

		if seconds, ok := securityEventSeconds(literal); ok {
			payload[claimSecurityEventTimestamp] = seconds
		} else {
			delete(payload, claimSecurityEventTimestamp)
		}
	}

	var data []byte

	if data, err = json.Marshal(payload); err != nil {
		return nil, fmt.Errorf("%w: the '%s' event payload is not valid: %w", ErrInvalidSecurityEvent, uri, err)
	}

	event = factory()

	if err = decodeSecurityEventInto(data, event); err != nil {
		return nil, fmt.Errorf("%w: the '%s' event payload is not valid: %w", ErrInvalidSecurityEvent, uri, err)
	}

	return event, nil
}

// decodeSecurityEventInto decodes the payload into the event. A number decoded into an interface value is converted as
// ParseSecurityEventTokenClaims converts the numbers of an event payload (RFC 8259 §6).
func decodeSecurityEventInto(data []byte, event SecurityEvent) (err error) {
	decoder := jjson.NewDecoder(bytes.NewReader(data))
	decoder.SetNumberType(jjson.UnmarshalJSONNumber)

	if err = decoder.Decode(event); err != nil {
		return err
	}

	if change, ok := event.(*CAEPTokenClaimsChange); ok && change.Claims != nil {
		_, err = securityEventNumbers(change.Claims)
	}

	return err
}

// securityEventSeconds returns the whole seconds of a JSON number, when they fit an int64. The fraction is removed
// from the decimal digits, as rounding to a float64 may carry it into the seconds, and the work is bounded by the
// length of the literal whatever its exponent (RFC 8259 §6).
func securityEventSeconds(literal string) (seconds int64, ok bool) {
	if i, err := strconv.ParseInt(literal, 10, 64); err == nil {
		return i, true
	}

	sign, rest := "", literal

	if strings.HasPrefix(rest, "-") {
		sign, rest = "-", rest[1:]
	}

	mantissa, exponent := rest, 0

	if i := strings.IndexAny(rest, "eE"); i >= 0 {
		var err error

		mantissa = rest[:i]

		if exponent, err = strconv.Atoi(rest[i+1:]); err != nil {
			if !errors.Is(err, strconv.ErrRange) {
				return 0, false
			}

			// An exponent beyond an int is beyond any number of digits.
			exponent = math.MaxInt32

			if strings.HasPrefix(rest[i+1:], "-") {
				exponent = math.MinInt32
			}
		}
	}

	whole, fraction, _ := strings.Cut(mantissa, ".")
	digits := whole + fraction

	if whole == "" || strings.Trim(digits, "0123456789") != "" {
		return 0, false
	}

	// Past the digits and the 19 of an int64 the whole part is zero, or all of the digits and too large.
	if limit := len(digits) + 19; exponent < -limit {
		return 0, true
	} else if exponent > limit {
		if strings.Trim(digits, "0") == "" {
			return 0, true
		}

		return 0, false
	}

	var integer string

	switch point := len(whole) + exponent; {
	case point <= 0:
		integer = "0"
	case point >= len(digits):
		integer = digits + strings.Repeat("0", point-len(digits))
	default:
		integer = digits[:point]
	}

	i, err := strconv.ParseInt(sign+integer, 10, 64)
	if err != nil {
		return 0, false
	}

	return i, true
}

func securityEventMemberJSON(payload map[string]any, claim string) (literal string) {
	value, ok := payload[claim]
	if !ok {
		return ""
	}

	data, err := json.Marshal(value)
	if err != nil {
		return ""
	}

	return string(data)
}

func securityEventError(err error) error {
	if errors.Is(err, ErrInvalidSecurityEvent) {
		return err
	}

	return fmt.Errorf("%w: %w", ErrInvalidSecurityEvent, err)
}

// SecurityEventCommon are the optional claims shared by CAEP 1.0 events (CAEP 1.0 §2). Reasons are objects keyed by
// BCP47 language tag. EventTimestamp is the time the event occurred, which each event type defines, such as the time
// the credential changed (CAEP 1.0 §3.3.1), and not the time the SET was issued.
type SecurityEventCommon struct {
	EventTimestamp   int64             `json:"event_timestamp,omitempty"`
	InitiatingEntity string            `json:"initiating_entity,omitempty"`
	ReasonAdmin      map[string]string `json:"reason_admin,omitempty"`
	ReasonUser       map[string]string `json:"reason_user,omitempty"`
}

// Validate checks initiating_entity and that each reason_admin and reason_user key is a BCP47 language tag (CAEP 1.0
// §2).
func (c SecurityEventCommon) Validate() (err error) {
	switch c.InitiatingEntity {
	case "", SecurityEventInitiatingEntityAdmin, SecurityEventInitiatingEntityUser, SecurityEventInitiatingEntityPolicy, SecurityEventInitiatingEntitySystem:
		break
	default:
		return securityEventInvalid("initiating_entity", c.InitiatingEntity)
	}

	if err = securityEventLanguageTags("reason_admin", c.ReasonAdmin); err != nil {
		return err
	}

	return securityEventLanguageTags("reason_user", c.ReasonUser)
}

func securityEventLanguageTags(claim string, reasons map[string]string) (err error) {
	for _, tag := range slices.Sorted(maps.Keys(reasons)) {
		if !isLanguageTag(tag) {
			return fmt.Errorf("%w: the '%s' claim key '%s' is not a BCP47 language tag", ErrInvalidSecurityEvent, claim, tag)
		}
	}

	return nil
}

func isLanguageTag(tag string) bool {
	if strings.Contains(tag, "_") {
		return false
	}

	var unknown language.ValueError

	// RFC 5646 §2.2.9: a well-formed tag whose subtags are not registered is still a language tag.
	if _, err := language.Parse(tag); err != nil && !errors.As(err, &unknown) {
		return false
	}

	return true
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

// SecurityEventType returns the event type URI of the session revoked security event.
func (CAEPSessionRevoked) SecurityEventType() (uri string) {
	return SecurityEventTypeCAEPSessionRevoked
}

// CAEPTokenClaimsChange is the token-claims-change event (CAEP 1.0 §3.2).
type CAEPTokenClaimsChange struct {
	SecurityEventCommon

	// Claims is the set of registered claim accessors implemented by the claim types of this package.
	Claims map[string]any `json:"claims"`
}

// SecurityEventType returns the event type URI of the token claims change security event.
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

// SecurityEventType returns the event type URI of the credential change security event.
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

// CAEPAssuranceLevelChange is the assurance-level-change event (CAEP 1.0 §3.4). An event with a PreviousLevel should
// have a ChangeDirection (CAEP 1.0 §3.4.1).
type CAEPAssuranceLevelChange struct {
	SecurityEventCommon

	Namespace       string `json:"namespace"`
	CurrentLevel    string `json:"current_level"`
	PreviousLevel   string `json:"previous_level,omitempty"`
	ChangeDirection string `json:"change_direction,omitempty"`
}

// SecurityEventType returns the event type URI of the assurance level change security event.
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

// SecurityEventType returns the event type URI of the device compliance change security event.
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

// SecurityEventType returns the event type URI of the session established security event.
func (CAEPSessionEstablished) SecurityEventType() (uri string) {
	return SecurityEventTypeCAEPSessionEstablished
}

// CAEPSessionPresented is the session-presented event (CAEP 1.0 §3.7).
type CAEPSessionPresented struct {
	SecurityEventCommon

	FingerprintUserAgent string `json:"fp_ua,omitempty"`
	ExternalID           string `json:"ext_id,omitempty"`
}

// SecurityEventType returns the event type URI of the session presented security event.
func (CAEPSessionPresented) SecurityEventType() (uri string) {
	return SecurityEventTypeCAEPSessionPresented
}

// CAEPRiskLevelChange is the risk-level-change event (CAEP 1.0 §3.8). A RiskReason is recommended (CAEP 1.0 §3.8.1).
type CAEPRiskLevelChange struct {
	SecurityEventCommon

	RiskReason    string `json:"risk_reason,omitempty"`
	Principal     string `json:"principal"`
	CurrentLevel  string `json:"current_level"`
	PreviousLevel string `json:"previous_level,omitempty"`
}

// SecurityEventType returns the event type URI of the risk level change security event.
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
	// State is the 'state' of the verification request, which is echoed even when it is the empty string (SSF 1.0
	// §8.1.4.2). It is nil when the request had none or the Transmitter initiated the event.
	State *string `json:"state,omitempty"`
}

// SecurityEventType returns the event type URI of the verification security event.
func (SSFVerification) SecurityEventType() (uri string) { return SecurityEventTypeSSFVerification }

// Validate always succeeds as state is optional (SSF 1.0 §8.1.4.1).
func (SSFVerification) Validate() (err error) { return nil }

// SSFStreamUpdated is the stream-updated event (SSF 1.0 §8.1.5). The top-level sub_id is an opaque subject holding the
// stream_id.
type SSFStreamUpdated struct {
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

// SecurityEventType returns the event type URI of the stream updated security event.
func (SSFStreamUpdated) SecurityEventType() (uri string) { return SecurityEventTypeSSFStreamUpdated }

// Validate requires status (SSF 1.0 §8.1.5).
func (e SSFStreamUpdated) Validate() (err error) {
	return securityEventOneOf("status", e.Status, false, SSFStreamStatusEnabled, SSFStreamStatusPaused, SSFStreamStatusDisabled)
}

// RawSecurityEvent carries an event type without a typed payload. Only Claims is marshaled. A raw event of an event
// type this package defines is validated as that type, and one of the deprecated RISC sessions-revoked event type is
// refused (RISC 1.0 §2.11).
type RawSecurityEvent struct {
	URI string
	// Claims is the set of registered claim accessors implemented by the claim types of this package.
	Claims map[string]any
}

// SecurityEventType returns the event type URI of the raw security event.
func (e RawSecurityEvent) SecurityEventType() (uri string) { return e.URI }

// MarshalJSON marshals the raw event claims.
func (e RawSecurityEvent) MarshalJSON() (data []byte, err error) {
	if e.Claims == nil {
		return []byte("{}"), nil
	}

	return json.Marshal(e.Claims)
}
