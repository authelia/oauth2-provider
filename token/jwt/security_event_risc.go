// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package jwt

import "fmt"

const (
	// SecurityEventTypeRISCAccountCredentialChangeRequired is the event type URI of the RISC account credential change
	// required security event.
	SecurityEventTypeRISCAccountCredentialChangeRequired = "https://schemas.openid.net/secevent/risc/event-type/account-credential-change-required" //nolint:gosec // G101: event type URI, not a credential.
	// SecurityEventTypeRISCAccountPurged is the event type URI of the RISC account purged security event.
	SecurityEventTypeRISCAccountPurged = "https://schemas.openid.net/secevent/risc/event-type/account-purged"
	// SecurityEventTypeRISCAccountDisabled is the event type URI of the RISC account disabled security event.
	SecurityEventTypeRISCAccountDisabled = "https://schemas.openid.net/secevent/risc/event-type/account-disabled"
	// SecurityEventTypeRISCAccountEnabled is the event type URI of the RISC account enabled security event.
	SecurityEventTypeRISCAccountEnabled = "https://schemas.openid.net/secevent/risc/event-type/account-enabled"
	// SecurityEventTypeRISCIdentifierChanged is the event type URI of the RISC identifier changed security event.
	SecurityEventTypeRISCIdentifierChanged = "https://schemas.openid.net/secevent/risc/event-type/identifier-changed"
	// SecurityEventTypeRISCIdentifierRecycled is the event type URI of the RISC identifier recycled security event.
	SecurityEventTypeRISCIdentifierRecycled = "https://schemas.openid.net/secevent/risc/event-type/identifier-recycled"
	// SecurityEventTypeRISCCredentialCompromise is the event type URI of the RISC credential compromise security event.
	SecurityEventTypeRISCCredentialCompromise = "https://schemas.openid.net/secevent/risc/event-type/credential-compromise" //nolint:gosec // G101: event type URI, not a credential.
	// SecurityEventTypeRISCOptIn is the event type URI of the RISC opt in security event.
	SecurityEventTypeRISCOptIn = "https://schemas.openid.net/secevent/risc/event-type/opt-in"
	// SecurityEventTypeRISCOptOutInitiated is the event type URI of the RISC opt out initiated security event.
	SecurityEventTypeRISCOptOutInitiated = "https://schemas.openid.net/secevent/risc/event-type/opt-out-initiated"
	// SecurityEventTypeRISCOptOutCancelled is the event type URI of the RISC opt out cancelled security event.
	SecurityEventTypeRISCOptOutCancelled = "https://schemas.openid.net/secevent/risc/event-type/opt-out-cancelled"
	// SecurityEventTypeRISCOptOutEffective is the event type URI of the RISC opt out effective security event.
	SecurityEventTypeRISCOptOutEffective = "https://schemas.openid.net/secevent/risc/event-type/opt-out-effective"
	// SecurityEventTypeRISCRecoveryActivated is the event type URI of the RISC recovery activated security event.
	SecurityEventTypeRISCRecoveryActivated = "https://schemas.openid.net/secevent/risc/event-type/recovery-activated"
	// SecurityEventTypeRISCRecoveryInformationChanged is the event type URI of the RISC recovery information changed
	// security event.
	SecurityEventTypeRISCRecoveryInformationChanged = "https://schemas.openid.net/secevent/risc/event-type/recovery-information-changed"
	// SecurityEventTypeRISCSessionsRevoked is the event type URI of the RISC sessions revoked security event. A SET of
	// this event type is refused (RISC 1.0 §2.11).
	//
	// Deprecated: use SecurityEventTypeCAEPSessionRevoked.
	SecurityEventTypeRISCSessionsRevoked = "https://schemas.openid.net/secevent/risc/event-type/sessions-revoked"
)

// The account-disabled reason values (RISC 1.0 §2.3).
const (
	// RISCAccountDisabledReasonHijacking is the reason value for an account that was disabled because it was hijacked
	// (RISC 1.0 §2.3).
	RISCAccountDisabledReasonHijacking = "hijacking"
	// RISCAccountDisabledReasonBulkAccount is the reason value for an account that was disabled as a bulk account
	// (RISC 1.0 §2.3).
	RISCAccountDisabledReasonBulkAccount = "bulk-account"
)

func init() {
	registerSecurityEventTypes(
		func() SecurityEvent { return &RISCAccountCredentialChangeRequired{} },
		func() SecurityEvent { return &RISCAccountPurged{} },
		func() SecurityEvent { return &RISCAccountDisabled{} },
		func() SecurityEvent { return &RISCAccountEnabled{} },
		func() SecurityEvent { return &RISCIdentifierChanged{} },
		func() SecurityEvent { return &RISCIdentifierRecycled{} },
		func() SecurityEvent { return &RISCCredentialCompromise{} },
		func() SecurityEvent { return &RISCOptIn{} },
		func() SecurityEvent { return &RISCOptOutInitiated{} },
		func() SecurityEvent { return &RISCOptOutCancelled{} },
		func() SecurityEvent { return &RISCOptOutEffective{} },
		func() SecurityEvent { return &RISCRecoveryActivated{} },
		func() SecurityEvent { return &RISCRecoveryInformationChanged{} },
		func() SecurityEvent { return &riscSessionsRevoked{} },
	)
}

// SecurityEventTypesRISC returns the event type URI of every RISC 1.0 event other than the deprecated sessions-revoked
// event (RISC 1.0 §2.11), in the order of the specification.
func SecurityEventTypesRISC() (uris []string) {
	return []string{
		SecurityEventTypeRISCAccountCredentialChangeRequired,
		SecurityEventTypeRISCAccountPurged,
		SecurityEventTypeRISCAccountDisabled,
		SecurityEventTypeRISCAccountEnabled,
		SecurityEventTypeRISCIdentifierChanged,
		SecurityEventTypeRISCIdentifierRecycled,
		SecurityEventTypeRISCCredentialCompromise,
		SecurityEventTypeRISCOptIn,
		SecurityEventTypeRISCOptOutInitiated,
		SecurityEventTypeRISCOptOutCancelled,
		SecurityEventTypeRISCOptOutEffective,
		SecurityEventTypeRISCRecoveryActivated,
		SecurityEventTypeRISCRecoveryInformationChanged,
	}
}

// RISCAccountCredentialChangeRequired is the account-credential-change-required event (RISC 1.0 §2.1), which has no
// members: the account was required to change a credential.
type RISCAccountCredentialChangeRequired struct{}

// SecurityEventType returns the event type URI of the account credential change required security event.
func (RISCAccountCredentialChangeRequired) SecurityEventType() (uri string) {
	return SecurityEventTypeRISCAccountCredentialChangeRequired
}

// RISCAccountPurged is the account-purged event (RISC 1.0 §2.2), which has no members: the account was permanently
// deleted.
type RISCAccountPurged struct{}

// SecurityEventType returns the event type URI of the account purged security event.
func (RISCAccountPurged) SecurityEventType() (uri string) { return SecurityEventTypeRISCAccountPurged }

// RISCAccountDisabled is the account-disabled event (RISC 1.0 §2.3).
type RISCAccountDisabled struct {
	Reason string `json:"reason,omitempty"`
}

// SecurityEventType returns the event type URI of the account disabled security event.
func (RISCAccountDisabled) SecurityEventType() (uri string) {
	return SecurityEventTypeRISCAccountDisabled
}

// Validate requires reason, when present, to be hijacking or bulk-account (RISC 1.0 §2.3).
func (e RISCAccountDisabled) Validate() (err error) {
	return securityEventOneOf("reason", e.Reason, true, RISCAccountDisabledReasonHijacking, RISCAccountDisabledReasonBulkAccount)
}

// RISCAccountEnabled is the account-enabled event (RISC 1.0 §2.4), which has no members: the account was enabled.
type RISCAccountEnabled struct{}

// SecurityEventType returns the event type URI of the account enabled security event.
func (RISCAccountEnabled) SecurityEventType() (uri string) {
	return SecurityEventTypeRISCAccountEnabled
}

// RISCIdentifierChanged is the identifier-changed event (RISC 1.0 §2.5). The subject is an email or phone_number
// identifier holding the old value. The event should be issued only by the provider that is authoritative over the
// identifier, and any other provider should issue RISCRecoveryInformationChanged instead.
type RISCIdentifierChanged struct {
	NewValue string `json:"new-value,omitempty"`
}

// SecurityEventType returns the event type URI of the identifier changed security event.
func (RISCIdentifierChanged) SecurityEventType() (uri string) {
	return SecurityEventTypeRISCIdentifierChanged
}

// ValidateSubject requires an email or phone_number subject (RISC 1.0 §2.5).
func (RISCIdentifierChanged) ValidateSubject(subject *SubjectIdentifier) (err error) {
	return riscIdentifierSubject(SecurityEventTypeRISCIdentifierChanged, subject)
}

// RISCIdentifierRecycled is the identifier-recycled event (RISC 1.0 §2.6), which has no members: the email or
// phone_number identifier in the subject now belongs to a new user.
type RISCIdentifierRecycled struct{}

// SecurityEventType returns the event type URI of the identifier recycled security event.
func (RISCIdentifierRecycled) SecurityEventType() (uri string) {
	return SecurityEventTypeRISCIdentifierRecycled
}

// ValidateSubject requires an email or phone_number subject (RISC 1.0 §2.6).
func (RISCIdentifierRecycled) ValidateSubject(subject *SubjectIdentifier) (err error) {
	return riscIdentifierSubject(SecurityEventTypeRISCIdentifierRecycled, subject)
}

// RISCCredentialCompromise is the credential-compromise event (RISC 1.0 §2.7). The credential_type is one of the
// CAEPCredentialType values or any other value the Transmitter and the Receiver both support (CAEP 1.0 §3.3.1), and
// event_timestamp is the time the Transmitter discovered the compromise. Reasons are objects keyed by BCP47 language
// tag (CAEP 1.0 §2).
type RISCCredentialCompromise struct {
	CredentialType string            `json:"credential_type"`
	EventTimestamp int64             `json:"event_timestamp,omitempty"`
	ReasonAdmin    map[string]string `json:"reason_admin,omitempty"`
	ReasonUser     map[string]string `json:"reason_user,omitempty"`
}

// SecurityEventType returns the event type URI of the credential compromise security event.
func (RISCCredentialCompromise) SecurityEventType() (uri string) {
	return SecurityEventTypeRISCCredentialCompromise
}

// Validate requires credential_type (RISC 1.0 §2.7) and that each reason_admin and reason_user key is a BCP47
// language tag (CAEP 1.0 §2).
func (e RISCCredentialCompromise) Validate() (err error) {
	if err = securityEventRequire("credential_type", e.CredentialType); err != nil {
		return err
	}

	if err = securityEventLanguageTags("reason_admin", e.ReasonAdmin); err != nil {
		return err
	}

	return securityEventLanguageTags("reason_user", e.ReasonUser)
}

// RISCOptIn is the opt-in event (RISC 1.0 §2.8.1), which has no members: the account opted in to RISC event exchange.
// The application should let a user opt in and out, keep the opt-out state of each account, and send this event and the
// three opt-out events as that state changes (RISC 1.0 §2.8).
type RISCOptIn struct{}

// SecurityEventType returns the event type URI of the opt in security event.
func (RISCOptIn) SecurityEventType() (uri string) { return SecurityEventTypeRISCOptIn }

// RISCOptOutInitiated is the opt-out-initiated event (RISC 1.0 §2.8.2), which has no members: the account asked to opt
// out of RISC event exchange.
type RISCOptOutInitiated struct{}

// SecurityEventType returns the event type URI of the opt out initiated security event.
func (RISCOptOutInitiated) SecurityEventType() (uri string) {
	return SecurityEventTypeRISCOptOutInitiated
}

// RISCOptOutCancelled is the opt-out-cancelled event (RISC 1.0 §2.8.3), which has no members: the account cancelled its
// opt out of RISC event exchange.
type RISCOptOutCancelled struct{}

// SecurityEventType returns the event type URI of the opt out cancelled security event.
func (RISCOptOutCancelled) SecurityEventType() (uri string) {
	return SecurityEventTypeRISCOptOutCancelled
}

// RISCOptOutEffective is the opt-out-effective event (RISC 1.0 §2.8.4), which has no members: the account is opted out
// of RISC event exchange.
type RISCOptOutEffective struct{}

// SecurityEventType returns the event type URI of the opt out effective security event.
func (RISCOptOutEffective) SecurityEventType() (uri string) {
	return SecurityEventTypeRISCOptOutEffective
}

// RISCRecoveryActivated is the recovery-activated event (RISC 1.0 §2.9), which has no members: the account activated a
// recovery flow.
type RISCRecoveryActivated struct{}

// SecurityEventType returns the event type URI of the recovery activated security event.
func (RISCRecoveryActivated) SecurityEventType() (uri string) {
	return SecurityEventTypeRISCRecoveryActivated
}

// RISCRecoveryInformationChanged is the recovery-information-changed event (RISC 1.0 §2.10), which has no members: the
// account changed some of its recovery information.
type RISCRecoveryInformationChanged struct{}

// SecurityEventType returns the event type URI of the recovery information changed security event.
func (RISCRecoveryInformationChanged) SecurityEventType() (uri string) {
	return SecurityEventTypeRISCRecoveryInformationChanged
}

type riscSessionsRevoked struct{}

func (riscSessionsRevoked) SecurityEventType() (uri string) {
	return SecurityEventTypeRISCSessionsRevoked
}

func (riscSessionsRevoked) Validate() (err error) {
	return fmt.Errorf("%w: the '%s' event type is deprecated and the CAEP session-revoked event type '%s' is used instead", ErrInvalidSecurityEvent, SecurityEventTypeRISCSessionsRevoked, SecurityEventTypeCAEPSessionRevoked)
}

func riscIdentifierSubject(uri string, subject *SubjectIdentifier) (err error) {
	if subject == nil {
		return fmt.Errorf("%w: the '%s' event requires a subject", ErrInvalidSecurityEvent, uri)
	}

	switch subject.Format {
	case SubjectIdentifierFormatEmail, SubjectIdentifierFormatPhoneNumber:
		return nil
	default:
		return fmt.Errorf("%w: the '%s' event subject format '%s' is not '%s' or '%s'", ErrInvalidSecurityEvent, uri, subject.Format, SubjectIdentifierFormatEmail, SubjectIdentifierFormatPhoneNumber)
	}
}
