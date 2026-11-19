// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package ssfreceiver

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"

	"authelia.com/provider/oauth2/token/jwt"
)

// RelayEvent is an event considered for relay to the downstream streams of the authorization server.
type RelayEvent struct {
	// Event is the event as received, or as originated by the application.
	Event jwt.SecurityEvent

	// Transaction is the 'txn' of the received SET, empty when it had none.
	Transaction string

	// Principal is the principal of the application the event is about.
	Principal any

	// OriginIssuer and OriginJTI are the 'iss' and 'jti' of the received SET.
	OriginIssuer, OriginJTI string

	// ExcludeClientIDs are the clients whose streams the event is not relayed to.
	ExcludeClientIDs []string
}

// RelayPolicy decides whether an event is relayed, and returns the event to relay in its place when it is. The event
// is a copy which shares its Event and Principal, and the reasonAdmin is a copy of the configured replacement
// 'reason_admin', which may be nil, so a change of either is not seen by the Relay. The returned event is issued as it is:
// a policy which does not return the SanitizeRelayEvent result answers for every member it discloses downstream. A nil
// RelayPolicy relays nothing.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-10.1
type RelayPolicy func(ctx context.Context, event *RelayEvent, reasonAdmin map[string]string) (out jwt.SecurityEvent, relay bool, err error)

// decide returns the event to relay and true when the policy relays the event. A nil policy relays nothing, the
// policy is not asked about a verification or stream updated event, and its event can not be one.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.4
func (p RelayPolicy) decide(ctx context.Context, event *RelayEvent, reasonAdmin map[string]string) (out jwt.SecurityEvent, relay bool, err error) {
	if p == nil || event == nil {
		return nil, false, nil
	}

	if have := relayEventValue(event.Event); have == nil || isStreamEvent(have.SecurityEventType()) {
		return nil, false, nil
	}

	handed := *event
	handed.ExcludeClientIDs = slices.Clone(event.ExcludeClientIDs)

	if out, relay, err = p(ctx, &handed, maps.Clone(reasonAdmin)); err != nil || !relay {
		return nil, false, err
	}

	if relayEventValue(out) == nil || isStreamEvent(out.SecurityEventType()) {
		return nil, false, ErrRelayPolicyEvent
	}

	return out, true, nil
}

// RelayEventTypes returns the default RelayPolicy, which relays the SanitizeRelayEvent result of an event of one of
// the listed event types. An event SanitizeRelayEvent has no rule for is not relayed even when its type is listed.
func RelayEventTypes(types ...string) RelayPolicy {
	types = slices.Clone(types)

	return func(_ context.Context, event *RelayEvent, reasonAdmin map[string]string) (out jwt.SecurityEvent, relay bool, err error) {
		if event == nil || relayEventValue(event.Event) == nil || !slices.Contains(types, event.Event.SecurityEventType()) {
			return nil, false, nil
		}

		if out, err = SanitizeRelayEvent(event.Event, reasonAdmin); err != nil {
			if errors.Is(err, ErrRelayEventNotSanitizable) {
				return nil, false, nil
			}

			return nil, false, err
		}

		return out, true, nil
	}
}

// SanitizeRelayEvent returns a copy of the event with only the members which are relayed, and does not change the
// event. The 'event_timestamp' and 'initiating_entity' are kept, the 'reason_admin' and 'reason_user' of the
// Transmitter are dropped, and the reasonAdmin when not empty is the 'reason_admin' of the copy. It returns an
// ErrRelayEventNotSanitizable error for an event type with no rule, and a jwt.ErrInvalidSecurityEvent error when the
// copy is not a valid event.
//
// See: https://openid.net/specs/openid-caep-1_0.html#section-2
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-9.2
// See: https://openid.net/specs/openid-caep-interoperability-profile-1_0.html#section-3.1
func SanitizeRelayEvent(event jwt.SecurityEvent, reasonAdmin map[string]string) (out jwt.SecurityEvent, err error) {
	if event = relayEventValue(event); event == nil {
		return nil, ErrRelayEventNotSanitizable
	}

	if out = sanitizeRelayEvent(event, reasonAdmin); out == nil {
		return nil, fmt.Errorf("%w: '%s'", ErrRelayEventNotSanitizable, event.SecurityEventType())
	}

	if v, ok := out.(interface{ Validate() error }); ok {
		if err = v.Validate(); err != nil {
			return nil, fmt.Errorf("ssfreceiver: the relayed '%s' event is not valid: %w", out.SecurityEventType(), err)
		}
	}

	return out, nil
}

// sanitizeRelayEvent returns the relayed copy of an event value, nil for a type with no rule. The CAEP token claims
// change event has none as its required 'claims' are not relayed.
//
//nolint:gocyclo // One case per event type.
func sanitizeRelayEvent(event jwt.SecurityEvent, reasonAdmin map[string]string) (out jwt.SecurityEvent) {
	switch e := event.(type) {
	case jwt.CAEPSessionRevoked:
		return &jwt.CAEPSessionRevoked{SecurityEventCommon: relayEventCommon(e.SecurityEventCommon, reasonAdmin)}
	case jwt.CAEPCredentialChange:
		// CAEP Section 3.3: the 'friendly_name', 'x509_issuer', 'x509_serial' and 'fido2_aaguid' are dropped.
		return &jwt.CAEPCredentialChange{
			SecurityEventCommon: relayEventCommon(e.SecurityEventCommon, reasonAdmin),
			CredentialType:      e.CredentialType,
			ChangeType:          e.ChangeType,
		}
	case jwt.CAEPAssuranceLevelChange:
		return &jwt.CAEPAssuranceLevelChange{
			SecurityEventCommon: relayEventCommon(e.SecurityEventCommon, reasonAdmin),
			Namespace:           e.Namespace,
			CurrentLevel:        e.CurrentLevel,
			PreviousLevel:       e.PreviousLevel,
			ChangeDirection:     e.ChangeDirection,
		}
	case jwt.CAEPDeviceComplianceChange:
		return &jwt.CAEPDeviceComplianceChange{
			SecurityEventCommon: relayEventCommon(e.SecurityEventCommon, reasonAdmin),
			PreviousStatus:      e.PreviousStatus,
			CurrentStatus:       e.CurrentStatus,
		}
	case jwt.CAEPSessionEstablished:
		// CAEP Section 3.6: the 'fp_ua', 'acr', 'amr' and 'ext_id' are dropped.
		return &jwt.CAEPSessionEstablished{SecurityEventCommon: relayEventCommon(e.SecurityEventCommon, reasonAdmin)}
	case jwt.CAEPSessionPresented:
		// CAEP Section 3.7: the 'fp_ua' and 'ext_id' are dropped.
		return &jwt.CAEPSessionPresented{SecurityEventCommon: relayEventCommon(e.SecurityEventCommon, reasonAdmin)}
	case jwt.CAEPRiskLevelChange:
		// CAEP Section 3.8: the 'risk_reason' is dropped.
		return &jwt.CAEPRiskLevelChange{
			SecurityEventCommon: relayEventCommon(e.SecurityEventCommon, reasonAdmin),
			Principal:           e.Principal,
			CurrentLevel:        e.CurrentLevel,
			PreviousLevel:       e.PreviousLevel,
		}
	case jwt.RISCAccountCredentialChangeRequired:
		return &jwt.RISCAccountCredentialChangeRequired{}
	case jwt.RISCAccountPurged:
		return &jwt.RISCAccountPurged{}
	case jwt.RISCAccountDisabled:
		return &jwt.RISCAccountDisabled{Reason: e.Reason}
	case jwt.RISCAccountEnabled:
		return &jwt.RISCAccountEnabled{}
	case jwt.RISCIdentifierChanged:
		// RISC Section 2.5: the 'new-value' is dropped.
		return &jwt.RISCIdentifierChanged{}
	case jwt.RISCIdentifierRecycled:
		return &jwt.RISCIdentifierRecycled{}
	case jwt.RISCCredentialCompromise:
		return &jwt.RISCCredentialCompromise{
			CredentialType: e.CredentialType,
			EventTimestamp: e.EventTimestamp,
			ReasonAdmin:    relayReasonAdmin(reasonAdmin),
		}
	case jwt.RISCOptIn:
		return &jwt.RISCOptIn{}
	case jwt.RISCOptOutInitiated:
		return &jwt.RISCOptOutInitiated{}
	case jwt.RISCOptOutCancelled:
		return &jwt.RISCOptOutCancelled{}
	case jwt.RISCOptOutEffective:
		return &jwt.RISCOptOutEffective{}
	case jwt.RISCRecoveryActivated:
		return &jwt.RISCRecoveryActivated{}
	case jwt.RISCRecoveryInformationChanged:
		return &jwt.RISCRecoveryInformationChanged{}
	default:
		return nil
	}
}

// relayEventCommon returns the relayed common claims of a CAEP event.
//
// See: https://openid.net/specs/openid-caep-1_0.html#section-2
func relayEventCommon(common jwt.SecurityEventCommon, reasonAdmin map[string]string) jwt.SecurityEventCommon {
	return jwt.SecurityEventCommon{
		EventTimestamp:   common.EventTimestamp,
		InitiatingEntity: common.InitiatingEntity,
		ReasonAdmin:      relayReasonAdmin(reasonAdmin),
	}
}

// relayReasonAdmin returns a copy of the configured 'reason_admin', nil when it is empty as the claim has one or
// more pairs.
//
// See: https://openid.net/specs/openid-caep-1_0.html#section-2
func relayReasonAdmin(reasonAdmin map[string]string) map[string]string {
	if len(reasonAdmin) == 0 {
		return nil
	}

	return maps.Clone(reasonAdmin)
}

// relayEventValue returns the event a pointer to an event refers to, so one rule covers an event held by value or by
// pointer. It returns nil for a nil event and for a nil pointer.
func relayEventValue(event jwt.SecurityEvent) jwt.SecurityEvent {
	if event == nil {
		return nil
	}

	value := reflect.ValueOf(event)

	if value.Kind() != reflect.Pointer {
		return event
	}

	if value.IsNil() {
		return nil
	}

	if elem, ok := value.Elem().Interface().(jwt.SecurityEvent); ok {
		return elem
	}

	return event
}
