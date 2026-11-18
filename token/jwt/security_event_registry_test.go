// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"errors"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecurityEventTypesRegistry(t *testing.T) {
	testCases := []struct {
		uri      string
		expected SecurityEvent
	}{
		{SecurityEventTypeCAEPSessionRevoked, &CAEPSessionRevoked{}},
		{SecurityEventTypeCAEPTokenClaimsChange, &CAEPTokenClaimsChange{}},
		{SecurityEventTypeCAEPCredentialChange, &CAEPCredentialChange{}},
		{SecurityEventTypeCAEPAssuranceLevelChange, &CAEPAssuranceLevelChange{}},
		{SecurityEventTypeCAEPDeviceComplianceChange, &CAEPDeviceComplianceChange{}},
		{SecurityEventTypeCAEPSessionEstablished, &CAEPSessionEstablished{}},
		{SecurityEventTypeCAEPSessionPresented, &CAEPSessionPresented{}},
		{SecurityEventTypeCAEPRiskLevelChange, &CAEPRiskLevelChange{}},
		{SecurityEventTypeSSFVerification, &SSFVerification{}},
		{SecurityEventTypeSSFStreamUpdated, &SSFStreamUpdated{}},
		{SecurityEventTypeRISCAccountCredentialChangeRequired, &RISCAccountCredentialChangeRequired{}},
		{SecurityEventTypeRISCAccountPurged, &RISCAccountPurged{}},
		{SecurityEventTypeRISCAccountDisabled, &RISCAccountDisabled{}},
		{SecurityEventTypeRISCAccountEnabled, &RISCAccountEnabled{}},
		{SecurityEventTypeRISCIdentifierChanged, &RISCIdentifierChanged{}},
		{SecurityEventTypeRISCIdentifierRecycled, &RISCIdentifierRecycled{}},
		{SecurityEventTypeRISCCredentialCompromise, &RISCCredentialCompromise{}},
		{SecurityEventTypeRISCOptIn, &RISCOptIn{}},
		{SecurityEventTypeRISCOptOutInitiated, &RISCOptOutInitiated{}},
		{SecurityEventTypeRISCOptOutCancelled, &RISCOptOutCancelled{}},
		{SecurityEventTypeRISCOptOutEffective, &RISCOptOutEffective{}},
		{SecurityEventTypeRISCRecoveryActivated, &RISCRecoveryActivated{}},
		{SecurityEventTypeRISCRecoveryInformationChanged, &RISCRecoveryInformationChanged{}},
		{SecurityEventTypeRISCSessionsRevoked, &riscSessionsRevoked{}},
	}

	for _, tc := range testCases {
		t.Run(tc.uri, func(t *testing.T) {
			factory, ok := securityEventTypes[tc.uri]
			require.True(t, ok)

			event := factory()

			assert.Equal(t, tc.expected, event)
			assert.Equal(t, tc.uri, event.SecurityEventType())

			if reflect.TypeOf(event).Elem().Size() != 0 {
				assert.NotSame(t, event, factory())
			}
		})
	}

	for uri, factory := range securityEventTypes {
		t.Run("ShouldReturnPointer/"+uri, func(t *testing.T) {
			event := factory()

			assert.Equal(t, reflect.Pointer, reflect.ValueOf(event).Kind())
			assert.Equal(t, uri, event.SecurityEventType())
		})
	}
}

func TestRegisterSecurityEventTypes(t *testing.T) {
	const uri = "https://example.com/event/registered"

	t.Cleanup(func() { delete(securityEventTypes, uri) })

	registerSecurityEventTypes(func() SecurityEvent { return &registeredEvent{} })

	require.Contains(t, securityEventTypes, uri)

	email, err := NewSubjectIdentifierEmail("john@example.com")
	require.NoError(t, err)

	opaque, err := NewSubjectIdentifierOpaque("abc")
	require.NoError(t, err)

	testCases := []struct {
		name    string
		subject *SubjectIdentifier
		claims  map[string]any
		err     error
	}{
		{"ShouldAcceptValidRawEvent", email, map[string]any{"level": "high"}, nil},
		{"ShouldValidateRawEvent", email, map[string]any{"level": "extreme"}, errRegisteredLevel},
		{"ShouldValidateRawEventSubject", opaque, map[string]any{"level": "high"}, errRegisteredSubject},
		{"ShouldRejectRawEventMemberType", email, map[string]any{"level": 1}, ErrInvalidSecurityEvent},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			claims, err := NewSecurityEventTokenClaims("https://issuer.example.com", []string{"aud"}, tc.subject, RawSecurityEvent{URI: uri, Claims: tc.claims}, "")

			if tc.err == nil {
				require.NoError(t, err)
				assert.NoError(t, claims.Valid())

				return
			}

			assert.Nil(t, claims)
			assert.ErrorIs(t, err, ErrInvalidSecurityEvent)
			assert.ErrorIs(t, err, tc.err)
		})
	}

	t.Run("ShouldValidateSubjectInValid", func(t *testing.T) {
		claims, err := NewSecurityEventTokenClaims("https://issuer.example.com", []string{"aud"}, email, RawSecurityEvent{URI: uri, Claims: map[string]any{"level": "high"}}, "")
		require.NoError(t, err)

		claims.SubjectIdentifier = opaque

		var vErr *ValidationError

		require.ErrorAs(t, claims.Valid(), &vErr)
		assert.Equal(t, ValidationErrorClaimsInvalid, vErr.Errors)
		assert.ErrorIs(t, vErr.Inner, errRegisteredSubject)
	})
}

var (
	errRegisteredLevel   = errors.New("the level is not valid")
	errRegisteredSubject = errors.New("the subject must be an email")
)

type registeredEvent struct {
	Level string `json:"level"`
}

func (*registeredEvent) SecurityEventType() string {
	return "https://example.com/event/registered"
}

func (e *registeredEvent) Validate() error {
	if e.Level != "high" {
		return errRegisteredLevel
	}

	return nil
}

func (*registeredEvent) ValidateSubject(subject *SubjectIdentifier) error {
	if subject.Format != SubjectIdentifierFormatEmail {
		return errRegisteredSubject
	}

	return nil
}
