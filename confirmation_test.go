// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2/token/jwt"
)

func TestApplyConfirmation(t *testing.T) {
	testCases := []struct {
		name     string
		claims   map[string]any
		session  Session
		expected map[string]any
	}{
		{
			name:     "ShouldAddConfirmationWhenBound",
			claims:   map[string]any{jwt.ClaimSubject: "peter"},
			session:  confirmationSession("test-jkt"),
			expected: map[string]any{jwt.ClaimSubject: "peter", jwt.ClaimConfirmation: map[string]any{jwt.ClaimConfirmationJWKThumbprint: "test-jkt"}},
		},
		{
			name:     "ShouldNotAddConfirmationWhenUnbound",
			claims:   map[string]any{jwt.ClaimSubject: "peter"},
			session:  confirmationSession(""),
			expected: map[string]any{jwt.ClaimSubject: "peter"},
		},
		{
			name:     "ShouldNotAddConfirmationWhenSessionDoesNotSupportBinding",
			claims:   map[string]any{jwt.ClaimSubject: "peter"},
			session:  &plainSession{},
			expected: map[string]any{jwt.ClaimSubject: "peter"},
		},
		{
			name:     "ShouldNotAddConfirmationWhenSessionIsNil",
			claims:   map[string]any{jwt.ClaimSubject: "peter"},
			session:  nil,
			expected: map[string]any{jwt.ClaimSubject: "peter"},
		},
		{
			name:     "ShouldRemoveThumbprintTheSessionDoesNotAssert",
			claims:   map[string]any{jwt.ClaimConfirmation: map[string]any{jwt.ClaimConfirmationJWKThumbprint: "forged-jkt"}},
			session:  confirmationSession(""),
			expected: map[string]any{},
		},
		{
			name:     "ShouldOverwriteThumbprintTheSessionDidNotEstablish",
			claims:   map[string]any{jwt.ClaimConfirmation: map[string]any{jwt.ClaimConfirmationJWKThumbprint: "forged-jkt"}},
			session:  confirmationSession("test-jkt"),
			expected: map[string]any{jwt.ClaimConfirmation: map[string]any{jwt.ClaimConfirmationJWKThumbprint: "test-jkt"}},
		},
		{
			// A confirmation method the session does not record is not the server's assertion to make, whichever RFC
			// defines it. Once RFC 8705 records 'x5t#S256' on the session it is emitted from there, not from here.
			name:     "ShouldDiscardConfirmationMethodsNotRecordedOnTheSession",
			claims:   map[string]any{jwt.ClaimConfirmation: map[string]any{jwt.ClaimConfirmationX509SHA256Thumbprint: "forged-x5t"}},
			session:  confirmationSession("test-jkt"),
			expected: map[string]any{jwt.ClaimConfirmation: map[string]any{jwt.ClaimConfirmationJWKThumbprint: "test-jkt"}},
		},
		{
			name:     "ShouldDiscardConfirmationMethodsNotRecordedOnTheSessionWhenUnbound",
			claims:   map[string]any{jwt.ClaimConfirmation: map[string]any{jwt.ClaimConfirmationX509SHA256Thumbprint: "forged-x5t"}},
			session:  confirmationSession(""),
			expected: map[string]any{},
		},
		{
			name:     "ShouldDiscardConfirmationThatIsNotAnObject",
			claims:   map[string]any{jwt.ClaimConfirmation: "not-an-object"},
			session:  confirmationSession("test-jkt"),
			expected: map[string]any{jwt.ClaimConfirmation: map[string]any{jwt.ClaimConfirmationJWKThumbprint: "test-jkt"}},
		},
		{
			name:     "ShouldDiscardConfirmationThatIsNotAnObjectWhenUnbound",
			claims:   map[string]any{jwt.ClaimConfirmation: "not-an-object"},
			session:  confirmationSession(""),
			expected: map[string]any{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ApplyConfirmation(tc.claims, tc.session)

			assert.Equal(t, tc.expected, tc.claims)
		})
	}

	t.Run("ShouldHandleNilClaims", func(t *testing.T) {
		assert.NotPanics(t, func() {
			ApplyConfirmation(nil, confirmationSession("test-jkt"))
		})
	})
}

func TestRestoreConfirmation(t *testing.T) {
	testCases := []struct {
		name     string
		claims   map[string]any
		expected string
	}{
		{
			name:     "ShouldRestoreThumbprint",
			claims:   map[string]any{jwt.ClaimConfirmation: map[string]any{jwt.ClaimConfirmationJWKThumbprint: "test-jkt"}},
			expected: "test-jkt",
		},
		{
			name:     "ShouldRestoreThumbprintFromMapClaims",
			claims:   map[string]any{jwt.ClaimConfirmation: jwt.MapClaims{jwt.ClaimConfirmationJWKThumbprint: "test-jkt"}},
			expected: "test-jkt",
		},
		{
			name:     "ShouldRestoreNothingWhenConfirmationAbsent",
			claims:   map[string]any{jwt.ClaimSubject: "peter"},
			expected: "",
		},
		{
			name:     "ShouldRestoreNothingWhenConfirmationIsNotAnObject",
			claims:   map[string]any{jwt.ClaimConfirmation: "not-an-object"},
			expected: "",
		},
		{
			name:     "ShouldRestoreNothingWhenThumbprintIsNotAString",
			claims:   map[string]any{jwt.ClaimConfirmation: map[string]any{jwt.ClaimConfirmationJWKThumbprint: 1}},
			expected: "",
		},
		{
			name:     "ShouldRestoreNothingWhenThumbprintIsEmpty",
			claims:   map[string]any{jwt.ClaimConfirmation: map[string]any{jwt.ClaimConfirmationJWKThumbprint: ""}},
			expected: "",
		},
		{
			name:     "ShouldRestoreNothingFromAnotherConfirmationMethod",
			claims:   map[string]any{jwt.ClaimConfirmation: map[string]any{jwt.ClaimConfirmationX509SHA256Thumbprint: "some-x5t"}},
			expected: "",
		},
		{
			name:     "ShouldRestoreNothingWhenNilClaims",
			claims:   nil,
			expected: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			session := &DefaultSession{}

			RestoreConfirmation(tc.claims, session)

			assert.Equal(t, tc.expected, session.GetDPoPJWKThumbprint())
		})
	}

	t.Run("ShouldHandleSessionThatDoesNotSupportBinding", func(t *testing.T) {
		assert.NotPanics(t, func() {
			RestoreConfirmation(map[string]any{jwt.ClaimConfirmation: map[string]any{jwt.ClaimConfirmationJWKThumbprint: "test-jkt"}}, &plainSession{})
		})
	})
}

func TestConfirmationRoundTrip(t *testing.T) {
	require.NotEmpty(t, confirmationMethods)

	for _, method := range confirmationMethods {
		t.Run(method.name, func(t *testing.T) {
			source := &DefaultSession{}
			method.set(source, "round-trip-value")

			require.Equal(t, "round-trip-value", method.get(source), "DefaultSession does not record the '%s' confirmation method; give it the accessors that method's interface requires, as it does for DPoPBoundSession", method.name)

			claims := map[string]any{}
			ApplyConfirmation(claims, source)

			cnf, ok := claims[jwt.ClaimConfirmation].(map[string]any)
			require.True(t, ok, "expected cnf to be present and a map, got %#v", claims[jwt.ClaimConfirmation])
			assert.Equal(t, "round-trip-value", cnf[method.name])

			restored := &DefaultSession{}
			RestoreConfirmation(claims, restored)

			assert.Equal(t, "round-trip-value", method.get(restored), "the '%s' confirmation method was not recovered from the claims it was written to", method.name)
		})
	}
}

func TestGetDPoPConfirmationJWKThumbprint(t *testing.T) {
	testCases := []struct {
		name     string
		claims   map[string]any
		expected string
	}{
		{"ShouldReturnThumbprint", map[string]any{jwt.ClaimConfirmation: map[string]any{jwt.ClaimConfirmationJWKThumbprint: "test-jkt"}}, "test-jkt"},
		{"ShouldReturnThumbprintFromMapClaims", map[string]any{jwt.ClaimConfirmation: jwt.MapClaims{jwt.ClaimConfirmationJWKThumbprint: "test-jkt"}}, "test-jkt"},
		{"ShouldReturnEmptyWhenAbsent", map[string]any{}, ""},
		{"ShouldReturnEmptyWhenNilClaims", nil, ""},
		{"ShouldReturnEmptyWhenNotAnObject", map[string]any{jwt.ClaimConfirmation: "not-an-object"}, ""},
		{"ShouldReturnEmptyWhenNoThumbprint", map[string]any{jwt.ClaimConfirmation: map[string]any{jwt.ClaimConfirmationX509SHA256Thumbprint: "some-x5t"}}, ""},
		{"ShouldReturnEmptyWhenThumbprintNotAString", map[string]any{jwt.ClaimConfirmation: map[string]any{jwt.ClaimConfirmationJWKThumbprint: 1}}, ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, GetDPoPConfirmationJWKThumbprint(tc.claims))
		})
	}
}

func TestApplyConfirmationMTLS(t *testing.T) {
	testCases := []struct {
		name     string
		claims   map[string]any
		session  Session
		expected map[string]any
	}{
		{
			name:     "ShouldAddCertificateThumbprintWhenBound",
			claims:   map[string]any{jwt.ClaimSubject: "peter"},
			session:  confirmationSessionMTLS("", "test-x5t"),
			expected: map[string]any{jwt.ClaimSubject: "peter", jwt.ClaimConfirmation: map[string]any{jwt.ClaimConfirmationX509SHA256Thumbprint: "test-x5t"}},
		},
		{
			name:    "ShouldAddBothConfirmationMethodsWhenBoundByBoth",
			claims:  map[string]any{jwt.ClaimSubject: "peter"},
			session: confirmationSessionMTLS("test-jkt", "test-x5t"),
			expected: map[string]any{jwt.ClaimSubject: "peter", jwt.ClaimConfirmation: map[string]any{
				jwt.ClaimConfirmationJWKThumbprint:        "test-jkt",
				jwt.ClaimConfirmationX509SHA256Thumbprint: "test-x5t",
			}},
		},
		{
			name:     "ShouldNotAddCertificateThumbprintWhenUnbound",
			claims:   map[string]any{jwt.ClaimSubject: "peter"},
			session:  confirmationSessionMTLS("", ""),
			expected: map[string]any{jwt.ClaimSubject: "peter"},
		},
		{
			name:     "ShouldRemoveCertificateThumbprintTheSessionDoesNotAssert",
			claims:   map[string]any{jwt.ClaimConfirmation: map[string]any{jwt.ClaimConfirmationX509SHA256Thumbprint: "forged-x5t"}},
			session:  confirmationSessionMTLS("", ""),
			expected: map[string]any{},
		},
		{
			name:     "ShouldOverwriteCertificateThumbprintTheSessionDidNotEstablish",
			claims:   map[string]any{jwt.ClaimConfirmation: map[string]any{jwt.ClaimConfirmationX509SHA256Thumbprint: "forged-x5t"}},
			session:  confirmationSessionMTLS("", "test-x5t"),
			expected: map[string]any{jwt.ClaimConfirmation: map[string]any{jwt.ClaimConfirmationX509SHA256Thumbprint: "test-x5t"}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ApplyConfirmation(tc.claims, tc.session)

			assert.Equal(t, tc.expected, tc.claims)
		})
	}
}

func TestConfirmationMTLSRoundTrip(t *testing.T) {
	claims := map[string]any{jwt.ClaimSubject: "peter"}

	ApplyConfirmation(claims, confirmationSessionMTLS("test-jkt", "test-x5t"))

	restored := &DefaultSession{}

	RestoreConfirmation(claims, restored)

	assert.Equal(t, "test-x5t", restored.GetClientCertificateSHA256Thumbprint())
	assert.Equal(t, "test-jkt", restored.GetDPoPJWKThumbprint())
}

func TestGetMTLSConfirmationX509SHA256Thumbprint(t *testing.T) {
	testCases := []struct {
		name     string
		claims   map[string]any
		expected string
	}{
		{name: "ShouldReturnTheThumbprint", claims: map[string]any{jwt.ClaimConfirmation: map[string]any{jwt.ClaimConfirmationX509SHA256Thumbprint: "test-x5t"}}, expected: "test-x5t"},
		{name: "ShouldReturnEmptyWhenAbsent", claims: map[string]any{}, expected: ""},
		{name: "ShouldReturnEmptyWhenConfirmationIsNotAnObject", claims: map[string]any{jwt.ClaimConfirmation: "not-an-object"}, expected: ""},
		{name: "ShouldReturnEmptyWhenTheMemberIsNotAString", claims: map[string]any{jwt.ClaimConfirmation: map[string]any{jwt.ClaimConfirmationX509SHA256Thumbprint: 42}}, expected: ""},
		{name: "ShouldReturnEmptyForNilClaims", claims: nil, expected: ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, GetMTLSConfirmationX509SHA256Thumbprint(tc.claims))
		})
	}
}

func TestDefaultSessionMTLSBinding(t *testing.T) {
	var session *DefaultSession

	assert.Empty(t, session.GetClientCertificateSHA256Thumbprint())

	session = &DefaultSession{}

	assert.Empty(t, session.GetClientCertificateSHA256Thumbprint())

	session.SetClientCertificateSHA256Thumbprint("test-x5t")

	assert.Equal(t, "test-x5t", session.GetClientCertificateSHA256Thumbprint())
}

func confirmationSessionMTLS(jkt, x5t string) Session {
	session := &DefaultSession{}
	session.SetDPoPJWKThumbprint(jkt)
	session.SetClientCertificateSHA256Thumbprint(x5t)

	return session
}

func confirmationSession(jkt string) Session {
	session := &DefaultSession{}
	session.SetDPoPJWKThumbprint(jkt)

	return session
}

type plainSession struct {
	Session
}
