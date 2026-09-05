// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestApplyConfirmation(t *testing.T) {
	testCases := []struct {
		name     string
		claims   map[string]any
		session  Session
		config   ConfirmationConfigProvider
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
		{
			name:     "ShouldNotAssertDPoPWhenTheMethodIsDisabled",
			claims:   map[string]any{jwt.ClaimSubject: "peter"},
			session:  confirmationSession("test-jkt"),
			config:   &Config{DPoPEnabled: false, MTLSEnabled: true},
			expected: map[string]any{jwt.ClaimSubject: "peter"},
		},
		{
			name:     "ShouldNotAssertMTLSWhenTheMethodIsDisabled",
			claims:   map[string]any{jwt.ClaimSubject: "peter"},
			session:  confirmationSessionMTLS("", "test-x5t"),
			config:   &Config{DPoPEnabled: true, MTLSEnabled: false},
			expected: map[string]any{jwt.ClaimSubject: "peter"},
		},
		{
			name:     "ShouldAssertOnlyTheEnabledMethod",
			claims:   map[string]any{jwt.ClaimSubject: "peter"},
			session:  confirmationSessionMTLS("test-jkt", "test-x5t"),
			config:   &Config{DPoPEnabled: true, MTLSEnabled: false},
			expected: map[string]any{jwt.ClaimSubject: "peter", jwt.ClaimConfirmation: map[string]any{jwt.ClaimConfirmationJWKThumbprint: "test-jkt"}},
		},
		{
			name:     "ShouldRemoveExistingConfirmationWhenEveryMethodIsDisabled",
			claims:   map[string]any{jwt.ClaimConfirmation: map[string]any{jwt.ClaimConfirmationJWKThumbprint: "forged-jkt"}},
			session:  confirmationSessionMTLS("test-jkt", "test-x5t"),
			config:   &Config{DPoPEnabled: false, MTLSEnabled: false},
			expected: map[string]any{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := tc.config
			if config == nil {
				config = &Config{DPoPEnabled: true, MTLSEnabled: true}
			}

			ApplyConfirmation(context.Background(), config, tc.claims, tc.session)

			assert.Equal(t, tc.expected, tc.claims)
		})
	}

	t.Run("ShouldHandleNilClaims", func(t *testing.T) {
		assert.NotPanics(t, func() {
			ApplyConfirmation(context.Background(), &Config{DPoPEnabled: true, MTLSEnabled: true}, nil, confirmationSession("test-jkt"))
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
			ApplyConfirmation(context.Background(), &Config{DPoPEnabled: true, MTLSEnabled: true}, claims, source)

			cnf, ok := claims[jwt.ClaimConfirmation].(map[string]any)
			require.Truef(t, ok, "cnf is absent or not a map, got %#v", claims[jwt.ClaimConfirmation])
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
			ApplyConfirmation(context.Background(), &Config{DPoPEnabled: true, MTLSEnabled: true}, tc.claims, tc.session)

			assert.Equal(t, tc.expected, tc.claims)
		})
	}
}

func TestConfirmationMTLSRoundTrip(t *testing.T) {
	claims := map[string]any{jwt.ClaimSubject: "peter"}

	ApplyConfirmation(context.Background(), &Config{DPoPEnabled: true, MTLSEnabled: true}, claims, confirmationSessionMTLS("test-jkt", "test-x5t"))

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

func TestApplyIDTokenConfirmation(t *testing.T) {
	const rawJWK = `{"crv":"P-256","kty":"EC","x":"x","y":"y"}`

	newRequest := func(grant string, scopes []string, jwk []byte) *AccessRequest {
		session := &DefaultSession{}

		if jwk != nil {
			session.SetDPoPJWKThumbprint("thumbprint")
			session.SetRequestedDPoPJWKThumbprint("thumbprint")
			session.SetDPoPPublicKeyJWK(jwk)
		}

		if Arguments(scopes).Has(consts.ScopeBoundKey) {
			session.SetOIDCKeyBindingGranted(true)
		}

		request := NewAccessRequest(session)
		request.GrantTypes = Arguments{grant}
		request.GrantedScope = Arguments(scopes)

		return request
	}

	testCases := []struct {
		name     string
		enabled  bool
		request  *AccessRequest
		expected bool
		err      string
	}{
		{
			name:     "ShouldEmitForAuthorizationCode",
			enabled:  true,
			request:  newRequest(consts.GrantTypeAuthorizationCode, []string{consts.ScopeOpenID, consts.ScopeBoundKey}, []byte(rawJWK)),
			expected: true,
		},
		{
			name:     "ShouldEmitForDeviceCode",
			enabled:  true,
			request:  newRequest(consts.GrantTypeOAuthDeviceCode, []string{consts.ScopeOpenID, consts.ScopeBoundKey}, []byte(rawJWK)),
			expected: true,
		},
		{
			name:     "ShouldEmitForRefreshToken",
			enabled:  true,
			request:  newRequest(consts.GrantTypeRefreshToken, []string{consts.ScopeOpenID, consts.ScopeBoundKey}, []byte(rawJWK)),
			expected: true,
		},
		{
			name:     "ShouldNotEmitWhenDisabled",
			enabled:  false,
			request:  newRequest(consts.GrantTypeAuthorizationCode, []string{consts.ScopeOpenID, consts.ScopeBoundKey}, []byte(rawJWK)),
			expected: false,
		},
		{
			name:     "ShouldNotEmitForTokenExchange",
			enabled:  true,
			request:  newRequest(consts.GrantTypeOAuthTokenExchange, []string{consts.ScopeOpenID, consts.ScopeBoundKey}, []byte(rawJWK)),
			expected: false,
		},
		{
			name:     "ShouldNotEmitWhenBoundKeyNotGranted",
			enabled:  true,
			request:  newRequest(consts.GrantTypeAuthorizationCode, []string{consts.ScopeOpenID}, []byte(rawJWK)),
			expected: false,
		},
		{
			name:     "ShouldNotEmitWhenNoKeyRecordedAndNotBound",
			enabled:  true,
			request:  newRequest(consts.GrantTypeAuthorizationCode, []string{consts.ScopeOpenID}, nil),
			expected: false,
		},
		{
			name:    "ShouldErrorWhenBoundKeyGrantedButUnproven",
			enabled: true,
			request: func() *AccessRequest {
				r := newRequest(consts.GrantTypeAuthorizationCode, []string{consts.ScopeOpenID, consts.ScopeBoundKey}, nil)
				r.GetSession().(*DefaultSession).SetDPoPJWKThumbprint("thumbprint")

				return r
			}(),
			expected: false,
			err:      "The request requires a DPoP proof",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.WithValue(t.Context(), AccessRequestContextKey, AccessRequester(tc.request))

			claims, headers := &jwt.IDTokenClaims{Subject: "sub"}, &jwt.Headers{}

			err := ApplyIDTokenConfirmation(ctx, &Config{OIDCKeyBindingEnabled: tc.enabled, DPoPEnabled: true}, claims, headers)

			if tc.err != "" {
				require.Error(t, err)
				assert.Contains(t, ErrorToDebugRFC6749Error(err).Error(), tc.err)

				return
			}

			require.NoError(t, err)

			if !tc.expected {
				assert.Empty(t, claims.Confirmation)
				assert.Nil(t, headers.Get(jwt.JSONWebTokenHeaderType))

				return
			}

			require.NotNil(t, claims.Confirmation)
			assert.Equal(t, jwt.JSONWebTokenTypeDPoPIDToken, headers.Get(jwt.JSONWebTokenHeaderType))

			key, ok := claims.Confirmation[jwt.ClaimConfirmationJWK].(map[string]any)
			require.True(t, ok)
			assert.Equal(t, "EC", key["kty"])
		})
	}
}

func TestApplyIDTokenConfirmation_NoAccessRequestInContext(t *testing.T) {
	claims, headers := &jwt.IDTokenClaims{Subject: "sub"}, &jwt.Headers{}

	require.NoError(t, ApplyIDTokenConfirmation(t.Context(), &Config{OIDCKeyBindingEnabled: true, DPoPEnabled: true}, claims, headers))

	assert.Empty(t, claims.Confirmation)
	assert.Nil(t, headers.Get(jwt.JSONWebTokenHeaderType))
}

func TestApplyIDTokenConfirmation_ClearsPreexistingConfirmation(t *testing.T) {
	claims := &jwt.IDTokenClaims{Subject: "sub", Confirmation: map[string]any{"jkt": "spoofed"}}

	require.NoError(t, ApplyIDTokenConfirmation(t.Context(), &Config{}, claims, &jwt.Headers{}))

	assert.Empty(t, claims.Confirmation)
}

func TestApplyIDTokenConfirmation_ClearsPreexistingHeaderType(t *testing.T) {
	t.Run("ShouldRemoveTheKeyBindingType", func(t *testing.T) {
		claims := &jwt.IDTokenClaims{Subject: "sub"}
		headers := &jwt.Headers{Extra: map[string]any{jwt.JSONWebTokenHeaderType: jwt.JSONWebTokenTypeDPoPIDToken}}

		require.NoError(t, ApplyIDTokenConfirmation(t.Context(), &Config{OIDCKeyBindingEnabled: true, DPoPEnabled: true}, claims, headers))

		assert.Empty(t, claims.Confirmation)
		assert.Nil(t, headers.Get(jwt.JSONWebTokenHeaderType))
	})

	t.Run("ShouldPreserveADeploymentsOwnType", func(t *testing.T) {
		claims := &jwt.IDTokenClaims{Subject: "sub"}
		headers := &jwt.Headers{Extra: map[string]any{jwt.JSONWebTokenHeaderType: "JWT"}}

		require.NoError(t, ApplyIDTokenConfirmation(t.Context(), &Config{OIDCKeyBindingEnabled: true, DPoPEnabled: true}, claims, headers))

		assert.Empty(t, claims.Confirmation)
		assert.Equal(t, "JWT", headers.Get(jwt.JSONWebTokenHeaderType))
	})
}

func TestApplyIDTokenConfirmation_NilHeaders(t *testing.T) {
	session := &DefaultSession{}
	session.SetDPoPJWKThumbprint("thumbprint")
	session.SetRequestedDPoPJWKThumbprint("thumbprint")
	session.SetOIDCKeyBindingGranted(true)
	session.SetDPoPPublicKeyJWK([]byte(`{"crv":"P-256","kty":"EC","x":"x","y":"y"}`))

	request := NewAccessRequest(session)
	request.GrantTypes = Arguments{consts.GrantTypeAuthorizationCode}
	request.GrantedScope = Arguments{consts.ScopeOpenID, consts.ScopeBoundKey}

	ctx := context.WithValue(t.Context(), AccessRequestContextKey, AccessRequester(request))

	claims := &jwt.IDTokenClaims{Subject: "peter"}

	err := ApplyIDTokenConfirmation(ctx, &Config{OIDCKeyBindingEnabled: true, DPoPEnabled: true}, claims, nil)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrServerError)
	assert.Empty(t, claims.Confirmation)
}

func TestApplyIDTokenConfirmation_DPoPDisabled(t *testing.T) {
	session := &DefaultSession{}
	session.SetDPoPJWKThumbprint("thumbprint")
	session.SetRequestedDPoPJWKThumbprint("thumbprint")
	session.SetOIDCKeyBindingGranted(true)
	session.SetDPoPPublicKeyJWK([]byte(`{"crv":"P-256","kty":"EC","x":"x","y":"y"}`))

	request := NewAccessRequest(session)
	request.GrantTypes = Arguments{consts.GrantTypeRefreshToken}
	request.GrantedScope = Arguments{consts.ScopeOpenID, consts.ScopeBoundKey}

	ctx := context.WithValue(t.Context(), AccessRequestContextKey, AccessRequester(request))

	claims, headers := &jwt.IDTokenClaims{Subject: "peter"}, &jwt.Headers{}

	require.NoError(t, ApplyIDTokenConfirmation(ctx, &Config{OIDCKeyBindingEnabled: true, DPoPEnabled: false}, claims, headers))

	assert.Empty(t, claims.Confirmation)
	assert.Nil(t, headers.Get(consts.JSONWebTokenHeaderType))
}

type plainSession struct {
	Session
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
