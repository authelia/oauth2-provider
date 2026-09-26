// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2/token/jwt"
)

func TestFmtDecodeErrorNilToken(t *testing.T) {
	testCases := []struct {
		name  string
		flags uint32
	}{
		{"ShouldHandleKeyIDInvalid", jwt.ValidationErrorHeaderKeyIDInvalid},
		{"ShouldHandleAlgorithmInvalid", jwt.ValidationErrorHeaderAlgorithmInvalid},
		{"ShouldHandleTypeInvalid", jwt.ValidationErrorHeaderTypeInvalid},
		{"ShouldHandleEncryptionTypeInvalid", jwt.ValidationErrorHeaderEncryptionTypeInvalid},
		{"ShouldHandleContentTypeInvalid", jwt.ValidationErrorHeaderContentTypeInvalid},
		{"ShouldHandleEncryptionKeyIDInvalid", jwt.ValidationErrorHeaderEncryptionKeyIDInvalid},
		{"ShouldHandleKeyAlgorithmInvalid", jwt.ValidationErrorHeaderKeyAlgorithmInvalid},
		{"ShouldHandleContentEncryptionInvalid", jwt.ValidationErrorHeaderContentEncryptionInvalid},
		{"ShouldHandleExpired", jwt.ValidationErrorExpired},
		{"ShouldHandleIssuedAt", jwt.ValidationErrorIssuedAt},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			inner := &jwt.ValidationError{Errors: tc.flags, Inner: errors.New("failure")}

			client := &DefaultJARClient{DefaultClient: &DefaultClient{ID: "test"}}

			var actual *RFC6749Error

			require.NotPanics(t, func() {
				actual = fmtClientAssertionDecodeError(nil, client, &TokenEndpointClientAuthStrategy{}, nil, inner)
			})

			assert.ErrorIs(t, actual, ErrInvalidClient)

			require.NotPanics(t, func() {
				actual = fmtRequestObjectDecodeError(nil, client, "https://auth.example.com", true, inner)
			})

			assert.ErrorIs(t, actual, ErrInvalidRequestObject)
		})
	}
}

func TestFmtDecodeErrorAbsentDateClaims(t *testing.T) {
	client := &DefaultJARClient{DefaultClient: &DefaultClient{ID: "test"}}

	testCases := []struct {
		name     string
		flags    uint32
		format   func(token *jwt.Token, inner error) error
		expected string
	}{
		{
			name:  "ShouldHandleClientAssertionExpired",
			flags: jwt.ValidationErrorExpired,
			format: func(token *jwt.Token, inner error) error {
				return fmtClientAssertionDecodeError(token, client, &TokenEndpointClientAuthStrategy{}, nil, inner)
			},
			expected: "The client assertion does not have an 'exp' claim or it has an invalid type.",
		},
		{
			name:  "ShouldHandleClientAssertionIssuedAt",
			flags: jwt.ValidationErrorIssuedAt,
			format: func(token *jwt.Token, inner error) error {
				return fmtClientAssertionDecodeError(token, client, &TokenEndpointClientAuthStrategy{}, nil, inner)
			},
			expected: "The client assertion does not have an 'iat' claim or it has an invalid type.",
		},
		{
			name:  "ShouldHandleClientAssertionNotValidYet",
			flags: jwt.ValidationErrorNotValidYet,
			format: func(token *jwt.Token, inner error) error {
				return fmtClientAssertionDecodeError(token, client, &TokenEndpointClientAuthStrategy{}, nil, inner)
			},
			expected: "The client assertion does not have an 'nbf' claim or it has an invalid type.",
		},
		{
			name:  "ShouldHandleRequestObjectIssuedAt",
			flags: jwt.ValidationErrorIssuedAt,
			format: func(token *jwt.Token, inner error) error {
				return fmtRequestObjectDecodeError(token, client, "https://auth.example.com", true, inner)
			},
			expected: "The request object does not have an 'iat' claim or it has an invalid type.",
		},
		{
			name:  "ShouldHandleRequestObjectLifetime",
			flags: jwt.ValidationErrorLifetime,
			format: func(token *jwt.Token, inner error) error {
				return fmtRequestObjectDecodeError(token, client, "https://auth.example.com", true, inner)
			},
			expected: "provided a request object that exceeds the maximum lifetime. The request object does not have both an 'nbf' and an 'exp' claim.",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			inner := &jwt.ValidationError{Errors: tc.flags, Inner: errors.New("failure")}

			actual := ErrorToDebugRFC6749Error(tc.format(&jwt.Token{Claims: jwt.MapClaims{}}, inner)).Error()

			assert.Contains(t, actual, tc.expected)
			assert.NotContains(t, actual, " 0.")
		})
	}
}
