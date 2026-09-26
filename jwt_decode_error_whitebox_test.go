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
