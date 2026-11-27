// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"authelia.com/provider/oauth2"
)

func TestIntrospectionStorageError(t *testing.T) {
	testCases := []struct {
		name     string
		err      error
		expected error
	}{
		{name: "ShouldReportAPlainErrorAsAServerError", err: errors.New("the database is unavailable"), expected: oauth2.ErrServerError},
		{name: "ShouldReportAPointerRejection", err: oauth2.ErrInactiveToken, expected: oauth2.ErrRequestUnauthorized},
		{name: "ShouldReportAValueRejection", err: *oauth2.ErrInactiveToken, expected: oauth2.ErrRequestUnauthorized},
		{name: "ShouldReportAWrappedValueRejection", err: fmt.Errorf("lookup: %w", error(*oauth2.ErrInactiveToken)), expected: oauth2.ErrRequestUnauthorized},
		{name: "ShouldReportAPointerServerError", err: oauth2.ErrServerError, expected: oauth2.ErrServerError},
		{name: "ShouldReportAValueServerError", err: *oauth2.ErrServerError, expected: oauth2.ErrServerError},
		{name: "ShouldPassThroughAPointerTemporarilyUnavailable", err: oauth2.ErrTemporarilyUnavailable, expected: oauth2.ErrTemporarilyUnavailable},
		{name: "ShouldPassThroughAWrappedTemporarilyUnavailable", err: fmt.Errorf("lookup: %w", error(oauth2.ErrTemporarilyUnavailable.WithHint("x"))), expected: oauth2.ErrTemporarilyUnavailable},
		{name: "ShouldPassThroughAValueTemporarilyUnavailable", err: *oauth2.ErrTemporarilyUnavailable, expected: oauth2.ErrTemporarilyUnavailable},
		{name: "ShouldReportAnUnrecognizableErrorAsAServerError", err: oauth2.ErrorToRFC6749Error(errors.New("the database is unavailable")), expected: oauth2.ErrServerError},
		{name: "ShouldPassThroughMisconfiguration", err: oauth2.ErrMisconfiguration, expected: oauth2.ErrMisconfiguration},
		{name: "ShouldReportAValueServerErrorWrappingAPointerRejection", err: *oauth2.ErrServerError.WithWrap(oauth2.ErrInactiveToken), expected: oauth2.ErrServerError},
		{name: "ShouldPassThroughAValueTemporarilyUnavailableWrappingAPointerRejection", err: *oauth2.ErrTemporarilyUnavailable.WithWrap(oauth2.ErrInactiveToken), expected: oauth2.ErrTemporarilyUnavailable},
		{name: "ShouldReportAValueRejectionWrappingAPointerServerError", err: *oauth2.ErrInactiveToken.WithWrap(oauth2.ErrServerError), expected: oauth2.ErrRequestUnauthorized},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := IntrospectionStorageError(tc.err)

			assert.ErrorIs(t, actual, tc.expected)
			assert.Equal(t, oauth2.ErrorToRFC6749Error(tc.expected).ErrorField, actual.ErrorField)
		})
	}
}

func TestPreferDefiniteIntrospectionError(t *testing.T) {
	testCases := []struct {
		name      string
		primary   error
		secondary error
		expected  error
	}{
		{name: "ShouldPreferARejectionOverAnUnavailableStore", primary: oauth2.ErrTemporarilyUnavailable, secondary: oauth2.ErrRequestUnauthorized, expected: oauth2.ErrRequestUnauthorized},
		{name: "ShouldPreferARejectionOverAServerError", primary: oauth2.ErrServerError, secondary: oauth2.ErrRequestUnauthorized, expected: oauth2.ErrRequestUnauthorized},
		{name: "ShouldPreferAnUnavailableStoreOverAnUnknownToken", primary: oauth2.ErrUnknownRequest, secondary: oauth2.ErrTemporarilyUnavailable, expected: oauth2.ErrTemporarilyUnavailable},
		{name: "ShouldPreferAServerErrorOverAnUnknownToken", primary: oauth2.ErrUnknownRequest, secondary: oauth2.ErrServerError, expected: oauth2.ErrServerError},
		{name: "ShouldPreferThePrimaryUnknownToken", primary: oauth2.ErrUnknownRequest, secondary: oauth2.ErrNotFound, expected: oauth2.ErrUnknownRequest},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.ErrorIs(t, preferDefiniteIntrospectionError(tc.primary, tc.secondary), tc.expected)
		})
	}
}
