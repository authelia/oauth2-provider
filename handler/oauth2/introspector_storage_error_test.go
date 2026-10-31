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
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.ErrorIs(t, IntrospectionStorageError(tc.err), tc.expected)
		})
	}
}
