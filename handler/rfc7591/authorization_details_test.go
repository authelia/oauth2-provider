// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7591

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal"
)

func TestCheckAuthorizationDetailsTypes(t *testing.T) {
	enabled := &oauth2.Config{AuthorizationDetailsTypeHandlers: []oauth2.AuthorizationDetailsTypeHandler{internal.PaymentInitiationTypeHandler{}}}

	testCases := []struct {
		name    string
		config  any
		types   []string
		err     bool
		ignored bool
	}{
		{name: "ShouldAcceptAbsent", config: &oauth2.Config{}},
		{name: "ShouldAcceptSupported", config: enabled, types: []string{internal.AuthorizationDetailsTypePaymentInitiation}},
		{name: "ShouldRejectUnsupported", config: enabled, types: []string{internal.AuthorizationDetailsTypePaymentInitiation, "account_information"}, err: true},
		{name: "ShouldIgnoreWhenDisabled", config: &oauth2.Config{}, types: []string{internal.AuthorizationDetailsTypePaymentInitiation}, ignored: true},
		{name: "ShouldIgnoreEmptyWhenDisabled", config: &oauth2.Config{}, types: []string{}, ignored: true},
		{name: "ShouldKeepEmptyWhenEnabled", config: enabled, types: []string{}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			metadata := &oauth2.ClientRegistrationMetadata{AuthorizationDetailsTypes: tc.types}

			err := CheckAuthorizationDetailsTypes(context.Background(), tc.config, metadata)

			if !tc.err {
				assert.NoError(t, err)

				if tc.ignored {
					assert.Nil(t, metadata.AuthorizationDetailsTypes)
				} else {
					assert.Equal(t, tc.types, metadata.AuthorizationDetailsTypes)
				}

				return
			}

			require.Error(t, err)
			assert.ErrorIs(t, err, oauth2.ErrInvalidClientMetadata)
		})
	}
}
