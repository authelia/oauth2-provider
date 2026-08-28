// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
)

func TestCompareClientSecretHonoursTheSecretExpiry(t *testing.T) {
	const secret = "foobarfoobarfoobarfoobar"

	newClient := func(expires time.Time) *oauth2.DefaultRegisteredClient {
		return &oauth2.DefaultRegisteredClient{
			DefaultClient: &oauth2.DefaultClient{
				ID:           "test",
				ClientSecret: oauth2.NewPlainTextClientSecret(secret),
			},
			ClientSecretExpiresAt: expires,
		}
	}

	testCases := []struct {
		name    string
		expires time.Time
		err     bool
	}{
		{name: "ShouldAcceptWhenTheSecretDoesNotExpire", expires: time.Time{}},
		{name: "ShouldAcceptWhenTheSecretHasNotExpired", expires: time.Now().Add(time.Hour)},
		{name: "ShouldRejectWhenTheSecretHasExpired", expires: time.Now().Add(-time.Hour), err: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := oauth2.CompareClientSecret(t.Context(), newClient(tc.expires), []byte(secret))

			if !tc.err {
				assert.NoError(t, err)

				return
			}

			require.Error(t, err)
			assert.Contains(t, err.Error(), "expired")
		})
	}
}
