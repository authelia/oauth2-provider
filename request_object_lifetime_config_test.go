// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestConfigGetRequestObjectMaximumLifetime(t *testing.T) {
	testCases := []struct {
		name     string
		have     time.Duration
		expected time.Duration
	}{
		{"ShouldDefaultWhenZero", 0, time.Hour},
		{"ShouldDisableWhenNegative", -time.Second, 0},
		{"ShouldUseConfiguredShorter", time.Minute * 5, time.Minute * 5},
		{"ShouldUseConfiguredLonger", time.Hour * 2, time.Hour * 2},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Config{RequestObjectMaximumLifetime: tc.have}

			assert.Equal(t, tc.expected, c.GetRequestObjectMaximumLifetime(context.Background()))
			assert.Equal(t, tc.have, c.RequestObjectMaximumLifetime)
		})
	}
}
