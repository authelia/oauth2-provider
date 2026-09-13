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

func TestConfigGetJWTClockSkew(t *testing.T) {
	testCases := []struct {
		name     string
		have     time.Duration
		expected time.Duration
	}{
		{"ShouldDefaultWhenZero", 0, time.Second * 10},
		{"ShouldDisableWhenNegative", -time.Second, 0},
		{"ShouldUseConfigured", time.Second * 30, time.Second * 30},
		{"ShouldAllowTheCap", time.Minute, time.Minute},
		{"ShouldCapAboveSixtySeconds", time.Minute * 5, time.Minute},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Config{JWTClockSkew: tc.have}

			assert.Equal(t, tc.expected, c.GetJWTClockSkew(context.Background()))
			assert.Equal(t, tc.have, c.JWTClockSkew)
		})
	}
}
