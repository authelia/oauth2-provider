// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	. "authelia.com/provider/oauth2"
)

func TestIsValidDPoPJWKThumbprint(t *testing.T) {
	sum := sha256.Sum256([]byte("some key material"))
	valid := base64.RawURLEncoding.EncodeToString(sum[:])

	testCases := []struct {
		name     string
		have     string
		expected bool
	}{
		{"ShouldAcceptASHA256Thumbprint", valid, true},
		{"ShouldAcceptAKnownGoodValue", "kM1FTfCFVzO9tGKBVBEAWCVoWZ2WcOK1EbSPxNjQfSw", true},
		{"ShouldRejectEmpty", "", false},
		{"ShouldRejectShort", "kM1FTfCFVzO9tGKBVBEAWCVoWZ2WcOK1EbSPxNjQfS", false},
		{"ShouldRejectLong", "kM1FTfCFVzO9tGKBVBEAWCVoWZ2WcOK1EbSPxNjQfSww", false},
		{"ShouldRejectOverlong", strings.Repeat("A", 4096), false},
		{"ShouldRejectStandardBase64Plus", "kM1FTfCFVzO9tGKBVBEAWCVoWZ2WcOK1EbSPxNjQfS+", false},
		{"ShouldRejectStandardBase64Slash", "kM1FTfCFVzO9tGKBVBEAWCVoWZ2WcOK1EbSPxNjQfS/", false},
		{"ShouldRejectPadding", "kM1FTfCFVzO9tGKBVBEAWCVoWZ2WcOK1EbSPxNjQfS=", false},
		{"ShouldRejectNonAlphabet", "kM1FTfCFVzO9tGKBVBEAWCVoWZ2WcOK1EbSPxNjQfS!", false},
		{"ShouldRejectSHA512Thumbprint", base64.RawURLEncoding.EncodeToString(make([]byte, 64)), false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, IsValidDPoPJWKThumbprint(tc.have))
		})
	}
}

func TestThumbprintJWKProducesAValidDPoPJKT(t *testing.T) {
	sum := sha256.Sum256([]byte("a key"))

	assert.Len(t, base64.RawURLEncoding.EncodeToString(sum[:]), DPoPJWKThumbprintLength)
	assert.True(t, IsValidDPoPJWKThumbprint(base64.RawURLEncoding.EncodeToString(sum[:])))
}
