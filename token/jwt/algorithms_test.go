// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"authelia.com/provider/jose"
)

func TestToAsymmetricSignatureAlgorithms(t *testing.T) {
	testCases := []struct {
		name     string
		algs     []string
		expected []jose.SignatureAlgorithm
	}{
		{"ShouldKeepAsymmetricAlgorithms", []string{"RS256", "ES256", "PS256", "EdDSA"}, []jose.SignatureAlgorithm{jose.RS256, jose.ES256, jose.PS256, jose.EdDSA}},
		{"ShouldDropNone", []string{JSONWebTokenAlgNone, "RS256"}, []jose.SignatureAlgorithm{jose.RS256}},
		{"ShouldDropTheHMACAlgorithms", []string{"HS256", "HS384", "HS512", "ES256"}, []jose.SignatureAlgorithm{jose.ES256}},
		{"ShouldReturnEmptyWhenNothingRemains", []string{JSONWebTokenAlgNone, "HS256"}, []jose.SignatureAlgorithm{}},
		{"ShouldReturnEmptyForNil", nil, []jose.SignatureAlgorithm{}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, ToAsymmetricSignatureAlgorithms(tc.algs))
		})
	}
}
