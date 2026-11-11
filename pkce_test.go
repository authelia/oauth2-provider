// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	. "authelia.com/provider/oauth2"
)

func TestIsPKCECodeVerifierMatch(t *testing.T) {
	const (
		verifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	)

	testCases := []struct {
		name      string
		method    string
		challenge string
		verifier  string
		expected  bool
	}{
		// RFC 7636 Appendix B.
		{name: "ShouldMatchS256", method: "S256", challenge: challenge, verifier: verifier, expected: true},
		{name: "ShouldNotMatchS256WithAnotherVerifier", method: "S256", challenge: challenge, verifier: verifier + "x"},
		{name: "ShouldNotMatchS256AsPlain", method: "S256", challenge: verifier, verifier: verifier},
		{name: "ShouldMatchPlain", method: "plain", challenge: verifier, verifier: verifier, expected: true},
		{name: "ShouldNotMatchPlainWithAnotherVerifier", method: "plain", challenge: verifier, verifier: challenge},
		{name: "ShouldNotMatchAnEmptyVerifier", method: "plain", challenge: verifier},
		{name: "ShouldNotMatchAnEmptyChallenge", method: "plain", verifier: verifier},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, IsPKCECodeVerifierMatch(tc.method, tc.challenge, tc.verifier))
		})
	}
}
