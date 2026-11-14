// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNarrowsAuthorizationDetails(t *testing.T) {
	id, other := "account-1", "account-2"

	requested := AuthorizationDetails{
		{Type: "payment", Actions: []string{"read", "write"}, Locations: []string{"https://a.example.com"}, Extra: map[string]any{"amount": "100"}},
		{Type: "account", Identifier: &id, Actions: []string{"read"}},
	}

	testCases := []struct {
		name     string
		granted  AuthorizationDetails
		expected bool
	}{
		{name: "ShouldAllowNone", expected: true},
		{name: "ShouldAllowEqual", granted: requested, expected: true},
		{name: "ShouldAllowASubsetOfDetails", granted: AuthorizationDetails{requested[1]}, expected: true},
		{name: "ShouldAllowFewerValues", granted: AuthorizationDetails{{Type: "payment", Actions: []string{"read"}, Locations: []string{"https://a.example.com"}, Extra: map[string]any{"amount": "100"}}}, expected: true},
		{name: "ShouldAllowNoValuesOfAField", granted: AuthorizationDetails{{Type: "payment", Actions: []string{}, Locations: []string{"https://a.example.com"}, Extra: map[string]any{"amount": "100"}}}, expected: true},
		{name: "ShouldDenyAnotherValue", granted: AuthorizationDetails{{Type: "payment", Actions: []string{"delete"}, Locations: []string{"https://a.example.com"}, Extra: map[string]any{"amount": "100"}}}, expected: false},
		{name: "ShouldDenyAnOmittedField", granted: AuthorizationDetails{{Type: "payment", Locations: []string{"https://a.example.com"}, Extra: map[string]any{"amount": "100"}}}, expected: false},
		{name: "ShouldDenyAnOmittedMember", granted: AuthorizationDetails{{Type: "payment", Actions: []string{"read"}, Locations: []string{"https://a.example.com"}}}, expected: false},
		{name: "ShouldDenyAChangedMember", granted: AuthorizationDetails{{Type: "payment", Actions: []string{"read"}, Locations: []string{"https://a.example.com"}, Extra: map[string]any{"amount": "1000"}}}, expected: false},
		{name: "ShouldDenyAnAddedMember", granted: AuthorizationDetails{{Type: "payment", Actions: []string{"read"}, Locations: []string{"https://a.example.com"}, Extra: map[string]any{"amount": "100", "currency": "EUR"}}}, expected: false},
		{name: "ShouldDenyAnOmittedIdentifier", granted: AuthorizationDetails{{Type: "account", Actions: []string{"read"}}}, expected: false},
		{name: "ShouldDenyAnotherIdentifier", granted: AuthorizationDetails{{Type: "account", Identifier: &other, Actions: []string{"read"}}}, expected: false},
		{name: "ShouldDenyAnotherType", granted: AuthorizationDetails{{Type: "transfer", Actions: []string{"read"}}}, expected: false},
		{name: "ShouldDenyADuplicate", granted: AuthorizationDetails{requested[1], requested[1]}, expected: false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, narrowsAuthorizationDetails(tc.granted, requested))
		})
	}
}
