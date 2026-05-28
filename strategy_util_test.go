// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"

	"authelia.com/provider/oauth2/internal/consts"
)

func TestJoinGrantedAudienceAndResource(t *testing.T) {
	testCases := []struct {
		name     string
		audience Arguments
		resource Arguments
		expected Arguments
	}{
		{
			name:     "ShouldReturnNilWhenBothEmpty",
			audience: Arguments{},
			resource: Arguments{},
			expected: nil,
		},
		{
			name:     "ShouldReturnAudienceWhenResourceEmpty",
			audience: Arguments{"my-service"},
			resource: Arguments{},
			expected: Arguments{"my-service"},
		},
		{
			name:     "ShouldReturnResourceWhenAudienceEmpty",
			audience: Arguments{},
			resource: Arguments{"https://api.example.com"},
			expected: Arguments{"https://api.example.com"},
		},
		{
			name:     "ShouldConcatenateBoth",
			audience: Arguments{"my-service"},
			resource: Arguments{"https://api.example.com"},
			expected: Arguments{"my-service", "https://api.example.com"},
		},
		{
			name:     "ShouldDeduplicateOverlappingValues",
			audience: Arguments{"foo", "shared"},
			resource: Arguments{"shared", "bar"},
			expected: Arguments{"foo", "shared", "bar"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, JoinGrantedAudienceAndResource(tc.audience, tc.resource))
		})
	}
}

func TestGetResourcesParameter(t *testing.T) {
	testCases := []struct {
		name      string
		parameter string
		form      url.Values
		expected  []string
		ok        bool
	}{
		{
			name:      "ShouldReturnFalseWhenParameterMissing",
			parameter: consts.FormParameterResource,
			form:      url.Values{},
			expected:  []string{},
			ok:        false,
		},
		{
			name:      "ShouldReturnFalseForSingleEmptyValue",
			parameter: consts.FormParameterResource,
			form:      url.Values{consts.FormParameterResource: {""}},
			ok:        false,
		},
		{
			name:      "ShouldReturnFalseForAllEmptyRepeatedValues",
			parameter: consts.FormParameterResource,
			form:      url.Values{consts.FormParameterResource: {"", ""}},
			ok:        false,
		},
		{
			name:      "ShouldSplitSingleSpaceDelimitedValue",
			parameter: consts.FormParameterResource,
			form:      url.Values{consts.FormParameterResource: {"https://api.example.com https://api.other.com"}},
			expected:  []string{"https://api.example.com", "https://api.other.com"},
			ok:        true,
		},
		{
			name:      "ShouldReturnRepeatedValues",
			parameter: consts.FormParameterResource,
			form:      url.Values{consts.FormParameterResource: {"https://api.example.com", "https://api.other.com"}},
			expected:  []string{"https://api.example.com", "https://api.other.com"},
			ok:        true,
		},
		{
			name:      "ShouldFilterEmptyFromRepeatedValues",
			parameter: consts.FormParameterResource,
			form:      url.Values{consts.FormParameterResource: {"https://api.example.com", "", "https://api.other.com"}},
			expected:  []string{"https://api.example.com", "https://api.other.com"},
			ok:        true,
		},
		{
			name:      "ShouldReadAudienceParameter",
			parameter: consts.FormParameterAudience,
			form:      url.Values{consts.FormParameterAudience: {"https://api.example.com"}},
			expected:  []string{"https://api.example.com"},
			ok:        true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, ok := GetResourcesParameter(tc.parameter, tc.form)
			assert.Equal(t, tc.ok, ok)

			if tc.expected == nil {
				assert.Empty(t, actual)
			} else {
				assert.Equal(t, tc.expected, actual)
			}
		})
	}
}
