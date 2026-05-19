// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
)

func TestAccessResponseConstructor(t *testing.T) {
	testCases := []struct {
		name  string
		check func(t *testing.T, actual *AccessResponse)
	}{
		{
			name: "ShouldInitializeEmptyExtra",
			check: func(t *testing.T, actual *AccessResponse) {
				assert.NotNil(t, actual.Extra)
				assert.Empty(t, actual.Extra)
			},
		},
		{
			name: "ShouldInitializeEmptyTokenAndType",
			check: func(t *testing.T, actual *AccessResponse) {
				assert.Empty(t, actual.AccessToken)
				assert.Empty(t, actual.TokenType)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := NewAccessResponse()
			tc.check(t, actual)
		})
	}
}

func TestAccessResponseGettersAndSetters(t *testing.T) {
	testCases := []struct {
		name  string
		check func(t *testing.T)
	}{
		{
			name: "ShouldSetAndGetAccessToken",
			check: func(t *testing.T) {
				ar := NewAccessResponse()
				ar.SetAccessToken("access")
				assert.Equal(t, "access", ar.GetAccessToken())
			},
		},
		{
			name: "ShouldSetAndGetTokenType",
			check: func(t *testing.T) {
				ar := NewAccessResponse()
				ar.SetTokenType(BearerAccessToken)
				assert.Equal(t, BearerAccessToken, ar.GetTokenType())
			},
		},
		{
			name: "ShouldSetAndGetExtra",
			check: func(t *testing.T) {
				ar := NewAccessResponse()
				ar.SetExtra("foo", "bar")
				assert.Equal(t, "bar", ar.GetExtra("foo"))
			},
		},
		{
			name: "ShouldReturnNilForMissingExtra",
			check: func(t *testing.T) {
				ar := NewAccessResponse()
				assert.Nil(t, ar.GetExtra("missing"))
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, tc.check)
	}
}

func TestAccessResponseSetScopes(t *testing.T) {
	testCases := []struct {
		name     string
		scopes   Arguments
		expected string
	}{
		{
			name:     "ShouldStoreSingleScope",
			scopes:   Arguments{"openid"},
			expected: "openid",
		},
		{
			name:     "ShouldJoinMultipleScopesWithSpace",
			scopes:   Arguments{"openid", "profile", "email"},
			expected: "openid profile email",
		},
		{
			name:     "ShouldStoreEmptyStringForEmptyScopes",
			scopes:   Arguments{},
			expected: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ar := NewAccessResponse()
			ar.SetScopes(tc.scopes)
			assert.Equal(t, tc.expected, ar.GetExtra(consts.AccessResponseScope))
		})
	}
}

func TestAccessResponseSetExpiresIn(t *testing.T) {
	testCases := []struct {
		name     string
		duration time.Duration
		expected int64
	}{
		{
			name:     "ShouldStoreSecondsForOneHour",
			duration: time.Hour,
			expected: 3600,
		},
		{
			name:     "ShouldStoreSecondsForSixtySeconds",
			duration: 60 * time.Second,
			expected: 60,
		},
		{
			name:     "ShouldStoreZeroForZeroDuration",
			duration: 0,
			expected: 0,
		},
		{
			name:     "ShouldTruncateSubSecondDuration",
			duration: 500 * time.Millisecond,
			expected: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ar := NewAccessResponse()
			ar.SetExpiresIn(tc.duration)
			assert.Equal(t, tc.expected, ar.GetExtra(consts.AccessResponseExpiresIn))
		})
	}
}

func TestAccessResponseToMap(t *testing.T) {
	testCases := []struct {
		name     string
		setup    func() *AccessResponse
		expected map[string]any
	}{
		{
			name: "ShouldIncludeAccessTokenAndTokenType",
			setup: func() *AccessResponse {
				ar := NewAccessResponse()
				ar.SetAccessToken("access")
				ar.SetTokenType(BearerAccessToken)
				return ar
			},
			expected: map[string]any{
				consts.AccessResponseAccessToken: "access",
				consts.AccessResponseTokenType:   BearerAccessToken,
			},
		},
		{
			name: "ShouldOverrideExtraAccessTokenWithSetter",
			setup: func() *AccessResponse {
				ar := NewAccessResponse()
				ar.SetAccessToken("access")
				ar.SetTokenType(BearerAccessToken)
				ar.SetExtra(consts.AccessResponseAccessToken, "invalid")
				ar.SetExtra("foo", "bar")
				return ar
			},
			expected: map[string]any{
				consts.AccessResponseAccessToken: "access",
				consts.AccessResponseTokenType:   BearerAccessToken,
				"foo":                            "bar",
			},
		},
		{
			name: "ShouldEmitEmptyTokenFieldsWhenUnset",
			setup: func() *AccessResponse {
				return NewAccessResponse()
			},
			expected: map[string]any{
				consts.AccessResponseAccessToken: "",
				consts.AccessResponseTokenType:   "",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := tc.setup().ToMap()
			assert.Equal(t, tc.expected, actual)
		})
	}
}
