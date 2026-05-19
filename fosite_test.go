// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/handler/par"
	"authelia.com/provider/oauth2/handler/rfc8628"
)

func TestNewFosite(t *testing.T) {
	testCases := []struct {
		name   string
		store  Storage
		config Configurator
	}{
		{
			name:   "ShouldConstructWithNilStoreAndConfig",
			store:  nil,
			config: nil,
		},
		{
			name:   "ShouldConstructWithDefaultConfig",
			store:  nil,
			config: new(Config),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := New(tc.store, tc.config)
			require.NotNil(t, actual)
			assert.Equal(t, tc.store, actual.Store)
			assert.Equal(t, tc.config, actual.Config)
		})
	}
}

func TestResponseModeHandlersAppend(t *testing.T) {
	testCases := []struct {
		name    string
		appends []ResponseModeHandler
		length  int
	}{
		{
			name:    "ShouldAppendSingleHandler",
			appends: []ResponseModeHandler{&DefaultResponseModeHandler{}},
			length:  1,
		},
		{
			name:    "ShouldNotAppendDuplicateHandler",
			appends: []ResponseModeHandler{&DefaultResponseModeHandler{}, &DefaultResponseModeHandler{}},
			length:  1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := ResponseModeHandlers{}
			for _, h := range tc.appends {
				actual.Append(h)
			}
			assert.Len(t, actual, tc.length)
			assert.Equal(t, tc.appends[0], actual[0])
		})
	}
}

func TestResponseModeParameterHandlersAppend(t *testing.T) {
	testCases := []struct {
		name    string
		appends []ResponseModeParameterHandler
		length  int
	}{
		{
			name:    "ShouldAppendSingleHandler",
			appends: []ResponseModeParameterHandler{&RFC9207ResponseModeParameterHandler{}},
			length:  1,
		},
		{
			name:    "ShouldNotAppendDuplicateHandler",
			appends: []ResponseModeParameterHandler{&RFC9207ResponseModeParameterHandler{}, &RFC9207ResponseModeParameterHandler{}},
			length:  1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := ResponseModeParameterHandlers{}
			for _, h := range tc.appends {
				actual.Append(h)
			}
			assert.Len(t, actual, tc.length)
			assert.Equal(t, tc.appends[0], actual[0])
		})
	}
}

func TestAuthorizeEndpointHandlersAppend(t *testing.T) {
	first := &oauth2.AuthorizeExplicitGrantHandler{}

	testCases := []struct {
		name    string
		appends []AuthorizeEndpointHandler
		length  int
	}{
		{
			name:    "ShouldAppendSingleHandler",
			appends: []AuthorizeEndpointHandler{first},
			length:  1,
		},
		{
			name:    "ShouldNotAppendDuplicateHandler",
			appends: []AuthorizeEndpointHandler{first, first},
			length:  1,
		},
		{
			name:    "ShouldNotAppendDifferentInstanceOfSameType",
			appends: []AuthorizeEndpointHandler{first, &oauth2.AuthorizeExplicitGrantHandler{}},
			length:  1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := AuthorizeEndpointHandlers{}
			for _, h := range tc.appends {
				actual.Append(h)
			}
			assert.Len(t, actual, tc.length)
			assert.Equal(t, first, actual[0])
		})
	}
}

func TestTokenEndpointHandlersAppend(t *testing.T) {
	first := &oauth2.AuthorizeExplicitGrantHandler{}

	testCases := []struct {
		name    string
		appends []TokenEndpointHandler
		length  int
	}{
		{
			name:    "ShouldAppendSingleHandler",
			appends: []TokenEndpointHandler{first},
			length:  1,
		},
		{
			name:    "ShouldNotAppendDuplicateHandler",
			appends: []TokenEndpointHandler{first, first},
			length:  1,
		},
		{
			name: "ShouldNotAppendDifferentInstanceOfSameTypeAfterAnyAssertion",
			appends: func() []TokenEndpointHandler {
				var f any = &oauth2.AuthorizeExplicitGrantHandler{}
				return []TokenEndpointHandler{first, &oauth2.AuthorizeExplicitGrantHandler{}, f.(TokenEndpointHandler)}
			}(),
			length: 1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := TokenEndpointHandlers{}
			for _, h := range tc.appends {
				actual.Append(h)
			}
			require.Len(t, actual, tc.length)
			assert.Equal(t, first, actual[0])
		})
	}
}

func TestTokenIntrospectionHandlersAppend(t *testing.T) {
	first := &oauth2.CoreValidator{}

	testCases := []struct {
		name    string
		appends []TokenIntrospector
		length  int
	}{
		{
			name:    "ShouldAppendSingleHandler",
			appends: []TokenIntrospector{first},
			length:  1,
		},
		{
			name:    "ShouldNotAppendDuplicateHandler",
			appends: []TokenIntrospector{first, first},
			length:  1,
		},
		{
			name:    "ShouldNotAppendDifferentInstanceOfSameType",
			appends: []TokenIntrospector{first, &oauth2.CoreValidator{}},
			length:  1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := TokenIntrospectionHandlers{}
			for _, h := range tc.appends {
				actual.Append(h)
			}
			require.Len(t, actual, tc.length)
			assert.Equal(t, first, actual[0])
		})
	}
}

func TestRevocationHandlersAppend(t *testing.T) {
	first := &oauth2.TokenRevocationHandler{}

	testCases := []struct {
		name    string
		appends []RevocationHandler
		length  int
	}{
		{
			name:    "ShouldAppendSingleHandler",
			appends: []RevocationHandler{first},
			length:  1,
		},
		{
			name:    "ShouldNotAppendDuplicateHandler",
			appends: []RevocationHandler{first, first},
			length:  1,
		},
		{
			name:    "ShouldNotAppendDifferentInstanceOfSameType",
			appends: []RevocationHandler{first, &oauth2.TokenRevocationHandler{}},
			length:  1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := RevocationHandlers{}
			for _, h := range tc.appends {
				actual.Append(h)
			}
			require.Len(t, actual, tc.length)
			assert.Equal(t, first, actual[0])
		})
	}
}

func TestPushedAuthorizeEndpointHandlersAppend(t *testing.T) {
	first := &par.PushedAuthorizeHandler{}

	testCases := []struct {
		name    string
		appends []PushedAuthorizeEndpointHandler
		length  int
	}{
		{
			name:    "ShouldAppendSingleHandler",
			appends: []PushedAuthorizeEndpointHandler{first},
			length:  1,
		},
		{
			name:    "ShouldNotAppendDuplicateHandler",
			appends: []PushedAuthorizeEndpointHandler{first, first},
			length:  1,
		},
		{
			name:    "ShouldNotAppendDifferentInstanceOfSameType",
			appends: []PushedAuthorizeEndpointHandler{first, &par.PushedAuthorizeHandler{}},
			length:  1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := PushedAuthorizeEndpointHandlers{}
			for _, h := range tc.appends {
				actual.Append(h)
			}
			require.Len(t, actual, tc.length)
			assert.Equal(t, first, actual[0])
		})
	}
}

func TestRFC8628DeviceAuthorizeEndpointHandlersAppend(t *testing.T) {
	first := &rfc8628.DeviceAuthorizeHandler{}

	testCases := []struct {
		name    string
		appends []RFC8628DeviceAuthorizeEndpointHandler
		length  int
	}{
		{
			name:    "ShouldAppendSingleHandler",
			appends: []RFC8628DeviceAuthorizeEndpointHandler{first},
			length:  1,
		},
		{
			name:    "ShouldNotAppendDuplicateHandler",
			appends: []RFC8628DeviceAuthorizeEndpointHandler{first, first},
			length:  1,
		},
		{
			name:    "ShouldNotAppendDifferentInstanceOfSameType",
			appends: []RFC8628DeviceAuthorizeEndpointHandler{first, &rfc8628.DeviceAuthorizeHandler{}},
			length:  1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := RFC8628DeviceAuthorizeEndpointHandlers{}
			for _, h := range tc.appends {
				actual.Append(h)
			}
			require.Len(t, actual, tc.length)
			assert.Equal(t, first, actual[0])
		})
	}
}

func TestRFC8628UserAuthorizeEndpointHandlersAppend(t *testing.T) {
	first := &rfc8628.UserAuthorizeHandler{}

	testCases := []struct {
		name    string
		appends []RFC8628UserAuthorizeEndpointHandler
		length  int
	}{
		{
			name:    "ShouldAppendSingleHandler",
			appends: []RFC8628UserAuthorizeEndpointHandler{first},
			length:  1,
		},
		{
			name:    "ShouldNotAppendDuplicateHandler",
			appends: []RFC8628UserAuthorizeEndpointHandler{first, first},
			length:  1,
		},
		{
			name:    "ShouldNotAppendDifferentInstanceOfSameType",
			appends: []RFC8628UserAuthorizeEndpointHandler{first, &rfc8628.UserAuthorizeHandler{}},
			length:  1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := RFC8628UserAuthorizeEndpointHandlers{}
			for _, h := range tc.appends {
				actual.Append(h)
			}
			require.Len(t, actual, tc.length)
			assert.Equal(t, first, actual[0])
		})
	}
}

func TestFositeGetMinParameterEntropy(t *testing.T) {
	testCases := []struct {
		name     string
		config   *Config
		expected int
	}{
		{
			name:     "ShouldReturnDefaultWhenUnset",
			config:   new(Config),
			expected: MinParameterEntropy,
		},
		{
			name:     "ShouldReturnConfiguredValue",
			config:   &Config{MinParameterEntropy: 42},
			expected: 42,
		},
		{
			name:     "ShouldReturnDisabledWhenNegativeOne",
			config:   &Config{MinParameterEntropy: -1},
			expected: -1,
		},
		{
			name:     "ShouldReturnDefaultForNegativeOtherThanMinusOne",
			config:   &Config{MinParameterEntropy: -5},
			expected: MinParameterEntropy,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider := Fosite{Config: tc.config}
			actual := provider.GetMinParameterEntropy(context.Background())
			assert.Equal(t, tc.expected, actual)
		})
	}
}
