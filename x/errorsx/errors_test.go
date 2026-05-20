// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package errorsx_test

import (
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/x/errorsx"
)

func TestCause(t *testing.T) {
	rootCause := errPlain("the root cause")

	testCases := []struct {
		name          string
		have          error
		expected      error
		expectedDebug string
	}{
		{
			name:     "ShouldReturnNilForNilError",
			have:     nil,
			expected: nil,
		},
		{
			name:          "ShouldReturnErrorUnchangedWhenItIsNotACauser",
			have:          rootCause,
			expected:      rootCause,
			expectedDebug: "the root cause",
		},
		{
			name:          "ShouldUnwrapPkgErrorsStackToRootCause",
			have:          errors.WithStack(rootCause),
			expected:      rootCause,
			expectedDebug: "the root cause",
		},
		{
			name:          "ShouldStopAtRFC6749ErrorWhenItHasNoCause",
			have:          oauth2.ErrInvalidRequest,
			expected:      oauth2.ErrInvalidRequest,
			expectedDebug: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Make sure that the various parameters are correct, be aware of case sensitivity and trim your parameters. Make sure that the client you are using has exactly whitelisted the redirect_uri you specified.",
		},
		{
			name:          "ShouldUnwrapRFC6749ErrorToItsPlainCause",
			have:          oauth2.ErrInvalidRequest.WithWrap(rootCause),
			expected:      rootCause,
			expectedDebug: "the root cause",
		},
		{
			name:          "ShouldUnwrapRFC6749ErrorToItsWrappedRFC6749Cause",
			have:          oauth2.ErrInvalidRequest.WithWrap(oauth2.ErrAccessDenied),
			expected:      oauth2.ErrAccessDenied,
			expectedDebug: "The resource owner or authorization server denied the request. Make sure that the request you are making is valid. Maybe the credential or request parameters you are using are limited in scope or otherwise restricted.",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := errorsx.Cause(tc.have)

			if tc.expected == nil {
				assert.Nil(t, actual)
				return
			}

			assert.Equal(t, tc.expected, actual)

			// ErrorToDebugRFC6749Error renders the full description of the resolved cause,
			// which is the short error code for an *RFC6749Error and the plain message
			// otherwise.
			assert.Equal(t, tc.expectedDebug, oauth2.ErrorToDebugRFC6749Error(actual).Error())
		})
	}
}

func TestWithStack(t *testing.T) {
	testCases := []struct {
		name          string
		have          error
		expectSame    bool
		expectedDebug string
	}{
		{
			name:          "ShouldNotRewrapErrorThatAlreadyHasAStackTrace",
			have:          errors.New("already stacked"),
			expectSame:    true,
			expectedDebug: "already stacked",
		},
		{
			name:          "ShouldNotRewrapRFC6749ErrorWhoseCauseHasAStackTrace",
			have:          oauth2.ErrInvalidRequest.WithWrap(errors.New("stacked cause")),
			expectSame:    true,
			expectedDebug: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Make sure that the various parameters are correct, be aware of case sensitivity and trim your parameters. Make sure that the client you are using has exactly whitelisted the redirect_uri you specified.",
		},
		{
			name:          "ShouldAddStackTraceToPlainError",
			have:          errPlain("no stack"),
			expectSame:    false,
			expectedDebug: "no stack",
		},
		{
			name:          "ShouldAddStackTraceToRFC6749ErrorWithoutACause",
			have:          oauth2.ErrInvalidRequest,
			expectSame:    false,
			expectedDebug: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Make sure that the various parameters are correct, be aware of case sensitivity and trim your parameters. Make sure that the client you are using has exactly whitelisted the redirect_uri you specified.",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := errorsx.WithStack(tc.have)

			tracer, ok := actual.(errorsx.StackTracer)
			require.True(t, ok, "result must expose a stack trace")
			assert.NotEmpty(t, tracer.StackTrace())

			if tc.expectSame {
				assert.Same(t, tc.have, actual)
			} else {
				causer, ok := actual.(errorsx.Causer)
				require.True(t, ok, "a freshly stacked error must wrap its cause")
				assert.Equal(t, tc.have, causer.Cause())
			}

			// WithStack must be idempotent once a stack trace is present.
			assert.Same(t, actual, errorsx.WithStack(actual))

			assert.Equal(t, tc.expectedDebug, oauth2.ErrorToDebugRFC6749Error(actual).Error())
		})
	}
}

// errPlain is a minimal error type with no stack trace and no Cause method, used to
// exercise the branches that handle errors which do not implement the carrier interfaces.
type errPlain string

func (e errPlain) Error() string { return string(e) }
