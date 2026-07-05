// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/text/language"

	"authelia.com/provider/oauth2/i18n"
	"authelia.com/provider/oauth2/x/errorsx"
)

func TestRFC6749ErrorWrap(t *testing.T) {
	testCases := []struct {
		name  string
		check func(t *testing.T)
	}{
		{
			name: "ShouldInheritStackTraceFromWrappedError",
			check: func(t *testing.T) {
				orig := errors.New("hi")
				wrap := new(RFC6749Error)
				wrap.Wrap(orig)

				assert.EqualValues(t, orig.(errorsx.StackTracer).StackTrace(), wrap.StackTrace())
			},
		},
		{
			name: "ShouldNotProduceStackWhenWrappingSelf",
			check: func(t *testing.T) {
				wrap := new(RFC6749Error)
				wrap.Wrap(wrap)

				assert.Empty(t, wrap.StackTrace())
			},
		},
		{
			name: "ShouldReturnEmptyStackForNilCause",
			check: func(t *testing.T) {
				e := new(RFC6749Error)
				assert.Empty(t, e.StackTrace())
			},
		},
		{
			name: "ShouldReturnEmptyStackForNonStackTracerCause",
			check: func(t *testing.T) {
				e := new(RFC6749Error)
				e.Wrap(errPlain("plain"))
				assert.Empty(t, e.StackTrace())
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, tc.check)
	}
}

func TestRFC6749ErrorUnwrap(t *testing.T) {
	testCases := []struct {
		name  string
		cause error
	}{
		{
			name:  "ShouldUnwrapNilWhenCauseUnset",
			cause: nil,
		},
		{
			name:  "ShouldUnwrapWrappedCause",
			cause: errors.New("wrapped"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			e := new(RFC6749Error)
			e.cause = tc.cause

			actual := e.Unwrap()
			if tc.cause == nil {
				assert.Nil(t, actual)
				return
			}
			assert.Same(t, tc.cause, actual)
		})
	}
}

func TestRFC6749ErrorWithWrap(t *testing.T) {
	cause := errors.New("the cause")
	e := ErrInvalidRequest.WithWrap(cause)

	require.NotNil(t, e)
	assert.Equal(t, cause, e.cause)
	assert.NotSame(t, ErrInvalidRequest, e, "WithWrap must return a copy")
}

func TestRFC6749ErrorWithLegacyFormat(t *testing.T) {
	testCases := []struct {
		name     string
		value    bool
		expected bool
	}{
		{name: "ShouldEnableLegacyFormat", value: true, expected: true},
		{name: "ShouldDisableLegacyFormat", value: false, expected: false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := ErrInvalidRequest.WithLegacyFormat(tc.value)
			assert.Equal(t, tc.expected, actual.useLegacyFormat)
			assert.False(t, ErrInvalidRequest.useLegacyFormat, "original must not mutate")
		})
	}
}

func TestRFC6749ErrorWithTrace(t *testing.T) {
	testCases := []struct {
		name      string
		setup     func(e *RFC6749Error)
		err       error
		sameCause bool
	}{
		{
			name:      "ShouldWrapWithStackWhenCauseHasNone",
			setup:     func(e *RFC6749Error) {},
			err:       errPlain("no stack"),
			sameCause: false,
		},
		{
			name: "ShouldNotDoubleWrapWhenCauseAlreadyHasStack",
			setup: func(e *RFC6749Error) {
				e.cause = errors.New("already has stack")
			},
			err:       errors.New("another stacked error"),
			sameCause: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			e := new(RFC6749Error)
			tc.setup(e)

			actual := e.WithTrace(tc.err)
			require.NotNil(t, actual.cause)

			if tc.sameCause {
				// Cause already had a stack trace, so WithTrace must wrap the raw err
				// directly without re-wrapping it in another stack-tracer.
				require.Same(t, tc.err, actual.cause)
			}
		})
	}
}

func TestRFC6749ErrorIs(t *testing.T) {
	testCases := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "ShouldMatchSameRFC6749ErrorPointer",
			err:      ErrInvalidRequest,
			expected: true,
		},
		{
			name:     "ShouldMatchSameRFC6749ErrorValue",
			err:      *ErrInvalidRequest,
			expected: true,
		},
		{
			name:     "ShouldMatchEmptyRFC6749ErrorPointer",
			err:      &RFC6749Error{},
			expected: true,
		},
		{
			name:     "ShouldMatchEmptyRFC6749ErrorValue",
			err:      RFC6749Error{},
			expected: true,
		},
		{
			name:     "ShouldNotMatchDifferentRFC6749Error",
			err:      ErrInvalidClient,
			expected: false,
		},
		{
			name:     "ShouldNotMatchNonRFC6749Error",
			err:      errors.New("other"),
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := ErrInvalidRequest.Is(tc.err)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestRFC6749ErrorIsEmpty(t *testing.T) {
	testCases := []struct {
		name     string
		err      *RFC6749Error
		expected bool
	}{
		{
			name:     "ShouldBeEmptyForZeroValue",
			err:      &RFC6749Error{},
			expected: true,
		},
		{
			name:     "ShouldNotBeEmptyWhenErrorFieldSet",
			err:      &RFC6749Error{ErrorField: "x"},
			expected: false,
		},
		{
			name:     "ShouldNotBeEmptyWhenCodeFieldSet",
			err:      &RFC6749Error{CodeField: 400},
			expected: false,
		},
		{
			name:     "ShouldNotBeEmptyWhenCauseSet",
			err:      &RFC6749Error{cause: errors.New("x")},
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.err.IsEmpty())
		})
	}
}

func TestRFC6749ErrorCarriers(t *testing.T) {
	e := &RFC6749Error{
		ErrorField:       "test_error",
		DescriptionField: "description",
		HintField:        "hint",
		DebugField:       "debug",
		CodeField:        http.StatusTeapot,
	}

	testCases := []struct {
		name  string
		check func(t *testing.T)
	}{
		{
			name: "ShouldReturnErrorField",
			check: func(t *testing.T) {
				assert.Equal(t, "test_error", e.Error())
			},
		},
		{
			name: "ShouldReturnStatusFromCode",
			check: func(t *testing.T) {
				assert.Equal(t, http.StatusText(http.StatusTeapot), e.Status())
			},
		},
		{
			name: "ShouldReturnStatusCode",
			check: func(t *testing.T) {
				assert.Equal(t, http.StatusTeapot, e.StatusCode())
			},
		},
		{
			name: "ShouldReturnEmptyRequestID",
			check: func(t *testing.T) {
				assert.Empty(t, e.RequestID())
			},
		},
		{
			name: "ShouldReturnHintFieldAsReason",
			check: func(t *testing.T) {
				assert.Equal(t, "hint", e.Reason())
			},
		},
		{
			name: "ShouldReturnNilDetails",
			check: func(t *testing.T) {
				assert.Nil(t, e.Details())
			},
		},
		{
			name: "ShouldReturnDebugField",
			check: func(t *testing.T) {
				assert.Equal(t, "debug", e.Debug())
			},
		},
		{
			name: "ShouldReturnCauseField",
			check: func(t *testing.T) {
				cause := errors.New("cause")
				e := &RFC6749Error{cause: cause}
				assert.Same(t, cause, e.Cause())
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, tc.check)
	}
}

func TestRFC6749ErrorWithHint(t *testing.T) {
	testCases := []struct {
		name        string
		base        *RFC6749Error
		hint        string
		expectField string
		expectID    string
	}{
		{
			name:        "ShouldSetHintAndIDWhenBaseHasNoID",
			base:        &RFC6749Error{},
			hint:        "my hint",
			expectField: "my hint",
			expectID:    "my hint",
		},
		{
			name:        "ShouldNotOverwriteExistingHintID",
			base:        &RFC6749Error{hintIDField: "existing-id"},
			hint:        "another hint",
			expectField: "another hint",
			expectID:    "existing-id",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := tc.base.WithHint(tc.hint)
			assert.Equal(t, tc.expectField, actual.HintField)
			assert.Equal(t, tc.expectID, actual.hintIDField)
		})
	}
}

func TestRFC6749ErrorWithHintTranslationID(t *testing.T) {
	actual := ErrInvalidRequest.WithHintTranslationID("badRequestMethod")
	assert.Equal(t, "badRequestMethod", actual.hintIDField)
}

func TestRFC6749ErrorWithDebug(t *testing.T) {
	testCases := []struct {
		name  string
		check func(t *testing.T)
	}{
		{
			name: "ShouldSetDebugFieldOnCopy",
			check: func(t *testing.T) {
				actual := ErrInvalidRequest.WithDebug("debug-x")
				assert.Equal(t, "debug-x", actual.DebugField)
				assert.Empty(t, ErrInvalidRequest.DebugField, "original must not mutate")
			},
		},
		{
			name: "ShouldFormatDebugfMessage",
			check: func(t *testing.T) {
				actual := ErrInvalidRequest.WithDebugf("got %d", 42)
				assert.Equal(t, "got 42", actual.DebugField)
			},
		},
		{
			name: "ShouldReturnSelfWhenDebugErrorIsNil",
			check: func(t *testing.T) {
				actual := ErrInvalidRequest.WithDebugError(nil)
				assert.Same(t, ErrInvalidRequest, actual)
			},
		},
		{
			name: "ShouldUseDebugDescriptionFromErrorWhenRFC6749",
			check: func(t *testing.T) {
				inner := ErrAccessDenied.WithDebug("inner debug")
				actual := ErrInvalidRequest.WithDebugError(inner)
				assert.Contains(t, actual.DebugField, "The resource owner or authorization server denied the request.")
				assert.Contains(t, actual.DebugField, "inner debug")
			},
		},
		{
			name: "ShouldUseErrorStringForNonRFC6749Error",
			check: func(t *testing.T) {
				actual := ErrInvalidRequest.WithDebugError(errors.New("plain"))
				assert.Equal(t, "plain", actual.DebugField)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, tc.check)
	}
}

func TestRFC6749ErrorWithDescription(t *testing.T) {
	actual := ErrInvalidRequest.WithDescription("replaced")
	assert.Equal(t, "replaced", actual.DescriptionField)
	assert.NotEqual(t, "replaced", ErrInvalidRequest.DescriptionField, "original must not mutate")
}

func TestRFC6749ErrorSanitize(t *testing.T) {
	base := ErrInvalidRequest.WithDebug("sensitive")
	actual := base.Sanitize()
	assert.Empty(t, actual.DebugField)
	assert.Equal(t, "sensitive", base.DebugField, "original must not mutate")
}

func TestRFC6749ErrorWithExposeDebug(t *testing.T) {
	testCases := []struct {
		name     string
		expose   bool
		expected bool
	}{
		{name: "ShouldEnableExposeDebug", expose: true, expected: true},
		{name: "ShouldDisableExposeDebug", expose: false, expected: false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := ErrInvalidRequest.WithExposeDebug(tc.expose)
			assert.Equal(t, tc.expected, actual.exposeDebug)
			assert.False(t, ErrInvalidRequest.exposeDebug, "original must not mutate")
		})
	}
}

func TestRFC6749ErrorGetDescription(t *testing.T) {
	testCases := []struct {
		name     string
		err      *RFC6749Error
		expected string
	}{
		{
			name:     "ShouldReturnDescriptionOnly",
			err:      &RFC6749Error{DescriptionField: "desc"},
			expected: "desc",
		},
		{
			name:     "ShouldAppendHint",
			err:      &RFC6749Error{DescriptionField: "desc", HintField: "hint"},
			expected: "desc hint",
		},
		{
			name:     "ShouldNotAppendDebugWhenExposeIsFalse",
			err:      &RFC6749Error{DescriptionField: "desc", DebugField: "secret"},
			expected: "desc",
		},
		{
			name:     "ShouldAppendDebugWhenExposed",
			err:      &RFC6749Error{DescriptionField: "desc", DebugField: "debug", exposeDebug: true},
			expected: "desc debug",
		},
		{
			name:     "ShouldReplaceDoubleQuotesWithSingleQuotes",
			err:      &RFC6749Error{DescriptionField: `value "x"`},
			expected: "value 'x'",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.err.GetDescription())
		})
	}
}

func TestRFC6749ErrorMarshalJSON(t *testing.T) {
	testCases := []struct {
		name     string
		err      *RFC6749Error
		expected string
	}{
		{
			name:     "ShouldMarshalDefaultFormat",
			err:      ErrInvalidRequest,
			expected: `{"error":"invalid_request","error_description":"The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Make sure that the various parameters are correct, be aware of case sensitivity and trim your parameters. Make sure that the client you are using has exactly whitelisted the redirect_uri you specified."}`,
		},
		{
			name:     "ShouldMarshalLegacyFormat",
			err:      ErrInvalidRequest.WithLegacyFormat(true),
			expected: `{"error":"invalid_request","error_description":"The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed.","error_hint":"Make sure that the various parameters are correct, be aware of case sensitivity and trim your parameters. Make sure that the client you are using has exactly whitelisted the redirect_uri you specified.","status_code":400}`,
		},
		{
			name:     "ShouldMarshalLegacyFormatWithDebugWhenExposed",
			err:      ErrInvalidRequest.WithLegacyFormat(true).WithDebug("debug detail").WithExposeDebug(true),
			expected: `{"error":"invalid_request","error_description":"The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed.","error_hint":"Make sure that the various parameters are correct, be aware of case sensitivity and trim your parameters. Make sure that the client you are using has exactly whitelisted the redirect_uri you specified.","status_code":400,"error_debug":"debug detail"}`,
		},
		{
			name:     "ShouldOmitDebugInLegacyWhenNotExposed",
			err:      ErrInvalidRequest.WithLegacyFormat(true).WithDebug("debug detail"),
			expected: `{"error":"invalid_request","error_description":"The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed.","error_hint":"Make sure that the various parameters are correct, be aware of case sensitivity and trim your parameters. Make sure that the client you are using has exactly whitelisted the redirect_uri you specified.","status_code":400}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := json.Marshal(tc.err)
			require.NoError(t, err)
			assert.JSONEq(t, tc.expected, string(actual))
		})
	}
}

func TestRFC6749ErrorUnmarshalJSON(t *testing.T) {
	testCases := []struct {
		name     string
		body     string
		expected *RFC6749Error
		legacy   bool
	}{
		{
			name: "ShouldUnmarshalSimpleErrorBody",
			body: `{"error":"invalid_request","error_description":"desc"}`,
			expected: &RFC6749Error{
				ErrorField:       "invalid_request",
				DescriptionField: "desc",
			},
		},
		{
			name: "ShouldUnmarshalLegacyErrorBody",
			body: `{"error":"invalid_request","error_description":"desc","error_hint":"hint","error_debug":"debug","status_code":400}`,
			expected: &RFC6749Error{
				ErrorField:       "invalid_request",
				DescriptionField: "desc",
				HintField:        "hint",
				DebugField:       "debug",
				CodeField:        400,
			},
			legacy: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := &RFC6749Error{}
			require.NoError(t, json.Unmarshal([]byte(tc.body), actual))

			assert.Equal(t, tc.expected.ErrorField, actual.ErrorField)
			assert.Equal(t, tc.expected.DescriptionField, actual.DescriptionField)
			assert.Equal(t, tc.expected.HintField, actual.HintField)
			assert.Equal(t, tc.expected.DebugField, actual.DebugField)
			assert.Equal(t, tc.expected.CodeField, actual.CodeField)
			assert.Equal(t, tc.legacy, actual.useLegacyFormat)
		})
	}
}

func TestRFC6749ErrorUnmarshalJSONInvalid(t *testing.T) {
	// Passing a JSON array invokes UnmarshalJSON (the bytes are syntactically valid JSON) but
	// the inner Unmarshal into RFC6749ErrorJson fails because an array cannot decode into a
	// struct.
	actual := &RFC6749Error{}
	err := actual.UnmarshalJSON([]byte(`[1, 2, 3]`))
	assert.Error(t, err)
}

func TestRFC6749ErrorToValues(t *testing.T) {
	testCases := []struct {
		name     string
		err      *RFC6749Error
		expected url.Values
	}{
		{
			name: "ShouldEmitDefaultDescription",
			err:  ErrInvalidRequest,
			expected: url.Values{
				"error":             {"invalid_request"},
				"error_description": {"The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Make sure that the various parameters are correct, be aware of case sensitivity and trim your parameters. Make sure that the client you are using has exactly whitelisted the redirect_uri you specified."},
			},
		},
		{
			name: "ShouldEmitLegacyDescriptionAndHint",
			err:  ErrInvalidRequest.WithLegacyFormat(true),
			expected: url.Values{
				"error":             {"invalid_request"},
				"error_description": {"The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed."},
				"error_hint":        {"Make sure that the various parameters are correct, be aware of case sensitivity and trim your parameters. Make sure that the client you are using has exactly whitelisted the redirect_uri you specified."},
			},
		},
		{
			name: "ShouldEmitLegacyDescriptionWithDebugWhenExposed",
			err:  ErrInvalidRequest.WithLegacyFormat(true).WithDebug("debug detail").WithExposeDebug(true),
			expected: url.Values{
				"error":             {"invalid_request"},
				"error_description": {"The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed."},
				"error_hint":        {"Make sure that the various parameters are correct, be aware of case sensitivity and trim your parameters. Make sure that the client you are using has exactly whitelisted the redirect_uri you specified."},
				"error_debug":       {"debug detail"},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.err.ToValues())
		})
	}
}

func TestErrorToRFC6749Error(t *testing.T) {
	testCases := []struct {
		name     string
		err      error
		expected func(t *testing.T, actual *RFC6749Error)
	}{
		{
			name: "ShouldReturnRFC6749ErrorWhenAlreadyOfType",
			err:  ErrInvalidRequest,
			expected: func(t *testing.T, actual *RFC6749Error) {
				assert.Same(t, ErrInvalidRequest, actual)
			},
		},
		{
			name: "ShouldReturnRFC6749ErrorFromWrappedError",
			err:  errors.WithStack(ErrInvalidRequest),
			expected: func(t *testing.T, actual *RFC6749Error) {
				assert.Equal(t, ErrInvalidRequest.ErrorField, actual.ErrorField)
			},
		},
		{
			name: "ShouldReturnGenericRFC6749ErrorForUnknownError",
			err:  errors.New("plain"),
			expected: func(t *testing.T, actual *RFC6749Error) {
				assert.Equal(t, errUnknownErrorName, actual.ErrorField)
				assert.Equal(t, "plain", actual.DebugField)
				assert.Equal(t, http.StatusInternalServerError, actual.CodeField)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := ErrorToRFC6749Error(tc.err)
			require.NotNil(t, actual)
			tc.expected(t, actual)
		})
	}
}

func TestErrorToRFC6749ErrorFallback(t *testing.T) {
	fallback := &RFC6749Error{ErrorField: "fallback_error"}

	testCases := []struct {
		name     string
		err      error
		expected func(t *testing.T, actual *RFC6749Error)
	}{
		{
			name: "ShouldReturnRFC6749ErrorWhenAlreadyOfType",
			err:  ErrInvalidRequest,
			expected: func(t *testing.T, actual *RFC6749Error) {
				assert.Same(t, ErrInvalidRequest, actual)
			},
		},
		{
			name: "ShouldReturnFallbackForUnknownError",
			err:  errors.New("plain"),
			expected: func(t *testing.T, actual *RFC6749Error) {
				assert.Equal(t, "fallback_error", actual.ErrorField)
				assert.Equal(t, "plain", actual.DebugField)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := ErrorToRFC6749ErrorFallback(tc.err, fallback)
			require.NotNil(t, actual)
			tc.expected(t, actual)
		})
	}
}

func TestErrorToDebugRFC6749Error(t *testing.T) {
	testCases := []struct {
		name  string
		err   error
		check func(t *testing.T, actual error)
	}{
		{
			name: "ShouldReturnNilForNilInput",
			err:  nil,
			check: func(t *testing.T, actual error) {
				assert.Nil(t, actual)
			},
		},
		{
			name: "ShouldReturnDebugRFC6749ErrorForRFC6749Error",
			err:  ErrInvalidRequest.WithDebug("debug detail"),
			check: func(t *testing.T, actual error) {
				_, ok := actual.(*DebugRFC6749Error)
				require.True(t, ok, "expected *DebugRFC6749Error, got %T", actual)
				assert.Contains(t, actual.Error(), "debug detail")
			},
		},
		{
			name: "ShouldReturnInputForNonRFC6749Error",
			err:  errors.New("plain"),
			check: func(t *testing.T, actual error) {
				assert.Equal(t, "plain", actual.Error())
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := ErrorToDebugRFC6749Error(tc.err)
			tc.check(t, actual)
		})
	}
}

func TestErrorI18N(t *testing.T) {
	catalog := i18n.NewDefaultMessageCatalog([]*i18n.DefaultLocaleBundle{
		{
			LangTag: "en",
			Messages: []*i18n.DefaultMessage{
				{
					ID:               "access_denied",
					FormattedMessage: "The resource owner or authorization server denied the request.",
				},
				{
					ID:               "badRequestMethod",
					FormattedMessage: "HTTP method is '%s', expected 'POST'.",
				},
			},
		},
		{
			LangTag: "es",
			Messages: []*i18n.DefaultMessage{
				{
					ID:               "access_denied",
					FormattedMessage: "El propietario del recurso o el servidor de autorización denegó la solicitud.",
				},
				{
					ID:               "HTTP method is '%s', expected 'POST'.",
					FormattedMessage: "El método HTTP es '%s', esperado 'POST'.",
				},
				{
					ID:               "Unable to parse HTTP body, make sure to send a properly formatted form request body.",
					FormattedMessage: "No se puede analizar el cuerpo HTTP, asegúrese de enviar un cuerpo de solicitud de formulario con el formato adecuado.",
				},
				{
					ID:               "badRequestMethod",
					FormattedMessage: "El método HTTP es '%s', esperado 'POST'.",
				},
			},
		},
	})

	testCases := []struct {
		name     string
		setup    func() *RFC6749Error
		expected string
	}{
		{
			name: "ShouldLocalizeWithHintf",
			setup: func() *RFC6749Error {
				return ErrAccessDenied.WithLocalizer(catalog, language.Spanish).WithHintf("HTTP method is '%s', expected 'POST'.", "GET")
			},
			expected: "El propietario del recurso o el servidor de autorización denegó la solicitud. El método HTTP es 'GET', esperado 'POST'.",
		},
		{
			name: "ShouldFallBackForUnsupportedLocaleWithHintf",
			setup: func() *RFC6749Error {
				return ErrAccessDenied.WithLocalizer(catalog, language.Afrikaans).WithHintf("HTTP method is '%s', expected 'POST'.", "GET")
			},
			expected: "The resource owner or authorization server denied the request. HTTP method is 'GET', expected 'POST'.",
		},
		{
			name: "ShouldLocalizeWithHintIDOrDefaultf",
			setup: func() *RFC6749Error {
				return ErrAccessDenied.WithLocalizer(catalog, language.Spanish).WithHintIDOrDefaultf("badRequestMethod", "HTTP method is '%s', expected 'POST'.", "GET")
			},
			expected: "El propietario del recurso o el servidor de autorización denegó la solicitud. El método HTTP es 'GET', esperado 'POST'.",
		},
		{
			name: "ShouldFallBackForUnsupportedLocaleWithHintIDOrDefaultf",
			setup: func() *RFC6749Error {
				return ErrAccessDenied.WithLocalizer(catalog, language.Afrikaans).WithHintIDOrDefaultf("badRequestMethod", "HTTP method is '%s', expected 'POST'.", "GET")
			},
			expected: "The resource owner or authorization server denied the request. HTTP method is 'GET', expected 'POST'.",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.setup()
			assert.Equal(t, tc.expected, err.GetDescription())
		})
	}
}

func TestDPoPErrors(t *testing.T) {
	assert.Equal(t, "invalid_dpop_proof", ErrInvalidDPoPProof.ErrorField)
	assert.Equal(t, http.StatusBadRequest, ErrInvalidDPoPProof.CodeField)

	assert.Equal(t, "use_dpop_nonce", ErrUseDPoPNonce.ErrorField)
	assert.Equal(t, http.StatusBadRequest, ErrUseDPoPNonce.CodeField)
}

// errPlain is a simple error type used to exercise paths that depend on the absence of
// stack traces or other carrier interfaces.
type errPlain string

func (e errPlain) Error() string { return string(e) }
