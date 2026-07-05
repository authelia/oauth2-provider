// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"net/http"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/text/language"

	"authelia.com/provider/oauth2/i18n"
)

func newTestCatalog() i18n.MessageCatalog {
	return i18n.NewDefaultMessageCatalog([]*i18n.DefaultLocaleBundle{
		{
			LangTag: "en",
			Messages: []*i18n.DefaultMessage{
				{
					ID:               "badRequestMethod",
					FormattedMessage: "HTTP method is '%s', expected 'POST'.",
				},
				{
					ID:               "invalid_request",
					FormattedMessage: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed.",
				},
			},
		},
		{
			LangTag: "es",
			Messages: []*i18n.DefaultMessage{
				{
					ID:               "badRequestMethod",
					FormattedMessage: "El método HTTP es '%s', esperado 'POST'.",
				},
				{
					ID:               "invalid_request",
					FormattedMessage: "A la solicitud le falta un parámetro obligatorio, incluye un valor de parámetro no válido, incluye un parámetro más de una vez o tiene un formato incorrecto.",
				},
			},
		},
	})
}

const (
	expectedEnglish = "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. HTTP method is 'GET', expected 'POST'."
	expectedSpanish = "A la solicitud le falta un parámetro obligatorio, incluye un valor de parámetro no válido, incluye un parámetro más de una vez o tiene un formato incorrecto. El método HTTP es 'GET', esperado 'POST'."
)

func TestErrorTranslation(t *testing.T) {
	catalog := newTestCatalog()

	testCases := []struct {
		name     string
		lang     language.Tag
		expected string
	}{
		{
			name:     "ShouldRenderEnglishWhenNoCatalog",
			expected: expectedEnglish,
		},
		{
			name:     "ShouldRenderSpanishWithCatalog",
			lang:     language.Spanish,
			expected: expectedSpanish,
		},
		{
			name:     "ShouldRenderEnglishWithCatalog",
			lang:     language.English,
			expected: expectedEnglish,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ErrInvalidRequest.WithHintIDOrDefaultf("badRequestMethod", "HTTP method is '%s', expected 'POST'.", http.MethodGet)

			if tc.lang != language.Und {
				err = err.WithLocalizer(catalog, tc.lang)
			}

			assert.Equal(t, tc.expected, err.GetDescription())
		})
	}
}

func TestAddLocalizerToErrWithLang(t *testing.T) {
	catalog := newTestCatalog()

	// AddLocalizerToErrWithLang matches errors whose dynamic type is *RFC6749Error,
	// matching the pointer the package's WithHintIDOrDefaultf actually returns.
	makeErr := func() *RFC6749Error {
		return ErrInvalidRequest.WithHintIDOrDefaultf("badRequestMethod", "HTTP method is '%s', expected 'POST'.", http.MethodGet)
	}

	testCases := []struct {
		name     string
		lang     language.Tag
		err      error
		localize bool
		expected string
	}{
		{
			name:     "ShouldLocalizeDirectRFC6749Error",
			lang:     language.Spanish,
			err:      makeErr(),
			localize: true,
			expected: expectedSpanish,
		},
		{
			name:     "ShouldLocalizeStackWrappedRFC6749Error",
			lang:     language.Spanish,
			err:      errors.WithStack(makeErr()),
			localize: true,
			expected: expectedSpanish,
		},
		{
			name:     "ShouldLocalizeCauseOnlyWrappedRFC6749Error",
			lang:     language.Spanish,
			err:      &causeOnlyError{cause: makeErr()},
			localize: true,
			expected: expectedSpanish,
		},
		{
			name:     "ShouldReturnNonRFCErrorUnchanged",
			lang:     language.Spanish,
			err:      errors.New("some other error"),
			localize: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := AddLocalizerToErrWithLang(catalog, tc.lang, tc.err)
			require.NotNil(t, actual)

			if !tc.localize {
				assert.Equal(t, tc.err.Error(), actual.Error())
				return
			}

			rfc, ok := actual.(*RFC6749Error)
			require.True(t, ok, "expected *RFC6749Error, got %T", actual)
			assert.Equal(t, tc.expected, rfc.GetDescription())
		})
	}

	t.Run("ShouldLocalizePointerRFC6749Error", func(t *testing.T) {
		// AddLocalizerToErrWithLang's errors.As target is *RFC6749Error, so the pointer
		// returned by the production-facing WithHintIDOrDefaultf matches and a localized
		// copy is returned. This documents the real API usage pattern.
		input := ErrInvalidRequest.WithHintIDOrDefaultf("badRequestMethod", "HTTP method is '%s', expected 'POST'.", http.MethodGet)

		actual := AddLocalizerToErrWithLang(catalog, language.Spanish, input)
		rfc, ok := actual.(*RFC6749Error)
		require.True(t, ok, "expected *RFC6749Error, got %T", actual)
		assert.Equal(t, expectedSpanish, rfc.GetDescription())
	})
}

func TestAddLocalizerToErr(t *testing.T) {
	catalog := newTestCatalog()

	testCases := []struct {
		name      string
		requester Requester
		expected  string
	}{
		{
			name:      "ShouldUseRequesterLanguageWhenG11N",
			requester: &Request{Lang: language.Spanish},
			expected:  expectedSpanish,
		},
		{
			name:      "ShouldFallBackToEnglishWhenRequesterIsNotG11N",
			requester: &nonG11NRequester{},
			expected:  expectedEnglish,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ErrInvalidRequest.WithHintIDOrDefaultf("badRequestMethod", "HTTP method is '%s', expected 'POST'.", http.MethodGet)
			actual := AddLocalizerToErr(catalog, err, tc.requester)

			rfc, ok := actual.(*RFC6749Error)
			require.True(t, ok, "expected *RFC6749Error, got %T", actual)
			assert.Equal(t, tc.expected, rfc.GetDescription())
		})
	}

	t.Run("ShouldLocalizePointerRFC6749Error", func(t *testing.T) {
		// Mirrors the real production usage where callers pass the *RFC6749Error returned by
		// WithHintIDOrDefaultf directly. The function localizes the input per the requester's
		// language tag.
		input := ErrInvalidRequest.WithHintIDOrDefaultf("badRequestMethod", "HTTP method is '%s', expected 'POST'.", http.MethodGet)

		actual := AddLocalizerToErr(catalog, input, &Request{Lang: language.Spanish})
		rfc, ok := actual.(*RFC6749Error)
		require.True(t, ok, "expected *RFC6749Error, got %T", actual)
		assert.Equal(t, expectedSpanish, rfc.GetDescription())
	})
}

func TestGetLangFromRequester(t *testing.T) {
	testCases := []struct {
		name      string
		requester Requester
		expected  language.Tag
	}{
		{
			name:      "ShouldReturnRequesterLanguageWhenG11N",
			requester: &Request{Lang: language.Spanish},
			expected:  language.Spanish,
		},
		{
			name:      "ShouldReturnEnglishForNonG11NRequester",
			requester: &nonG11NRequester{},
			expected:  language.English,
		},
		{
			name:      "ShouldReturnUndefinedWhenG11NRequesterReportsZero",
			requester: &Request{},
			expected:  language.Und,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := getLangFromRequester(tc.requester)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

// nonG11NRequester is a Requester that intentionally does not implement G11NContext
// (no GetLang method) so that getLangFromRequester falls back to the default language.
type nonG11NRequester struct {
	Requester
}

// causeOnlyError implements pkg/errors causer but does not implement Unwrap, so errors.As
// cannot traverse it and the errorsx.Cause fallback branch in AddLocalizerToErrWithLang is
// exercised.
type causeOnlyError struct {
	cause error
}

func (e *causeOnlyError) Error() string { return "cause-only wrapper" }

func (e *causeOnlyError) Cause() error { return e.cause }
