// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package i18n

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/text/language"
)

func TestGetMessage(t *testing.T) {
	catalog := newTestCatalog()

	testCases := []struct {
		name     string
		id       string
		tag      language.Tag
		args     []any
		expected string
	}{
		{
			name:     "ShouldTranslateToSpanish",
			id:       "badRequestMethod",
			tag:      language.Spanish,
			args:     []any{http.MethodGet},
			expected: "El método HTTP es 'GET', esperado 'POST'.",
		},
		{
			name:     "ShouldTranslateToEnglish",
			id:       "badRequestMethod",
			tag:      language.English,
			args:     []any{http.MethodGet},
			expected: "HTTP method is 'GET', expected 'POST'.",
		},
		{
			name:     "ShouldTranslateMessageWithoutArguments",
			id:       "badRequestBody",
			tag:      language.English,
			expected: "Unable to parse HTTP body, make sure to send a properly formatted form request body.",
		},
		{
			name:     "ShouldFallBackToEnglishForUnsupportedLocale",
			id:       "badRequestBody",
			tag:      language.Afrikaans,
			expected: "Unable to parse HTTP body, make sure to send a properly formatted form request body.",
		},
		{
			name:     "ShouldFallBackToEnglishWhenMessageMissingFromSupportedLocale",
			id:       "englishOnly",
			tag:      language.Spanish,
			expected: "This message only exists in English.",
		},
		{
			name:     "ShouldReturnIDWhenMessageIsUnknownInEnglish",
			id:       "unknownMessage",
			tag:      language.English,
			expected: "unknownMessage",
		},
		{
			name:     "ShouldReturnIDWhenMessageIsUnknownInAnyLocale",
			id:       "unknownMessage",
			tag:      language.Spanish,
			expected: "unknownMessage",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, GetMessage(catalog, tc.id, tc.tag, tc.args...))
		})
	}
}

func TestGetMessageOrDefault(t *testing.T) {
	catalog := newTestCatalog()

	testCases := []struct {
		name     string
		catalog  MessageCatalog
		id       string
		def      string
		expected string
	}{
		{
			name:     "ShouldReturnTranslatedMessageWhenFound",
			catalog:  catalog,
			id:       "badRequestBody",
			def:      "the default message",
			expected: "Unable to parse HTTP body, make sure to send a properly formatted form request body.",
		},
		{
			name:     "ShouldReturnDefaultWhenMessageNotFound",
			catalog:  catalog,
			id:       "unknownMessage",
			def:      "the default message",
			expected: "the default message",
		},
		{
			name:     "ShouldReturnDefaultWhenCatalogIsNil",
			catalog:  nil,
			id:       "badRequestBody",
			def:      "the default message",
			expected: "the default message",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, GetMessageOrDefault(tc.catalog, tc.id, language.English, tc.def))
		})
	}
}

func TestGetLangFromRequest(t *testing.T) {
	catalog := newTestCatalog()

	testCases := []struct {
		name     string
		catalog  MessageCatalog
		request  *http.Request
		expected language.Tag
	}{
		{
			name:     "ShouldReturnEnglishWhenCatalogIsNil",
			catalog:  nil,
			request:  newLangRequest("", ""),
			expected: language.English,
		},
		{
			name:     "ShouldDetectLanguageFromAcceptLanguageHeader",
			catalog:  catalog,
			request:  newLangRequest("", "es"),
			expected: language.Spanish,
		},
		{
			name:     "ShouldFallBackToEnglishForUnsupportedAcceptLanguage",
			catalog:  catalog,
			request:  newLangRequest("", "fr"),
			expected: language.English,
		},
		{
			name:     "ShouldFallBackToEnglishWhenRequestHasNoLanguage",
			catalog:  catalog,
			request:  newLangRequest("", ""),
			expected: language.English,
		},
		{
			// The 'lang' cookie is serialized through http.Cookie.String() ("lang=es") before
			// it reaches the matcher, so it never parses as a language tag. This asserts the
			// current behaviour: a 'lang' cookie has no effect on language detection.
			name:     "ShouldNotDetectLanguageFromLangCookie",
			catalog:  catalog,
			request:  newLangRequest("es", ""),
			expected: language.English,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, GetLangFromRequest(tc.catalog, tc.request))
		})
	}
}

func TestNewDefaultMessageCatalog(t *testing.T) {
	testCases := []struct {
		name     string
		bundles  []*DefaultLocaleBundle
		id       string
		expected string
	}{
		{
			name: "ShouldBuildCatalogFromValidBundles",
			bundles: []*DefaultLocaleBundle{
				{
					LangTag: "en",
					Messages: []*DefaultMessage{
						{ID: "catalogValid", FormattedMessage: "A valid catalog message."},
					},
				},
			},
			id:       "catalogValid",
			expected: "A valid catalog message.",
		},
		{
			name: "ShouldSkipBundlesThatFailToInitialize",
			bundles: []*DefaultLocaleBundle{
				{
					LangTag: "en",
					Messages: []*DefaultMessage{
						{ID: "catalogAfterSkip", FormattedMessage: "Survives a broken sibling bundle."},
					},
				},
				{
					LangTag: "en",
					Messages: []*DefaultMessage{
						{ID: "catalogBadInit", FormattedMessage: "${missing}"},
					},
				},
			},
			id:       "catalogAfterSkip",
			expected: "Survives a broken sibling bundle.",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			catalog := NewDefaultMessageCatalog(tc.bundles)
			require.NotNil(t, catalog)

			assert.Equal(t, tc.expected, GetMessage(catalog, tc.id, language.English))
		})
	}
}

func TestDefaultLocaleBundleInit(t *testing.T) {
	testCases := []struct {
		name        string
		bundle      *DefaultLocaleBundle
		expectErr   bool
		expectPanic bool
	}{
		{
			name: "ShouldInitializeValidBundle",
			bundle: &DefaultLocaleBundle{
				LangTag: "en",
				Messages: []*DefaultMessage{
					{ID: "initValid", FormattedMessage: "A valid message."},
				},
			},
		},
		{
			name: "ShouldErrorWhenMessageCannotBeCompiled",
			bundle: &DefaultLocaleBundle{
				LangTag: "en",
				Messages: []*DefaultMessage{
					{ID: "initInvalid", FormattedMessage: "${missing}"},
				},
			},
			expectErr: true,
		},
		{
			name: "ShouldPanicWhenLanguageTagIsInvalid",
			bundle: &DefaultLocaleBundle{
				LangTag: "!!!",
				Messages: []*DefaultMessage{
					{ID: "initBadTag", FormattedMessage: "Never reached."},
				},
			},
			expectPanic: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.expectPanic {
				assert.Panics(t, func() {
					_ = tc.bundle.Init()
				})

				return
			}

			err := tc.bundle.Init()

			if tc.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// newTestCatalog builds a message catalog with English and Spanish bundles used across the
// translation tests. The 'englishOnly' message is intentionally absent from the Spanish
// bundle to exercise the per-locale fallback to English.
func newTestCatalog() MessageCatalog {
	return NewDefaultMessageCatalog([]*DefaultLocaleBundle{
		{
			LangTag: "en",
			Messages: []*DefaultMessage{
				{ID: "badRequestMethod", FormattedMessage: "HTTP method is '%s', expected 'POST'."},
				{ID: "badRequestBody", FormattedMessage: "Unable to parse HTTP body, make sure to send a properly formatted form request body."},
				{ID: "englishOnly", FormattedMessage: "This message only exists in English."},
			},
		},
		{
			LangTag: "es",
			Messages: []*DefaultMessage{
				{ID: "badRequestMethod", FormattedMessage: "El método HTTP es '%s', esperado 'POST'."},
				{ID: "badRequestBody", FormattedMessage: "No se puede analizar el cuerpo HTTP, asegúrese de enviar un cuerpo de solicitud de formulario con el formato adecuado."},
			},
		},
	})
}

// newLangRequest builds an HTTP request optionally carrying a 'lang' cookie and an
// Accept-Language header.
func newLangRequest(cookie, accept string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	if cookie != "" {
		r.AddCookie(&http.Cookie{Name: "lang", Value: cookie})
	}

	if accept != "" {
		r.Header.Set("Accept-Language", accept)
	}

	return r
}
