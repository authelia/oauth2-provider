// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"bytes"
	"context"
	"html/template"
	"io"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal"
	"authelia.com/provider/oauth2/internal/consts"
)

func TestDefaultFormPostResponseWriter(t *testing.T) {
	testCases := []struct {
		name       string
		parameters url.Values
		check      func(t *testing.T, code string, state string, customParams url.Values)
	}{
		{
			name:       "ShouldRenderStandardCodeAndState",
			parameters: url.Values{consts.FormParameterAuthorizationCode: {"lshr755nsg39fgur"}, consts.FormParameterState: {"924659540232"}},
			check: func(t *testing.T, code string, state string, customParams url.Values) {
				assert.Equal(t, "lshr755nsg39fgur", code)
				assert.Equal(t, "924659540232", state)
			},
		},
		{
			name:       "ShouldRenderSpecialCharactersInCodeAndState",
			parameters: url.Values{consts.FormParameterAuthorizationCode: {"lshr75*ns-39f+ur"}, consts.FormParameterState: {"9a:* <&)"}},
			check: func(t *testing.T, code string, state string, customParams url.Values) {
				assert.Equal(t, "lshr75*ns-39f+ur", code)
				assert.Equal(t, "9a:* <&)", state)
			},
		},
		{
			name:       "ShouldRenderRepeatedCustomParameter",
			parameters: url.Values{consts.FormParameterAuthorizationCode: {"1234"}, "custom": {"test2", "test3"}},
			check: func(t *testing.T, code string, state string, customParams url.Values) {
				assert.Equal(t, "1234", code)
				assert.Equal(t, []string{"test2", "test3"}, customParams["custom"])
			},
		},
		{
			name:       "ShouldRenderHTMLEscapedCustomParameter",
			parameters: url.Values{consts.FormParameterAuthorizationCode: {"1234"}, "custom": {"<b>Bold</b>"}},
			check: func(t *testing.T, code string, state string, customParams url.Values) {
				assert.Equal(t, "1234", code)
				assert.Equal(t, "<b>Bold</b>", customParams.Get("custom"))
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var responseBuffer bytes.Buffer

			redirectURL := "https://localhost:8080/cb"
			oauth2.DefaultFormPostResponseWriter(&responseBuffer, oauth2.DefaultFormPostTemplate, redirectURL, tc.parameters)

			code, state, _, _, customParams, _, err := internal.ParseFormPostResponse(redirectURL, io.NopCloser(bytes.NewReader(responseBuffer.Bytes())))
			require.NoError(t, err)

			tc.check(t, code, state, customParams)
		})
	}
}

func TestGetPostFormHTMLTemplate(t *testing.T) {
	custom := template.Must(template.New("custom").Parse(`<html><body>custom template</body></html>`))

	testCases := []struct {
		name     string
		provider oauth2.FormPostHTMLTemplateProvider
		expected *template.Template
	}{
		{
			name:     "ShouldReturnDefaultTemplateWhenProviderReturnsNil",
			provider: &templateProvider{},
			expected: oauth2.DefaultFormPostTemplate,
		},
		{
			name:     "ShouldReturnConfiguredTemplate",
			provider: &templateProvider{tmpl: custom},
			expected: custom,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := oauth2.GetPostFormHTMLTemplate(context.Background(), tc.provider)
			assert.Same(t, tc.expected, actual)
		})
	}
}

// templateProvider is a minimal FormPostHTMLTemplateProvider used to drive GetPostFormHTMLTemplate.
type templateProvider struct {
	tmpl *template.Template
}

func (p *templateProvider) GetFormPostHTMLTemplate(_ context.Context) *template.Template {
	return p.tmpl
}
