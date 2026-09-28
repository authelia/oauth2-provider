// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package internal_test

import (
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2/internal"
)

func TestParseFormPostResponse(t *testing.T) {
	const (
		redirectURL = "https://localhost:8080/cb"
		code        = "abc"
		state       = "xyz"
	)

	testCases := []struct {
		name  string
		html  string
		code  string
		state string
		err   string
	}{
		{
			name: "ShouldParseIndentedTemplate",
			html: `<html>
  <head><title>Submit This Form</title></head>
  <body onload="javascript:document.forms[0].submit()">
    <form method="post" action="https://localhost:8080/cb">
      <input type="hidden" name="code" value="abc"/>
      <input type="hidden" name="state" value="xyz"/>
    </form>
  </body>
</html>`,
			code:  code,
			state: state,
		},
		{
			name:  "ShouldParseCompactTemplate",
			html:  `<html><head></head><body onload="javascript:document.forms[0].submit()"><form method="post" action="https://localhost:8080/cb"><input type="hidden" name="code" value="abc"/><input type="hidden" name="state" value="xyz"/></form></body></html>`,
			code:  code,
			state: state,
		},
		{
			name:  "ShouldParseTemplateWithDoctype",
			html:  `<!DOCTYPE html><html><head></head><body onload="javascript:document.forms[0].submit()"><form method="post" action="https://localhost:8080/cb"><input type="hidden" name="code" value="abc"/></form></body></html>`,
			code:  code,
			state: "",
		},
		{
			name:  "ShouldParseTemplateWithExtraAttributes",
			html:  `<html><body class="page" onload="javascript:document.forms[0].submit()"><form id="f" method="post" action="https://localhost:8080/cb"><input type="hidden" name="code" value="abc"/></form></body></html>`,
			code:  code,
			state: "",
		},
		{
			name: "ShouldErrorWhenBodyHasNoAttributes",
			html: `<html><body></body></html>`,
			err:  "onload event is missing",
		},
		{
			name: "ShouldErrorWhenOnloadIsWrong",
			html: `<html><body onload="alert(1)"></body></html>`,
			err:  "onload function is missing",
		},
		{
			name: "ShouldErrorWhenFormIsMissing",
			html: `<html><body onload="javascript:document.forms[0].submit()"></body></html>`,
			err:  "html form is missing",
		},
		{
			name: "ShouldErrorWhenMethodIsWrong",
			html: `<html><body onload="javascript:document.forms[0].submit()"><form method="get" action="https://localhost:8080/cb"></form></body></html>`,
			err:  "html form post method is missing",
		},
		{
			name: "ShouldErrorWhenActionIsWrong",
			html: `<html><body onload="javascript:document.forms[0].submit()"><form method="post" action="https://example.com/cb"></form></body></html>`,
			err:  "html form post url is wrong",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actualCode, actualState, _, _, _, _, err := internal.ParseFormPostResponse(redirectURL, io.NopCloser(strings.NewReader(tc.html)))

			if tc.err != "" {
				require.EqualError(t, err, tc.err)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.code, actualCode)
			assert.Equal(t, tc.state, actualState)
		})
	}
}
