// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"bytes"
	"io"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal"
	"authelia.com/provider/oauth2/internal/consts"
)

func TestWriteAuthorizeFormPostResponse(t *testing.T) {
	for d, c := range []struct {
		parameters url.Values
		check      func(code string, state string, customParams url.Values, d int)
	}{
		{
			parameters: url.Values{consts.FormParameterAuthorizationCode: {"lshr755nsg39fgur"}, consts.FormParameterState: {"924659540232"}},
			check: func(code string, state string, customParams url.Values, d int) {
				assert.Equal(t, "lshr755nsg39fgur", code, "case %d", d)
				assert.Equal(t, "924659540232", state, "case %d", d)
			},
		},
		{
			parameters: url.Values{consts.FormParameterAuthorizationCode: {"lshr75*ns-39f+ur"}, consts.FormParameterState: {"9a:* <&)"}},
			check: func(code string, state string, customParams url.Values, d int) {
				assert.Equal(t, "lshr75*ns-39f+ur", code, "case %d", d)
				assert.Equal(t, "9a:* <&)", state, "case %d", d)
			},
		},
		{
			parameters: url.Values{consts.FormParameterAuthorizationCode: {"1234"}, "custom": {"test2", "test3"}},
			check: func(code string, state string, customParams url.Values, d int) {
				assert.Equal(t, "1234", code, "case %d", d)
				assert.Equal(t, []string{"test2", "test3"}, customParams["custom"], "case %d", d)
			},
		},
		{
			parameters: url.Values{consts.FormParameterAuthorizationCode: {"1234"}, "custom": {"<b>Bold</b>"}},
			check: func(code string, state string, customParams url.Values, d int) {
				assert.Equal(t, "1234", code, "case %d", d)
				assert.Equal(t, "<b>Bold</b>", customParams.Get("custom"), "case %d", d)
			},
		},
	} {
		var responseBuffer bytes.Buffer

		redirectURL := "https://localhost:8080/cb"
		oauth2.DefaultFormPostResponseWriter(&responseBuffer, oauth2.DefaultFormPostTemplate, redirectURL, c.parameters)
		code, state, _, _, customParams, _, err := internal.ParseFormPostResponse(redirectURL, io.NopCloser(bytes.NewReader(responseBuffer.Bytes())))
		assert.NoError(t, err, "case %d", d)
		c.check(code, state, customParams, d)
	}
}
