// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
)

func TestAccessResponse(t *testing.T) {
	ar := NewAccessResponse()
	ar.SetAccessToken("access")
	ar.SetTokenType(BearerAccessToken)
	ar.SetExtra(consts.AccessResponseAccessToken, "invalid")
	ar.SetExtra("foo", "bar")
	assert.Equal(t, "access", ar.GetAccessToken())
	assert.Equal(t, BearerAccessToken, ar.GetTokenType())
	assert.Equal(t, "bar", ar.GetExtra("foo"))
	assert.Equal(t, map[string]any{
		consts.AccessResponseAccessToken: "access",
		consts.AccessResponseTokenType:   BearerAccessToken,
		"foo":                            "bar",
	}, ar.ToMap())
}
