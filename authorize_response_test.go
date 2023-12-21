// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"authelia.com/provider/oauth2/internal/consts"
)

func TestAuthorizeResponse(t *testing.T) {
	ar := NewAuthorizeResponse()
	ar.AddParameter("foo", "bar")
	ar.AddParameter("bar", "bar")

	ar.AddHeader("foo", "foo")

	ar.AddParameter(consts.FormParameterAuthorizationCode, "bar")
	assert.Equal(t, "bar", ar.GetCode())

	assert.Equal(t, "bar", ar.GetParameters().Get("foo"))
	assert.Equal(t, "foo", ar.GetHeader().Get("foo"))
	assert.Equal(t, "bar", ar.GetParameters().Get("bar"))
}
