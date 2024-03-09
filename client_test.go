// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"authelia.com/provider/oauth2/internal/consts"
)

func TestDefaultClient(t *testing.T) {
	sc := &DefaultClient{
		ID:            "1",
		RedirectURIs:  []string{"foo", "bar"},
		ResponseTypes: []string{"foo", "bar"},
		GrantTypes:    []string{"foo", "bar"},
		Scopes:        []string{"fooscope"},
	}

	assert.Equal(t, sc.ID, sc.GetID())
	assert.Equal(t, sc.RedirectURIs, sc.GetRedirectURIs())
	assert.Equal(t, sc.ClientSecret, sc.GetClientSecret())
	assert.Equal(t, sc.RotatedClientSecrets, sc.GetRotatedClientSecrets())
	assert.EqualValues(t, sc.ResponseTypes, sc.GetResponseTypes())
	assert.EqualValues(t, sc.GrantTypes, sc.GetGrantTypes())
	assert.EqualValues(t, sc.Scopes, sc.GetScopes())

	sc.GrantTypes = []string{}
	sc.ResponseTypes = []string{}
	assert.Equal(t, consts.ResponseTypeAuthorizationCodeFlow, sc.GetResponseTypes()[0])
	assert.Equal(t, consts.GrantTypeAuthorizationCode, sc.GetGrantTypes()[0])

	var _ RotatedClientSecretsClient = sc
}

func TestDefaultResponseModeClient_GetResponseMode(t *testing.T) {
	rc := &DefaultResponseModeClient{ResponseModes: []ResponseModeType{ResponseModeFragment}}
	assert.Equal(t, []ResponseModeType{ResponseModeFragment}, rc.GetResponseModes())
}
