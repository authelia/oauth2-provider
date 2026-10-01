// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package compose_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/compose"
	"authelia.com/provider/oauth2/handler/idjag"
	"authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
)

func TestComposeAllEnabledRegistersIDJAG(t *testing.T) {
	config := &oauth2.Config{
		GlobalSecret:                          []byte("some-secret-thats-random-some-secret-thats-random-"),
		RFC7591ClientRegistrationGlobalSecret: []byte("another-secret-thats-random-another-secret-thats-random-"),
	}

	compose.ComposeAllEnabled(config, storage.NewMemoryStore(), gen.MustRSAKey())

	var issue, redeem bool

	for _, handler := range config.TokenEndpointHandlers {
		switch handler.(type) {
		case *idjag.IssueHandler:
			issue = true
		case *idjag.RedeemHandler:
			redeem = true
		}
	}

	assert.True(t, issue)
	assert.True(t, redeem)
}

func TestIDJAGIssueHandlerOrder(t *testing.T) {
	grant, validator, issue := &rfc8693.TokenExchangeGrantHandler{}, &rfc8693.ActorTokenValidationHandler{}, &idjag.IssueHandler{}

	testCases := []struct {
		name     string
		handlers oauth2.TokenEndpointHandlers
		err      bool
	}{
		{name: "ShouldAcceptBetweenGrantAndValidator", handlers: oauth2.TokenEndpointHandlers{grant, issue, validator}},
		{name: "ShouldRejectAfterValidator", handlers: oauth2.TokenEndpointHandlers{grant, validator, issue}, err: true},
		{name: "ShouldRejectBeforeGrant", handlers: oauth2.TokenEndpointHandlers{issue, grant, validator}, err: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := compose.ValidateHandlerOrder(&oauth2.Config{TokenEndpointHandlers: tc.handlers})

			if tc.err {
				require.ErrorIs(t, err, compose.ErrHandlerOrder)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
