// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oidckb

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
)

func TestAuthorizeHandler_BindAuthorizeRequest(t *testing.T) {
	const jkt = "dnfb1T9jil_gOhti60baHs_WD_a4D8JN9VDJXbmBmGw"

	testCases := []struct {
		name          string
		enabled       bool
		dpop          bool
		scopes        oauth2.Arguments
		responseTypes oauth2.Arguments
		jkt           string
		err           string
	}{
		{
			name: "ShouldAllowCodeFlowWithThumbprint", enabled: true, dpop: true,
			scopes:        oauth2.Arguments{consts.ScopeOpenID, consts.ScopeBoundKey},
			responseTypes: oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow}, jkt: jkt,
		},
		{
			name: "ShouldIgnoreWhenBoundKeyNotRequested", enabled: true, dpop: true,
			scopes:        oauth2.Arguments{consts.ScopeOpenID},
			responseTypes: oauth2.Arguments{consts.ResponseTypeImplicitFlowIDToken},
		},
		{
			name: "ShouldIgnoreWhenDisabled", enabled: false, dpop: true,
			scopes:        oauth2.Arguments{consts.ScopeOpenID, consts.ScopeBoundKey},
			responseTypes: oauth2.Arguments{consts.ResponseTypeImplicitFlowIDToken},
		},
		{
			name: "ShouldIgnoreWhenDPoPDisabled", enabled: true, dpop: false,
			scopes:        oauth2.Arguments{consts.ScopeOpenID, consts.ScopeBoundKey},
			responseTypes: oauth2.Arguments{consts.ResponseTypeImplicitFlowIDToken},
		},
		{
			name: "ShouldRejectMissingThumbprint", enabled: true, dpop: true,
			scopes:        oauth2.Arguments{consts.ScopeOpenID, consts.ScopeBoundKey},
			responseTypes: oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow},
			err:           "'dpop_jkt'",
		},
		{
			name: "ShouldRejectImplicitFlow", enabled: true, dpop: true,
			scopes:        oauth2.Arguments{consts.ScopeOpenID, consts.ScopeBoundKey},
			responseTypes: oauth2.Arguments{consts.ResponseTypeImplicitFlowIDToken}, jkt: jkt,
			err: "'bound_key'",
		},
		{
			name: "ShouldRejectHybridFlow", enabled: true, dpop: true,
			scopes:        oauth2.Arguments{consts.ScopeOpenID, consts.ScopeBoundKey},
			responseTypes: oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeImplicitFlowIDToken},
			jkt:           jkt, err: "'bound_key'",
		},
		{
			name: "ShouldRejectHybridFlowAccessTokenOnly", enabled: true, dpop: true,
			scopes:        oauth2.Arguments{consts.ScopeOpenID, consts.ScopeBoundKey},
			responseTypes: oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeImplicitFlowToken},
			jkt:           jkt, err: "response type 'code token'",
		},
		{
			name: "ShouldRejectBoundKeyWithoutOpenID", enabled: true, dpop: true,
			scopes:        oauth2.Arguments{consts.ScopeBoundKey},
			responseTypes: oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow}, jkt: jkt,
			err: "'openid'",
		},
		{
			name: "ShouldRejectBoundKeyWithoutOpenIDEvenWithoutThumbprint", enabled: true, dpop: true,
			scopes:        oauth2.Arguments{consts.ScopeBoundKey},
			responseTypes: oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow},
			err:           "'openid'",
		},
		{
			name: "ShouldNotRejectImplicitFlowAccessTokenOnly", enabled: true, dpop: true,
			scopes:        oauth2.Arguments{consts.ScopeOpenID, consts.ScopeBoundKey},
			responseTypes: oauth2.Arguments{consts.ResponseTypeImplicitFlowToken}, jkt: jkt,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			handler := &AuthorizeHandler{Config: &oauth2.Config{OIDCKeyBindingEnabled: tc.enabled, DPoPEnabled: tc.dpop}}

			request := oauth2.NewAuthorizeRequest()
			request.Form = url.Values{}
			request.RequestedScope = tc.scopes
			request.ResponseTypes = tc.responseTypes
			request.Session = &oauth2.DefaultSession{}

			if tc.jkt != "" {
				request.Form.Set(consts.FormParameterDPoPJKT, tc.jkt)
			}

			err := handler.BindAuthorizeRequest(t.Context(), request)

			if tc.err != "" {
				assert.ErrorIs(t, err, oauth2.ErrInvalidRequest)
				assert.Contains(t, oauth2.ErrorToDebugRFC6749Error(err).Error(), tc.err)

				return
			}

			assert.NoError(t, err)
		})
	}
}

func TestAuthorizeHandler_RecordsTheGrantedMarker(t *testing.T) {
	const jkt = "dnfb1T9jil_gOhti60baHs_WD_a4D8JN9VDJXbmBmGw"

	newRequest := func(granted oauth2.Arguments) (*oauth2.AuthorizeRequest, *oauth2.DefaultSession) {
		session := &oauth2.DefaultSession{}

		request := oauth2.NewAuthorizeRequest()
		request.Form = url.Values{consts.FormParameterDPoPJKT: []string{jkt}}
		request.RequestedScope = oauth2.Arguments{consts.ScopeOpenID, consts.ScopeBoundKey}
		request.GrantedScope = granted
		request.ResponseTypes = oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow}
		request.Session = session

		return request, session
	}

	handler := &AuthorizeHandler{Config: &oauth2.Config{OIDCKeyBindingEnabled: true, DPoPEnabled: true}}

	t.Run("ShouldRecordWhenBoundKeyGranted", func(t *testing.T) {
		request, session := newRequest(oauth2.Arguments{consts.ScopeOpenID, consts.ScopeBoundKey})

		require.NoError(t, handler.BindAuthorizeRequest(t.Context(), request))
		assert.True(t, session.GetOIDCKeyBindingGranted())
	})

	t.Run("ShouldNotRecordWhenBoundKeyRequestedButNotGranted", func(t *testing.T) {
		request, session := newRequest(oauth2.Arguments{consts.ScopeOpenID})

		require.NoError(t, handler.BindAuthorizeRequest(t.Context(), request))
		assert.False(t, session.GetOIDCKeyBindingGranted())
	})
}
