// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
)

func TestFlowsRejectResourceRegisteredOnlyAsAudience(t *testing.T) {
	const resource = "https://auth.example.com/api"

	config := &oauth2.Config{}

	client := &oauth2.DefaultClient{
		ID:            "foo",
		GrantTypes:    oauth2.Arguments{consts.GrantTypeImplicit, consts.GrantTypeClientCredentials, consts.GrantTypeResourceOwnerPasswordCredentials},
		ResponseTypes: oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeImplicitFlowToken, consts.ResponseTypeNone},
		RedirectURIs:  []string{"https://app.example.com/cb"},
		Audience:      []string{resource},
	}

	redirectURI, err := url.Parse("https://app.example.com/cb")
	assert.NoError(t, err)

	authorize := func(responseType string) *oauth2.AuthorizeRequest {
		request := oauth2.NewAuthorizeRequest()
		request.Client = client
		request.ResponseTypes = oauth2.Arguments{responseType}
		request.RedirectURI = redirectURI
		request.RequestedResource = oauth2.Arguments{resource}

		return request
	}

	access := func(grantType string) *oauth2.AccessRequest {
		request := oauth2.NewAccessRequest(&oauth2.DefaultSession{})
		request.Client = client
		request.GrantTypes = oauth2.Arguments{grantType}
		request.Form = url.Values{consts.FormParameterResource: {resource}}
		request.RequestedResource = oauth2.Arguments{resource}

		return request
	}

	testCases := []struct {
		name string
		have func() error
	}{
		{
			name: "ShouldRejectAuthorizeCode",
			have: func() error {
				return (&AuthorizeExplicitGrantHandler{Config: config}).HandleAuthorizeEndpointRequest(t.Context(), authorize(consts.ResponseTypeAuthorizationCodeFlow), oauth2.NewAuthorizeResponse())
			},
		},
		{
			name: "ShouldRejectImplicit",
			have: func() error {
				return (&AuthorizeImplicitGrantTypeHandler{Config: config}).HandleAuthorizeEndpointRequest(t.Context(), authorize(consts.ResponseTypeImplicitFlowToken), oauth2.NewAuthorizeResponse())
			},
		},
		{
			name: "ShouldRejectNone",
			have: func() error {
				return (&NoneResponseTypeHandler{Config: config}).HandleAuthorizeEndpointRequest(t.Context(), authorize(consts.ResponseTypeNone), oauth2.NewAuthorizeResponse())
			},
		},
		{
			name: "ShouldRejectResourceOwnerPasswordCredentials",
			have: func() error {
				return (&ResourceOwnerPasswordCredentialsGrantHandler{Config: config}).HandleTokenEndpointRequest(t.Context(), access(consts.GrantTypeResourceOwnerPasswordCredentials))
			},
		},
		{
			name: "ShouldRejectClientCredentials",
			have: func() error {
				return (&ClientCredentialsGrantHandler{Config: config}).HandleTokenEndpointRequest(t.Context(), access(consts.GrantTypeClientCredentials))
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.ErrorIs(t, tc.have(), oauth2.ErrInvalidTarget)
		})
	}
}
