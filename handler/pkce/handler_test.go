// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package pkce

import (
	"errors"
	"fmt"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/testing/mock"
)

func TestHandler_HandleAuthorizeEndpointRequest(t *testing.T) {
	testCases := []struct {
		name      string
		requester oauth2.AuthorizeRequester
		strategy  hoauth2.AuthorizeCodeStrategy
		setup     func(t *testing.T, config *oauth2.Config, store *mock.MockPKCERequestStorage, responder oauth2.AuthorizeResponder)
		err       error
		expected  string
	}{
		{
			"ShouldPassNotAuthorizationCodeFlow",
			&oauth2.AuthorizeRequest{
				ResponseTypes: oauth2.Arguments{consts.ResponseTypeNone},
				Request: oauth2.Request{
					Client: &TestPKCEClient{DefaultClient: &oauth2.DefaultClient{ID: "test"}},
					Form:   nil,
				},
			},
			nil,
			nil,
			nil,
			"",
		},
		{
			"ShouldPassNoPKCE",
			&oauth2.AuthorizeRequest{
				ResponseTypes: oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow},
				Request: oauth2.Request{
					Client: &TestPKCEClient{DefaultClient: &oauth2.DefaultClient{ID: "test"}},
					Form:   nil,
				},
			},
			nil,
			nil,
			nil,
			"",
		},
		{
			"ShouldFailNoPKCEWithoutClientWithEnforceForPublicClients",
			&oauth2.AuthorizeRequest{
				ResponseTypes: oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow},
				Request: oauth2.Request{
					Client: nil,
					Form:   nil,
				},
			},
			nil,
			func(t *testing.T, config *oauth2.Config, store *mock.MockPKCERequestStorage, responder oauth2.AuthorizeResponder) {
				config.EnforcePKCEForPublicClients = true
			},
			oauth2.ErrServerError,
			"The authorization server encountered an unexpected condition that prevented it from fulfilling the request. The client for the request wasn't properly loaded.",
		},
		{
			"ShouldFailNoPKCEButRequiredForClient",
			&oauth2.AuthorizeRequest{
				ResponseTypes: oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow},
				Request: oauth2.Request{
					Client: &TestPKCEClient{EnforcePKCE: true, DefaultClient: &oauth2.DefaultClient{ID: "test"}},
					Form:   nil,
				},
			},
			nil,
			nil,
			oauth2.ErrInvalidRequest,
			"The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Clients must include a 'code_challenge' when performing the authorize code flow, but it is missing. The client with id 'test' is registered in a way that enforces PKCE.",
		},
		{
			"ShouldFailWithoutChallengeWithMethodButRequired",
			&oauth2.AuthorizeRequest{
				ResponseTypes: oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow},
				Request: oauth2.Request{
					Client: &TestPKCEClient{EnforcePKCE: false, DefaultClient: &oauth2.DefaultClient{ID: "test"}},
					Form:   url.Values{consts.FormParameterCodeChallengeMethod: []string{consts.PKCEChallengeMethodSHA256}},
				},
			},
			nil,
			func(t *testing.T, config *oauth2.Config, store *mock.MockPKCERequestStorage, responder oauth2.AuthorizeResponder) {
				config.EnforcePKCE = true
			},
			oauth2.ErrInvalidRequest,
			"The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Clients must include a 'code_challenge' when performing the authorize code flow, but it is missing. The authorization server is configured in a way that enforces PKCE for all clients.",
		},
		{
			"ShouldFailNoPKCEButRequiredForPublicClient",
			&oauth2.AuthorizeRequest{
				ResponseTypes: oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow},
				Request: oauth2.Request{
					Client: &TestPKCEClient{EnforcePKCE: false, DefaultClient: &oauth2.DefaultClient{ID: "test", Public: true}},
					Form:   nil,
				},
			},
			nil,
			func(t *testing.T, config *oauth2.Config, store *mock.MockPKCERequestStorage, responder oauth2.AuthorizeResponder) {
				config.EnforcePKCEForPublicClients = true
			},
			oauth2.ErrInvalidRequest,
			"The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Clients must include a 'code_challenge' when performing the authorize code flow, but it is missing. The authorization server is configured in a way that enforces PKCE for all public client type clients and the 'test' client is using the public client type.",
		},
		{
			"ShouldPassNoPKCEConfidentialClientWhenRequirePKCEForPublicClients",
			&oauth2.AuthorizeRequest{
				ResponseTypes: oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow},
				Request: oauth2.Request{
					Client: &TestPKCEClient{EnforcePKCE: false, DefaultClient: &oauth2.DefaultClient{ID: "test", Public: false}},
					Form:   nil,
				},
			},
			nil,
			func(t *testing.T, config *oauth2.Config, store *mock.MockPKCERequestStorage, responder oauth2.AuthorizeResponder) {
				config.EnforcePKCEForPublicClients = true
			},
			nil,
			"",
		},
		{
			"ShouldFailPKCEPlainWhenNotPermitted",
			&oauth2.AuthorizeRequest{
				ResponseTypes: oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow},
				Request: oauth2.Request{
					Client: &TestPKCEClient{EnforcePKCE: false, DefaultClient: &oauth2.DefaultClient{ID: "test", Public: false}},
					Form: url.Values{
						consts.FormParameterCodeChallengeMethod: []string{consts.PKCEChallengeMethodPlain},
						consts.FormParameterCodeChallenge:       []string{"abc123456"},
					},
				},
			},
			nil,
			nil,
			oauth2.ErrInvalidRequest,
			"The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Authorization was requested with 'code_challenge_method' value 'plain', but the authorization server policy does not allow method 'plain' and requires method 'S256'. The authorization server is configured in a way that enforces the 'S256' PKCE 'code_challenge_method' for all clients.",
		},
		{
			"ShouldFailLoadedAfterAuthorizeCodeHandler",
			&oauth2.AuthorizeRequest{
				ResponseTypes: oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow},
				Request: oauth2.Request{
					Client: &TestPKCEClient{EnforcePKCE: false, DefaultClient: &oauth2.DefaultClient{ID: "test", Public: false}},
					Form: url.Values{
						consts.FormParameterCodeChallengeMethod: []string{consts.PKCEChallengeMethodPlain},
						consts.FormParameterCodeChallenge:       []string{"abc123456"},
					},
				},
			},
			nil,
			func(t *testing.T, config *oauth2.Config, store *mock.MockPKCERequestStorage, responder oauth2.AuthorizeResponder) {
				config.EnablePKCEPlainChallengeMethod = true
			},
			oauth2.ErrServerError,
			"The authorization server encountered an unexpected condition that prevented it from fulfilling the request. The PKCE handler must be loaded after the authorize code handler.",
		},
		{
			"ShouldPassMethodPlain",
			&oauth2.AuthorizeRequest{
				ResponseTypes: oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow},
				Request: oauth2.Request{
					Client: &TestPKCEClient{EnforcePKCE: false, DefaultClient: &oauth2.DefaultClient{ID: "test", Public: false}},
					Form: url.Values{
						consts.FormParameterCodeChallengeMethod: []string{consts.PKCEChallengeMethodPlain},
						consts.FormParameterCodeChallenge:       []string{"abc123456"},
					},
				},
			},
			nil,
			func(t *testing.T, config *oauth2.Config, store *mock.MockPKCERequestStorage, responder oauth2.AuthorizeResponder) {
				config.EnablePKCEPlainChallengeMethod = true
				responder.AddParameter(consts.FormParameterAuthorizationCode, "abc123")

				gomock.InOrder(
					store.
						EXPECT().
						CreatePKCERequestSession(t.Context(), gomock.Any(), gomock.Any()).
						Return(nil),
				)
			},
			nil,
			"",
		},
		{
			"ShouldPassMethodS256",
			&oauth2.AuthorizeRequest{
				ResponseTypes: oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow},
				Request: oauth2.Request{
					Client: &TestPKCEClient{EnforcePKCE: true, EnforcePKCEChallengeMethod: true, PKCEChallengeMethod: "S256", DefaultClient: &oauth2.DefaultClient{ID: "test", Public: false}},
					Form: url.Values{
						consts.FormParameterCodeChallengeMethod: []string{consts.PKCEChallengeMethodSHA256},
						consts.FormParameterCodeChallenge:       []string{"abc123456"},
					},
				},
			},
			nil,
			func(t *testing.T, config *oauth2.Config, store *mock.MockPKCERequestStorage, responder oauth2.AuthorizeResponder) {
				config.EnablePKCEPlainChallengeMethod = false
				config.EnforcePKCE = true
				responder.AddParameter(consts.FormParameterAuthorizationCode, "abc123")

				gomock.InOrder(
					store.
						EXPECT().
						CreatePKCERequestSession(t.Context(), gomock.Any(), gomock.Any()).
						Return(nil),
				)
			},
			nil,
			"",
		},
		{
			"ShouldPassMethodPlainWithClientEnforce",
			&oauth2.AuthorizeRequest{
				ResponseTypes: oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow},
				Request: oauth2.Request{
					Client: &TestPKCEClient{EnforcePKCE: true, EnforcePKCEChallengeMethod: true, PKCEChallengeMethod: consts.PKCEChallengeMethodPlain, DefaultClient: &oauth2.DefaultClient{ID: "test", Public: false}},
					Form: url.Values{
						consts.FormParameterCodeChallengeMethod: []string{consts.PKCEChallengeMethodPlain},
						consts.FormParameterCodeChallenge:       []string{"abc123456"},
					},
				},
			},
			nil,
			func(t *testing.T, config *oauth2.Config, store *mock.MockPKCERequestStorage, responder oauth2.AuthorizeResponder) {
				config.EnablePKCEPlainChallengeMethod = true
				config.EnforcePKCE = false
				responder.AddParameter(consts.FormParameterAuthorizationCode, "abc123")

				gomock.InOrder(
					store.
						EXPECT().
						CreatePKCERequestSession(t.Context(), gomock.Any(), gomock.Any()).
						Return(nil),
				)
			},
			nil,
			"",
		},
		{
			"ShouldFailUnknownMethod",
			&oauth2.AuthorizeRequest{
				ResponseTypes: oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow},
				Request: oauth2.Request{
					Client: &TestPKCEClient{EnforcePKCE: false, EnforcePKCEChallengeMethod: false, DefaultClient: &oauth2.DefaultClient{ID: "test", Public: false}},
					Form: url.Values{
						consts.FormParameterCodeChallengeMethod: []string{"S252"},
						consts.FormParameterCodeChallenge:       []string{"abc123456"},
					},
				},
			},
			nil,
			func(t *testing.T, config *oauth2.Config, store *mock.MockPKCERequestStorage, responder oauth2.AuthorizeResponder) {
				config.EnablePKCEPlainChallengeMethod = true
				config.EnforcePKCE = false
				responder.AddParameter(consts.FormParameterAuthorizationCode, "abc123")
			},
			oauth2.ErrInvalidRequest,
			"The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Authorization was requested with 'code_challenge_method' value 'S252', but the authorization server doesn't know how to handle this method, try 'S256' instead.",
		},
		{
			"ShouldFailMethodS255WhenPlainEnforce",
			&oauth2.AuthorizeRequest{
				ResponseTypes: oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow},
				Request: oauth2.Request{
					Client: &TestPKCEClient{EnforcePKCE: true, EnforcePKCEChallengeMethod: true, PKCEChallengeMethod: consts.PKCEChallengeMethodPlain, DefaultClient: &oauth2.DefaultClient{ID: "test", Public: false}},
					Form: url.Values{
						consts.FormParameterCodeChallengeMethod: []string{consts.PKCEChallengeMethodSHA256},
						consts.FormParameterCodeChallenge:       []string{"abc123456"},
					},
				},
			},
			nil,
			func(t *testing.T, config *oauth2.Config, store *mock.MockPKCERequestStorage, responder oauth2.AuthorizeResponder) {
				config.EnablePKCEPlainChallengeMethod = true
				config.EnforcePKCE = false
				responder.AddParameter(consts.FormParameterAuthorizationCode, "abc123")
			},
			oauth2.ErrInvalidRequest,
			"The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Authorization was requested with 'code_challenge_method' value 'S256', but the authorization server policy does not allow method 'S256' and requires method 'plain'. The registered client with id 'test' is configured in a way that enforces the use of 'code_challenge_method' with a value of 'plain' but the authorization request included method 'S256'.",
		},
		{
			"ShouldPassMethodEmptyWhenPlainEnforce",
			&oauth2.AuthorizeRequest{
				ResponseTypes: oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow},
				Request: oauth2.Request{
					Client: &TestPKCEClient{EnforcePKCE: true, EnforcePKCEChallengeMethod: true, PKCEChallengeMethod: consts.PKCEChallengeMethodPlain, DefaultClient: &oauth2.DefaultClient{ID: "test", Public: false}},
					Form: url.Values{
						consts.FormParameterCodeChallenge: []string{"abc123456"},
					},
				},
			},
			nil,
			func(t *testing.T, config *oauth2.Config, store *mock.MockPKCERequestStorage, responder oauth2.AuthorizeResponder) {
				config.EnablePKCEPlainChallengeMethod = true
				config.EnforcePKCE = false
				responder.AddParameter(consts.FormParameterAuthorizationCode, "abc123")

				gomock.InOrder(
					store.
						EXPECT().
						CreatePKCERequestSession(t.Context(), gomock.Any(), gomock.Any()).
						Return(nil),
				)
			},
			nil,
			"",
		},
		{
			"ShouldFailStoreError",
			&oauth2.AuthorizeRequest{
				ResponseTypes: oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow},
				Request: oauth2.Request{
					Client: &TestPKCEClient{EnforcePKCE: false, DefaultClient: &oauth2.DefaultClient{ID: "test", Public: false}},
					Form: url.Values{
						consts.FormParameterCodeChallengeMethod: []string{consts.PKCEChallengeMethodPlain},
						consts.FormParameterCodeChallenge:       []string{"abc123456"},
					},
				},
			},
			nil,
			func(t *testing.T, config *oauth2.Config, store *mock.MockPKCERequestStorage, responder oauth2.AuthorizeResponder) {
				config.EnablePKCEPlainChallengeMethod = true
				responder.AddParameter(consts.FormParameterAuthorizationCode, "abc123.sig")

				gomock.InOrder(
					store.
						EXPECT().
						CreatePKCERequestSession(t.Context(), gomock.Any(), gomock.Any()).
						Return(fmt.Errorf("bad connection")),
				)
			},
			oauth2.ErrServerError,
			"The authorization server encountered an unexpected condition that prevented it from fulfilling the request. Error occurred attempting create PKCE request session: bad connection.",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)

			defer ctrl.Finish()

			store := mock.NewMockPKCERequestStorage(ctrl)

			config := &oauth2.Config{
				GlobalSecret: []byte("foofoofoofoofoofoofoofoofoofoofoo"),
			}

			responder := oauth2.NewAuthorizeResponse()

			if tc.setup != nil {
				tc.setup(t, config, store, responder)
			}

			// Configure the provided strategy or the fallback.
			var strategy hoauth2.AuthorizeCodeStrategy

			if tc.strategy == nil {
				strategy = hoauth2.NewCoreStrategy(config, "authelia_%s_", nil)
			} else {
				strategy = tc.strategy
			}

			handler := &Handler{
				AuthorizeCodeStrategy: strategy,
				Storage:               store,
				Config:                config,
			}

			err := handler.HandleAuthorizeEndpointRequest(t.Context(), tc.requester, responder)

			if len(tc.expected) == 0 && tc.err == nil {
				assert.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
			} else {
				require.NotNil(t, err)
				assert.EqualError(t, err, tc.err.Error())
				assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.expected)
			}
		})
	}
}

func TestHandler_HandleTokenEndpointRequest(t *testing.T) {
	testCases := []struct {
		name      string
		requester oauth2.AccessRequester
		strategy  hoauth2.AuthorizeCodeStrategy
		setup     func(t *testing.T, config *oauth2.Config, store *mock.MockPKCERequestStorage)
		err       error
		expected  string
	}{
		{
			"ShouldFailNotResponsible",
			&oauth2.AccessRequest{
				Request: oauth2.Request{
					Client: &TestPKCEClient{DefaultClient: &oauth2.DefaultClient{ID: "test"}},
					Form:   nil,
				},
			},
			nil,
			nil,
			oauth2.ErrUnknownRequest,
			"The handler is not responsible for this request.",
		},
		{
			"ShouldPassNoPKCE",
			&oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
				Request: oauth2.Request{
					Client:  &TestPKCEClient{DefaultClient: &oauth2.DefaultClient{ID: "test"}},
					Session: &oauth2.DefaultSession{},
					Form: url.Values{
						consts.FormParameterAuthorizationCode: []string{"abc123.sig"},
					},
				},
			},
			nil,
			func(t *testing.T, config *oauth2.Config, store *mock.MockPKCERequestStorage) {
				gomock.InOrder(
					store.
						EXPECT().
						GetPKCERequestSession(t.Context(), "sig", gomock.Any()).
						Return(nil, oauth2.ErrNotFound),
				)
			},
			nil,
			"",
		},
		{
			"ShouldFailNoPKCESessionWithPKCEEnforced",
			&oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
				Request: oauth2.Request{
					Client:  &TestPKCEClient{DefaultClient: &oauth2.DefaultClient{ID: "test"}},
					Session: &oauth2.DefaultSession{},
					Form: url.Values{
						consts.FormParameterAuthorizationCode: []string{"abc123.sig"},
					},
				},
			},
			nil,
			func(t *testing.T, config *oauth2.Config, store *mock.MockPKCERequestStorage) {
				config.EnforcePKCE = true
				gomock.InOrder(
					store.
						EXPECT().
						GetPKCERequestSession(t.Context(), "sig", gomock.Any()).
						Return(nil, oauth2.ErrNotFound),
				)
			},
			oauth2.ErrInvalidRequest,
			"The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Clients must include a 'code_verifier' when performing the authorize code flow, but it is missing. The authorization server is configured in a way that enforces PKCE for all clients.",
		},
		{
			"ShouldFailNoPKCESessionWithPKCEVerifier",
			&oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
				Request: oauth2.Request{
					Client:  &TestPKCEClient{DefaultClient: &oauth2.DefaultClient{ID: "test"}},
					Session: &oauth2.DefaultSession{},
					Form: url.Values{
						consts.FormParameterAuthorizationCode: []string{"abc123.sig"},
						consts.FormParameterCodeVerifier:      []string{"abc123"},
					},
				},
			},
			nil,
			func(t *testing.T, config *oauth2.Config, store *mock.MockPKCERequestStorage) {
				config.EnforcePKCE = true
				gomock.InOrder(
					store.
						EXPECT().
						GetPKCERequestSession(t.Context(), "sig", gomock.Any()).
						Return(nil, oauth2.ErrNotFound),
				)
			},
			oauth2.ErrInvalidGrant,
			"The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. Unable to find initial PKCE data tied to this request. Could not find the requested resource(s).",
		},
		{
			"ShouldFailStorageGetError",
			&oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
				Request: oauth2.Request{
					Client:  &TestPKCEClient{DefaultClient: &oauth2.DefaultClient{ID: "test"}},
					Session: &oauth2.DefaultSession{},
					Form: url.Values{
						consts.FormParameterAuthorizationCode: []string{"abc123.sig"},
						consts.FormParameterCodeVerifier:      []string{"abc123"},
					},
				},
			},
			nil,
			func(t *testing.T, config *oauth2.Config, store *mock.MockPKCERequestStorage) {
				config.EnforcePKCE = true
				gomock.InOrder(
					store.
						EXPECT().
						GetPKCERequestSession(t.Context(), "sig", gomock.Any()).
						Return(nil, errors.New("bad connection")),
				)
			},
			oauth2.ErrServerError,
			"The authorization server encountered an unexpected condition that prevented it from fulfilling the request. Error occurred attempting get PKCE request session: bad connection.",
		},
		{
			"ShouldFailStorageDeleteError",
			&oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
				Request: oauth2.Request{
					Client:  &TestPKCEClient{DefaultClient: &oauth2.DefaultClient{ID: "test"}},
					Session: &oauth2.DefaultSession{},
					Form: url.Values{
						consts.FormParameterAuthorizationCode: []string{"abc123.sig"},
						consts.FormParameterCodeVerifier:      []string{"abc123"},
					},
				},
			},
			nil,
			func(t *testing.T, config *oauth2.Config, store *mock.MockPKCERequestStorage) {
				config.EnforcePKCE = true
				gomock.InOrder(
					store.
						EXPECT().
						GetPKCERequestSession(t.Context(), "sig", gomock.Any()).
						Return(&oauth2.Request{}, nil),
					store.
						EXPECT().
						DeletePKCERequestSession(t.Context(), "sig").
						Return(errors.New("bad connection")),
				)
			},
			oauth2.ErrServerError,
			"The authorization server encountered an unexpected condition that prevented it from fulfilling the request. Error occurred attempting delete PKCE request session: bad connection.",
		},
		{
			"ShouldFailMissingOriginalCodeChallenge",
			&oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
				Request: oauth2.Request{
					Client:  &TestPKCEClient{DefaultClient: &oauth2.DefaultClient{ID: "test"}},
					Session: &oauth2.DefaultSession{},
					Form: url.Values{
						consts.FormParameterAuthorizationCode: []string{"abc123.sig"},
						consts.FormParameterCodeVerifier:      []string{"abc123"},
					},
				},
			},
			nil,
			func(t *testing.T, config *oauth2.Config, store *mock.MockPKCERequestStorage) {
				config.EnforcePKCE = true
				gomock.InOrder(
					store.
						EXPECT().
						GetPKCERequestSession(t.Context(), "sig", gomock.Any()).
						Return(&oauth2.Request{}, nil),
					store.
						EXPECT().
						DeletePKCERequestSession(t.Context(), "sig").
						Return(nil),
				)
			},
			oauth2.ErrInvalidRequest,
			"The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Clients must include a 'code_challenge' when performing the authorize code flow, but it is missing. The authorization server is configured in a way that enforces PKCE for all clients.",
		},
		{
			"ShouldPassSessionExistsButNoValues",
			&oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
				Request: oauth2.Request{
					Client:  &TestPKCEClient{DefaultClient: &oauth2.DefaultClient{ID: "test"}},
					Session: &oauth2.DefaultSession{},
					Form: url.Values{
						consts.FormParameterAuthorizationCode: []string{"abc123.sig"},
					},
				},
			},
			nil,
			func(t *testing.T, config *oauth2.Config, store *mock.MockPKCERequestStorage) {
				config.EnforcePKCE = false
				gomock.InOrder(
					store.
						EXPECT().
						GetPKCERequestSession(t.Context(), "sig", gomock.Any()).
						Return(&oauth2.Request{}, nil),
					store.
						EXPECT().
						DeletePKCERequestSession(t.Context(), "sig").
						Return(nil),
				)
			},
			nil,
			"",
		},
		{
			"ShouldFailClientRequiresPKCE",
			&oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
				Request: oauth2.Request{
					Client:  &TestPKCEClient{EnforcePKCE: true, DefaultClient: &oauth2.DefaultClient{ID: "test"}},
					Session: &oauth2.DefaultSession{},
					Form: url.Values{
						consts.FormParameterAuthorizationCode: []string{"abc123.sig"},
					},
				},
			},
			nil,
			func(t *testing.T, config *oauth2.Config, store *mock.MockPKCERequestStorage) {
				config.EnforcePKCE = false
				gomock.InOrder(
					store.
						EXPECT().
						GetPKCERequestSession(t.Context(), "sig", gomock.Any()).
						Return(&oauth2.Request{
							Client: &TestPKCEClient{EnforcePKCE: false, DefaultClient: &oauth2.DefaultClient{ID: "test"}},
						}, nil),
					store.
						EXPECT().
						DeletePKCERequestSession(t.Context(), "sig").
						Return(nil),
				)
			},
			oauth2.ErrInvalidRequest,
			"The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Clients must include a 'code_challenge' when performing the authorize code flow, but it is missing. The client with id 'test' is registered in a way that enforces PKCE.",
		},
		{
			"ShouldFailClientRequiresPKCEInPKCESession",
			&oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
				Request: oauth2.Request{
					Client:  &TestPKCEClient{EnforcePKCE: false, DefaultClient: &oauth2.DefaultClient{ID: "test"}},
					Session: &oauth2.DefaultSession{},
					Form: url.Values{
						consts.FormParameterAuthorizationCode: []string{"abc123.sig"},
					},
				},
			},
			nil,
			func(t *testing.T, config *oauth2.Config, store *mock.MockPKCERequestStorage) {
				config.EnforcePKCE = false
				gomock.InOrder(
					store.
						EXPECT().
						GetPKCERequestSession(t.Context(), "sig", gomock.Any()).
						Return(&oauth2.Request{
							Client: &TestPKCEClient{EnforcePKCE: true, DefaultClient: &oauth2.DefaultClient{ID: "test"}},
						}, nil),
					store.
						EXPECT().
						DeletePKCERequestSession(t.Context(), "sig").
						Return(nil),
				)
			},
			oauth2.ErrInvalidRequest,
			"The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Clients must include a 'code_challenge' when performing the authorize code flow, but it is missing. The client with id 'test' is registered in a way that enforces PKCE.",
		},
		{
			"ShouldFailServerRequiresPKCEForPublicClient",
			&oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
				Request: oauth2.Request{
					Client:  &TestPKCEClient{DefaultClient: &oauth2.DefaultClient{ID: "test", Public: true}},
					Session: &oauth2.DefaultSession{},
					Form: url.Values{
						consts.FormParameterAuthorizationCode: []string{"abc123.sig"},
					},
				},
			},
			nil,
			func(t *testing.T, config *oauth2.Config, store *mock.MockPKCERequestStorage) {
				config.EnforcePKCEForPublicClients = true
				gomock.InOrder(
					store.
						EXPECT().
						GetPKCERequestSession(t.Context(), "sig", gomock.Any()).
						Return(&oauth2.Request{
							Client: &TestPKCEClient{DefaultClient: &oauth2.DefaultClient{ID: "test"}},
						}, nil),
					store.
						EXPECT().
						DeletePKCERequestSession(t.Context(), "sig").
						Return(nil),
				)
			},
			oauth2.ErrInvalidRequest,
			"The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Clients must include a 'code_challenge' when performing the authorize code flow, but it is missing. The authorization server is configured in a way that enforces PKCE for all public client type clients and the 'test' client is using the public client type.",
		},
		{
			"ShouldFailServerRequiresPKCEForPublicClientInPKCESession",
			&oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
				Request: oauth2.Request{
					Client:  &TestPKCEClient{DefaultClient: &oauth2.DefaultClient{ID: "test", Public: false}},
					Session: &oauth2.DefaultSession{},
					Form: url.Values{
						consts.FormParameterAuthorizationCode: []string{"abc123.sig"},
					},
				},
			},
			nil,
			func(t *testing.T, config *oauth2.Config, store *mock.MockPKCERequestStorage) {
				config.EnforcePKCEForPublicClients = true
				gomock.InOrder(
					store.
						EXPECT().
						GetPKCERequestSession(t.Context(), "sig", gomock.Any()).
						Return(&oauth2.Request{
							Client: &TestPKCEClient{DefaultClient: &oauth2.DefaultClient{ID: "test", Public: true}},
						}, nil),
					store.
						EXPECT().
						DeletePKCERequestSession(t.Context(), "sig").
						Return(nil),
				)
			},
			oauth2.ErrInvalidRequest,
			"The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Clients must include a 'code_challenge' when performing the authorize code flow, but it is missing. The authorization server is configured in a way that enforces PKCE for all public client type clients and the 'test' client is using the public client type.",
		},
		{
			"ShouldFailServerRequiresPKCE",
			&oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
				Request: oauth2.Request{
					Client:  &TestPKCEClient{EnforcePKCE: false, DefaultClient: &oauth2.DefaultClient{ID: "test"}},
					Session: &oauth2.DefaultSession{},
					Form: url.Values{
						consts.FormParameterAuthorizationCode: []string{"abc123.sig"},
					},
				},
			},
			nil,
			func(t *testing.T, config *oauth2.Config, store *mock.MockPKCERequestStorage) {
				config.EnforcePKCE = true
				gomock.InOrder(
					store.
						EXPECT().
						GetPKCERequestSession(t.Context(), "sig", gomock.Any()).
						Return(&oauth2.Request{
							Client: &TestPKCEClient{EnforcePKCE: false, DefaultClient: &oauth2.DefaultClient{ID: "test"}},
						}, nil),
					store.
						EXPECT().
						DeletePKCERequestSession(t.Context(), "sig").
						Return(nil),
				)
			},
			oauth2.ErrInvalidRequest,
			"The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Clients must include a 'code_challenge' when performing the authorize code flow, but it is missing. The authorization server is configured in a way that enforces PKCE for all clients.",
		},
		{
			"ShouldFailServerRequiresPKCEPublicClient",
			&oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
				Request: oauth2.Request{
					Client:  &TestPKCEClient{EnforcePKCE: false, DefaultClient: &oauth2.DefaultClient{ID: "test", Public: true}},
					Session: &oauth2.DefaultSession{},
					Form: url.Values{
						consts.FormParameterAuthorizationCode: []string{"abc123.sig"},
					},
				},
			},
			nil,
			func(t *testing.T, config *oauth2.Config, store *mock.MockPKCERequestStorage) {
				config.EnforcePKCEForPublicClients = true
				gomock.InOrder(
					store.
						EXPECT().
						GetPKCERequestSession(t.Context(), "sig", gomock.Any()).
						Return(&oauth2.Request{
							Client: &TestPKCEClient{EnforcePKCE: false, DefaultClient: &oauth2.DefaultClient{ID: "test"}},
						}, nil),
					store.
						EXPECT().
						DeletePKCERequestSession(t.Context(), "sig").
						Return(nil),
				)
			},
			oauth2.ErrInvalidRequest,
			"The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Clients must include a 'code_challenge' when performing the authorize code flow, but it is missing. The authorization server is configured in a way that enforces PKCE for all public client type clients and the 'test' client is using the public client type.",
		},
		{
			"ShouldFailVerifierTooShort",
			&oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
				Request: oauth2.Request{
					Client:  &TestPKCEClient{EnforcePKCE: false, DefaultClient: &oauth2.DefaultClient{ID: "test", Public: true}},
					Session: &oauth2.DefaultSession{},
					Form: url.Values{
						consts.FormParameterAuthorizationCode: []string{"abc123.sig"},
						consts.FormParameterCodeVerifier:      []string{"short"},
					},
				},
			},
			nil,
			func(t *testing.T, config *oauth2.Config, store *mock.MockPKCERequestStorage) {
				gomock.InOrder(
					store.
						EXPECT().
						GetPKCERequestSession(t.Context(), "sig", gomock.Any()).
						Return(&oauth2.Request{
							Client: &TestPKCEClient{EnforcePKCE: false, DefaultClient: &oauth2.DefaultClient{ID: "test"}},
						}, nil),
					store.
						EXPECT().
						DeletePKCERequestSession(t.Context(), "sig").
						Return(nil),
				)
			},
			oauth2.ErrInvalidGrant,
			"The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. The PKCE code verifier must be at least 43 characters.",
		},
		{
			"ShouldFailVerifierTooLong",
			&oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
				Request: oauth2.Request{
					Client:  &TestPKCEClient{EnforcePKCE: false, DefaultClient: &oauth2.DefaultClient{ID: "test", Public: true}},
					Session: &oauth2.DefaultSession{},
					Form: url.Values{
						consts.FormParameterAuthorizationCode: []string{"abc123.sig"},
						consts.FormParameterCodeVerifier:      []string{"abcabcabc9abcabcabc9abcabcabc9abcabcabc9abcabcabc9abcabcabc9abcabcabc9abcabcabc9abcabcabc9abcabcabc9abcabcabc9abcabcabc9abcabcabc9"},
					},
				},
			},
			nil,
			func(t *testing.T, config *oauth2.Config, store *mock.MockPKCERequestStorage) {
				gomock.InOrder(
					store.
						EXPECT().
						GetPKCERequestSession(t.Context(), "sig", gomock.Any()).
						Return(&oauth2.Request{
							Client: &TestPKCEClient{EnforcePKCE: false, DefaultClient: &oauth2.DefaultClient{ID: "test"}},
						}, nil),
					store.
						EXPECT().
						DeletePKCERequestSession(t.Context(), "sig").
						Return(nil),
				)
			},
			oauth2.ErrInvalidGrant,
			"The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. The PKCE code verifier must be no more than 128 characters.",
		},
		{
			"ShouldFailVerifierBuNoCode",
			&oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
				Request: oauth2.Request{
					Client:  &TestPKCEClient{EnforcePKCE: false, DefaultClient: &oauth2.DefaultClient{ID: "test", Public: true}},
					Session: &oauth2.DefaultSession{},
					Form: url.Values{
						consts.FormParameterAuthorizationCode: []string{"abc123.sig"},
						consts.FormParameterCodeVerifier:      []string{"abcabcabc9abcabcabc9abcabcabc9abcabcabc9abcabcabc9"},
					},
				},
			},
			nil,
			func(t *testing.T, config *oauth2.Config, store *mock.MockPKCERequestStorage) {
				gomock.InOrder(
					store.
						EXPECT().
						GetPKCERequestSession(t.Context(), "sig", gomock.Any()).
						Return(&oauth2.Request{
							Client: &TestPKCEClient{EnforcePKCE: false, DefaultClient: &oauth2.DefaultClient{ID: "test"}},
						}, nil),
					store.
						EXPECT().
						DeletePKCERequestSession(t.Context(), "sig").
						Return(nil),
				)
			},
			oauth2.ErrInvalidGrant,
			"The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. The PKCE code verifier was provided but the code challenge was absent from the authorization request.",
		},
		{
			"ShouldFailVerifierInvalidValues",
			&oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
				Request: oauth2.Request{
					Client:  &TestPKCEClient{EnforcePKCE: false, DefaultClient: &oauth2.DefaultClient{ID: "test", Public: true}},
					Session: &oauth2.DefaultSession{},
					Form: url.Values{
						consts.FormParameterAuthorizationCode: []string{"abc123.sig"},
						consts.FormParameterCodeVerifier:      []string{"abcabcabc9abcabcabc9abcabcabc9abcabcabc9abcabcabc9@@"},
					},
				},
			},
			nil,
			func(t *testing.T, config *oauth2.Config, store *mock.MockPKCERequestStorage) {
				gomock.InOrder(
					store.
						EXPECT().
						GetPKCERequestSession(t.Context(), "sig", gomock.Any()).
						Return(&oauth2.Request{
							Client: &TestPKCEClient{EnforcePKCE: false, DefaultClient: &oauth2.DefaultClient{ID: "test"}},
							Form: url.Values{
								consts.FormParameterCodeChallenge:       []string{"example"},
								consts.FormParameterCodeChallengeMethod: []string{consts.PKCEChallengeMethodSHA256},
							},
						}, nil),
					store.
						EXPECT().
						DeletePKCERequestSession(t.Context(), "sig").
						Return(nil),
				)
			},
			oauth2.ErrInvalidGrant,
			"The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. The PKCE code verifier must only contain [a-Z], [0-9], '-', '.', '_', '~'.",
		},
		{
			"ShouldFailMethodPlainImplicit",
			&oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
				Request: oauth2.Request{
					Client:  &TestPKCEClient{EnforcePKCE: false, DefaultClient: &oauth2.DefaultClient{ID: "test", Public: true}},
					Session: &oauth2.DefaultSession{},
					Form: url.Values{
						consts.FormParameterAuthorizationCode: []string{"abc123.sig"},
						consts.FormParameterCodeVerifier:      []string{"abcabcabc9abcabcabc9abcabcabc9abcabcabc9abcabcabc9@@"},
					},
				},
			},
			nil,
			func(t *testing.T, config *oauth2.Config, store *mock.MockPKCERequestStorage) {
				gomock.InOrder(
					store.
						EXPECT().
						GetPKCERequestSession(t.Context(), "sig", gomock.Any()).
						Return(&oauth2.Request{
							Client: &TestPKCEClient{EnforcePKCE: false, DefaultClient: &oauth2.DefaultClient{ID: "test"}},
							Form: url.Values{
								consts.FormParameterCodeChallenge: []string{"example"},
							},
						}, nil),
					store.
						EXPECT().
						DeletePKCERequestSession(t.Context(), "sig").
						Return(nil),
				)
			},
			oauth2.ErrInvalidRequest,
			"The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Authorization was requested with 'code_challenge_method' value 'plain', but the authorization server policy does not allow method 'plain' and requires method 'S256'. The authorization server is configured in a way that enforces the 'S256' PKCE 'code_challenge_method' for all clients.",
		},
		{
			"ShouldFailMethodPlainExplicit",
			&oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
				Request: oauth2.Request{
					Client:  &TestPKCEClient{EnforcePKCE: false, DefaultClient: &oauth2.DefaultClient{ID: "test", Public: true}},
					Session: &oauth2.DefaultSession{},
					Form: url.Values{
						consts.FormParameterAuthorizationCode: []string{"abc123.sig"},
						consts.FormParameterCodeVerifier:      []string{"abcabcabc9abcabcabc9abcabcabc9abcabcabc9abcabcabc9@@"},
					},
				},
			},
			nil,
			func(t *testing.T, config *oauth2.Config, store *mock.MockPKCERequestStorage) {
				gomock.InOrder(
					store.
						EXPECT().
						GetPKCERequestSession(t.Context(), "sig", gomock.Any()).
						Return(&oauth2.Request{
							Client: &TestPKCEClient{EnforcePKCE: false, DefaultClient: &oauth2.DefaultClient{ID: "test"}},
							Form: url.Values{
								consts.FormParameterCodeChallenge:       []string{"example"},
								consts.FormParameterCodeChallengeMethod: []string{consts.PKCEChallengeMethodPlain},
							},
						}, nil),
					store.
						EXPECT().
						DeletePKCERequestSession(t.Context(), "sig").
						Return(nil),
				)
			},
			oauth2.ErrInvalidRequest,
			"The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Authorization was requested with 'code_challenge_method' value 'plain', but the authorization server policy does not allow method 'plain' and requires method 'S256'. The authorization server is configured in a way that enforces the 'S256' PKCE 'code_challenge_method' for all clients.",
		},
		{
			"ShouldFailMethodPlainExplicit",
			&oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
				Request: oauth2.Request{
					Client:  &TestPKCEClient{EnforcePKCE: false, DefaultClient: &oauth2.DefaultClient{ID: "test", Public: true}},
					Session: &oauth2.DefaultSession{},
					Form: url.Values{
						consts.FormParameterAuthorizationCode: []string{"abc123.sig"},
						consts.FormParameterCodeVerifier:      []string{"abcabcabc9abcabcabc9abcabcabc9abcabcabc9abcabcabc9@@"},
					},
				},
			},
			nil,
			func(t *testing.T, config *oauth2.Config, store *mock.MockPKCERequestStorage) {
				gomock.InOrder(
					store.
						EXPECT().
						GetPKCERequestSession(t.Context(), "sig", gomock.Any()).
						Return(&oauth2.Request{
							Client: &TestPKCEClient{EnforcePKCE: false, DefaultClient: &oauth2.DefaultClient{ID: "test"}},
							Form: url.Values{
								consts.FormParameterCodeChallenge:       []string{"example"},
								consts.FormParameterCodeChallengeMethod: []string{"nope"},
							},
						}, nil),
					store.
						EXPECT().
						DeletePKCERequestSession(t.Context(), "sig").
						Return(nil),
				)
			},
			oauth2.ErrInvalidRequest,
			"The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Authorization was requested with 'code_challenge_method' value 'nope', but the authorization server doesn't know how to handle this method, try 'S256' instead.",
		},
		{
			"ShouldFailMethodS256ClientRequiresPlain",
			&oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
				Request: oauth2.Request{
					Client:  &TestPKCEClient{EnforcePKCE: false, EnforcePKCEChallengeMethod: true, PKCEChallengeMethod: consts.PKCEChallengeMethodPlain, DefaultClient: &oauth2.DefaultClient{ID: "test", Public: true}},
					Session: &oauth2.DefaultSession{},
					Form: url.Values{
						consts.FormParameterAuthorizationCode: []string{"abc123.sig"},
						consts.FormParameterCodeVerifier:      []string{"abcabcabc9abcabcabc9abcabcabc9abcabcabc9abcabcabc9@@"},
					},
				},
			},
			nil,
			func(t *testing.T, config *oauth2.Config, store *mock.MockPKCERequestStorage) {
				gomock.InOrder(
					store.
						EXPECT().
						GetPKCERequestSession(t.Context(), "sig", gomock.Any()).
						Return(&oauth2.Request{
							Client: &TestPKCEClient{EnforcePKCE: false, DefaultClient: &oauth2.DefaultClient{ID: "test"}},
							Form: url.Values{
								consts.FormParameterCodeChallenge:       []string{"example"},
								consts.FormParameterCodeChallengeMethod: []string{consts.PKCEChallengeMethodSHA256},
							},
						}, nil),
					store.
						EXPECT().
						DeletePKCERequestSession(t.Context(), "sig").
						Return(nil),
				)
			},
			oauth2.ErrInvalidRequest,
			"The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Authorization was requested with 'code_challenge_method' value 'S256', but the authorization server policy does not allow method 'S256' and requires method 'plain'. The registered client with id 'test' is configured in a way that enforces the use of 'code_challenge_method' with a value of 'plain' but the authorization request included method 'S256'.",
		},
		{
			"ShouldFailMethodS256ClientRequiresPlain",
			&oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
				Request: oauth2.Request{
					Client:  &TestPKCEClient{EnforcePKCE: false, EnforcePKCEChallengeMethod: false, PKCEChallengeMethod: consts.PKCEChallengeMethodPlain, DefaultClient: &oauth2.DefaultClient{ID: "test", Public: true}},
					Session: &oauth2.DefaultSession{},
					Form: url.Values{
						consts.FormParameterAuthorizationCode: []string{"abc123.sig"},
						consts.FormParameterCodeVerifier:      []string{"abcabcabc9abcabcabc9abcabcabc9abcabcabc9abcabcabc9@@"},
					},
				},
			},
			nil,
			func(t *testing.T, config *oauth2.Config, store *mock.MockPKCERequestStorage) {
				gomock.InOrder(
					store.
						EXPECT().
						GetPKCERequestSession(t.Context(), "sig", gomock.Any()).
						Return(&oauth2.Request{
							Client: &TestPKCEClient{EnforcePKCE: false, EnforcePKCEChallengeMethod: true, PKCEChallengeMethod: consts.PKCEChallengeMethodPlain, DefaultClient: &oauth2.DefaultClient{ID: "test", Public: true}},
							Form: url.Values{
								consts.FormParameterCodeChallenge:       []string{"example"},
								consts.FormParameterCodeChallengeMethod: []string{consts.PKCEChallengeMethodSHA256},
							},
						}, nil),
					store.
						EXPECT().
						DeletePKCERequestSession(t.Context(), "sig").
						Return(nil),
				)
			},
			oauth2.ErrInvalidRequest,
			"The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Authorization was requested with 'code_challenge_method' value 'S256', but the authorization server policy does not allow method 'S256' and requires method 'plain'. The registered client with id 'test' is configured in a way that enforces the use of 'code_challenge_method' with a value of 'plain' but the authorization request included method 'S256'.",
		},
		{
			"ShouldPassMethodPlainImplicit",
			&oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
				Request: oauth2.Request{
					Client:  &TestPKCEClient{EnforcePKCE: false, EnforcePKCEChallengeMethod: true, PKCEChallengeMethod: consts.PKCEChallengeMethodPlain, DefaultClient: &oauth2.DefaultClient{ID: "test", Public: true}},
					Session: &oauth2.DefaultSession{},
					Form: url.Values{
						consts.FormParameterAuthorizationCode: []string{"abc123.sig"},
						consts.FormParameterCodeVerifier:      []string{"abcabcabc9abcabcabc9abcabcabc9abcabcabc9abcabcabc9"},
					},
				},
			},
			nil,
			func(t *testing.T, config *oauth2.Config, store *mock.MockPKCERequestStorage) {
				config.EnablePKCEPlainChallengeMethod = true
				gomock.InOrder(
					store.
						EXPECT().
						GetPKCERequestSession(t.Context(), "sig", gomock.Any()).
						Return(&oauth2.Request{
							Client: &TestPKCEClient{EnforcePKCE: false, EnforcePKCEChallengeMethod: true, PKCEChallengeMethod: consts.PKCEChallengeMethodPlain, DefaultClient: &oauth2.DefaultClient{ID: "test", Public: true}},
							Form: url.Values{
								consts.FormParameterCodeChallenge: []string{"abcabcabc9abcabcabc9abcabcabc9abcabcabc9abcabcabc9"},
							},
						}, nil),
					store.
						EXPECT().
						DeletePKCERequestSession(t.Context(), "sig").
						Return(nil),
				)
			},
			nil,
			"",
		},
		{
			"ShouldPassMethodPlainExplicit",
			&oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
				Request: oauth2.Request{
					Client:  &TestPKCEClient{EnforcePKCE: false, EnforcePKCEChallengeMethod: true, PKCEChallengeMethod: consts.PKCEChallengeMethodPlain, DefaultClient: &oauth2.DefaultClient{ID: "test", Public: true}},
					Session: &oauth2.DefaultSession{},
					Form: url.Values{
						consts.FormParameterAuthorizationCode: []string{"abc123.sig"},
						consts.FormParameterCodeVerifier:      []string{"abcabcabc9abcabcabc9abcabcabc9abcabcabc9abcabcabc9"},
					},
				},
			},
			nil,
			func(t *testing.T, config *oauth2.Config, store *mock.MockPKCERequestStorage) {
				config.EnablePKCEPlainChallengeMethod = true
				gomock.InOrder(
					store.
						EXPECT().
						GetPKCERequestSession(t.Context(), "sig", gomock.Any()).
						Return(&oauth2.Request{
							Client: &TestPKCEClient{EnforcePKCE: false, EnforcePKCEChallengeMethod: true, PKCEChallengeMethod: consts.PKCEChallengeMethodPlain, DefaultClient: &oauth2.DefaultClient{ID: "test", Public: true}},
							Form: url.Values{
								consts.FormParameterCodeChallenge:       []string{"abcabcabc9abcabcabc9abcabcabc9abcabcabc9abcabcabc9"},
								consts.FormParameterCodeChallengeMethod: []string{consts.PKCEChallengeMethodPlain},
							},
						}, nil),
					store.
						EXPECT().
						DeletePKCERequestSession(t.Context(), "sig").
						Return(nil),
				)
			},
			nil,
			"",
		},
		{
			"ShouldFailMethodPlainNoMatch",
			&oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
				Request: oauth2.Request{
					Client:  &TestPKCEClient{EnforcePKCE: false, EnforcePKCEChallengeMethod: true, PKCEChallengeMethod: consts.PKCEChallengeMethodPlain, DefaultClient: &oauth2.DefaultClient{ID: "test", Public: true}},
					Session: &oauth2.DefaultSession{},
					Form: url.Values{
						consts.FormParameterAuthorizationCode: []string{"abc123.sig"},
						consts.FormParameterCodeVerifier:      []string{"abcabcabc9abcabcabc9abcabcabc9abcabcabc9abcabcabc1"},
					},
				},
			},
			nil,
			func(t *testing.T, config *oauth2.Config, store *mock.MockPKCERequestStorage) {
				config.EnablePKCEPlainChallengeMethod = true
				gomock.InOrder(
					store.
						EXPECT().
						GetPKCERequestSession(t.Context(), "sig", gomock.Any()).
						Return(&oauth2.Request{
							Client: &TestPKCEClient{EnforcePKCE: false, EnforcePKCEChallengeMethod: true, PKCEChallengeMethod: consts.PKCEChallengeMethodPlain, DefaultClient: &oauth2.DefaultClient{ID: "test", Public: true}},
							Form: url.Values{
								consts.FormParameterCodeChallenge: []string{"abcabcabc9abcabcabc9abcabcabc9abcabcabc9abcabcabc9"},
							},
						}, nil),
					store.
						EXPECT().
						DeletePKCERequestSession(t.Context(), "sig").
						Return(nil),
				)
			},
			oauth2.ErrInvalidGrant,
			"The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. The PKCE code challenge did not match the code verifier.",
		},
		{
			"ShouldFailMethodS256NoMatch",
			&oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
				Request: oauth2.Request{
					Client:  &TestPKCEClient{EnforcePKCE: false, DefaultClient: &oauth2.DefaultClient{ID: "test", Public: true}},
					Session: &oauth2.DefaultSession{},
					Form: url.Values{
						consts.FormParameterAuthorizationCode: []string{"abc123.sig"},
						consts.FormParameterCodeVerifier:      []string{"abcabcabc9abcabcabc9abcabcabc9abcabcabc9abcabcabc1"},
					},
				},
			},
			nil,
			func(t *testing.T, config *oauth2.Config, store *mock.MockPKCERequestStorage) {
				config.EnablePKCEPlainChallengeMethod = true
				gomock.InOrder(
					store.
						EXPECT().
						GetPKCERequestSession(t.Context(), "sig", gomock.Any()).
						Return(&oauth2.Request{
							Client: &TestPKCEClient{EnforcePKCE: false, DefaultClient: &oauth2.DefaultClient{ID: "test", Public: true}},
							Form: url.Values{
								consts.FormParameterCodeChallenge:       []string{"abcabcabc9abcabcabc9abcabcabc9abcabcabc9abcabcabc9"},
								consts.FormParameterCodeChallengeMethod: []string{consts.PKCEChallengeMethodSHA256},
							},
						}, nil),
					store.
						EXPECT().
						DeletePKCERequestSession(t.Context(), "sig").
						Return(nil),
				)
			},
			oauth2.ErrInvalidGrant,
			"The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. The PKCE code challenge did not match the code verifier.",
		},
		{
			"ShouldPassS256Match",
			&oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
				Request: oauth2.Request{
					Client:  &TestPKCEClient{EnforcePKCE: false, DefaultClient: &oauth2.DefaultClient{ID: "test", Public: true}},
					Session: &oauth2.DefaultSession{},
					Form: url.Values{
						consts.FormParameterAuthorizationCode: []string{"abc123.sig"},
						consts.FormParameterCodeVerifier:      []string{"abcabcabc9abcabcabc9abcabcabc9abcabcabc9abcabcabc1"},
					},
				},
			},
			nil,
			func(t *testing.T, config *oauth2.Config, store *mock.MockPKCERequestStorage) {
				config.EnablePKCEPlainChallengeMethod = true
				gomock.InOrder(
					store.
						EXPECT().
						GetPKCERequestSession(t.Context(), "sig", gomock.Any()).
						Return(&oauth2.Request{
							Client: &TestPKCEClient{EnforcePKCE: false, DefaultClient: &oauth2.DefaultClient{ID: "test", Public: true}},
							Form: url.Values{
								consts.FormParameterCodeChallenge:       []string{"X_rhBVULlQ_7LU7Cv25I6ouGvJQLtum1M-Fjw0f24hI"},
								consts.FormParameterCodeChallengeMethod: []string{consts.PKCEChallengeMethodSHA256},
							},
						}, nil),
					store.
						EXPECT().
						DeletePKCERequestSession(t.Context(), "sig").
						Return(nil),
				)
			},
			nil,
			"",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)

			defer ctrl.Finish()

			store := mock.NewMockPKCERequestStorage(ctrl)

			config := &oauth2.Config{
				GlobalSecret: []byte("foofoofoofoofoofoofoofoofoofoofoo"),
			}

			if tc.setup != nil {
				tc.setup(t, config, store)
			}

			// Configure the provided strategy or the fallback.
			var strategy hoauth2.AuthorizeCodeStrategy

			if tc.strategy == nil {
				strategy = hoauth2.NewCoreStrategy(config, "authelia_%s_", nil)
			} else {
				strategy = tc.strategy
			}

			handler := &Handler{
				AuthorizeCodeStrategy: strategy,
				Storage:               store,
				Config:                config,
			}

			err := handler.HandleTokenEndpointRequest(t.Context(), tc.requester)

			if len(tc.expected) == 0 && tc.err == nil {
				assert.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
			} else {
				require.NotNil(t, err)
				assert.EqualError(t, err, tc.err.Error())
				assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.expected)
			}
		})
	}
}

func TestMiscellaneous(t *testing.T) {
	ctrl := gomock.NewController(t)

	defer ctrl.Finish()

	store := mock.NewMockPKCERequestStorage(ctrl)

	config := &oauth2.Config{
		GlobalSecret: []byte("foofoofoofoofoofoofoofoofoofoofoo"),
	}

	strategy := hoauth2.NewCoreStrategy(config, "authelia_%s_", nil)

	handler := &Handler{
		AuthorizeCodeStrategy: strategy,
		Storage:               store,
		Config:                config,
	}

	assert.False(t, handler.CanSkipClientAuth(t.Context(), oauth2.NewAccessRequest(&oauth2.DefaultSession{})))
	assert.NoError(t, handler.PopulateTokenEndpointResponse(t.Context(), oauth2.NewAccessRequest(&oauth2.DefaultSession{}), oauth2.NewAccessResponse()))
}

type TestPKCEClient struct {
	*oauth2.DefaultClient
	EnforcePKCE                bool
	EnforcePKCEChallengeMethod bool
	PKCEChallengeMethod        string
}

func (c *TestPKCEClient) GetEnforcePKCE() (enforce bool) {
	return c.EnforcePKCE
}

func (c *TestPKCEClient) GetEnforcePKCEChallengeMethod() (enforce bool) {
	return c.EnforcePKCEChallengeMethod
}

func (c *TestPKCEClient) GetPKCEChallengeMethod() (method string) {
	return c.PKCEChallengeMethod
}
