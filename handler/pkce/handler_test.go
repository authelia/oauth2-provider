// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package pkce

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
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
			"ShouldFailMethodWithoutChallenge",
			&oauth2.AuthorizeRequest{
				ResponseTypes: oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow},
				Request: oauth2.Request{
					Client: &TestPKCEClient{EnforcePKCE: false, DefaultClient: &oauth2.DefaultClient{ID: "test"}},
					Form:   url.Values{consts.FormParameterCodeChallengeMethod: []string{consts.PKCEChallengeMethodSHA256}},
				},
			},
			nil,
			nil,
			oauth2.ErrInvalidRequest,
			"The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Make sure that the various parameters are correct, be aware of case sensitivity and trim your parameters. Make sure that the client you are using has exactly whitelisted the redirect_uri you specified. The client requested PKCE but no challenge was provided in the authorize request.",
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
						consts.FormParameterAuthorizationCode: []string{"authelia_ac_abc123.sig"},
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
						consts.FormParameterAuthorizationCode: []string{"authelia_ac_abc123.sig"},
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
						consts.FormParameterAuthorizationCode: []string{"authelia_ac_abc123.sig"},
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
						consts.FormParameterAuthorizationCode: []string{"authelia_ac_abc123.sig"},
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
			"ShouldFailMissingOriginalCodeChallenge",
			&oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
				Request: oauth2.Request{
					Client:  &TestPKCEClient{DefaultClient: &oauth2.DefaultClient{ID: "test"}},
					Session: &oauth2.DefaultSession{},
					Form: url.Values{
						consts.FormParameterAuthorizationCode: []string{"authelia_ac_abc123.sig"},
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
						consts.FormParameterAuthorizationCode: []string{"authelia_ac_abc123.sig"},
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
						consts.FormParameterAuthorizationCode: []string{"authelia_ac_abc123.sig"},
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
						consts.FormParameterAuthorizationCode: []string{"authelia_ac_abc123.sig"},
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
						consts.FormParameterAuthorizationCode: []string{"authelia_ac_abc123.sig"},
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
						consts.FormParameterAuthorizationCode: []string{"authelia_ac_abc123.sig"},
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
						consts.FormParameterAuthorizationCode: []string{"authelia_ac_abc123.sig"},
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
						consts.FormParameterAuthorizationCode: []string{"authelia_ac_abc123.sig"},
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
						consts.FormParameterAuthorizationCode: []string{"authelia_ac_abc123.sig"},
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
						consts.FormParameterAuthorizationCode: []string{"authelia_ac_abc123.sig"},
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
						consts.FormParameterAuthorizationCode: []string{"authelia_ac_abc123.sig"},
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
						consts.FormParameterAuthorizationCode: []string{"authelia_ac_abc123.sig"},
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
						consts.FormParameterAuthorizationCode: []string{"authelia_ac_abc123.sig"},
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
						consts.FormParameterAuthorizationCode: []string{"authelia_ac_abc123.sig"},
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
				)
			},
			oauth2.ErrInvalidRequest,
			"The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Authorization was requested with 'code_challenge_method' value 'plain', but the authorization server policy does not allow method 'plain' and requires method 'S256'. The authorization server is configured in a way that enforces the 'S256' PKCE 'code_challenge_method' for all clients.",
		},
		{
			"ShouldFailMethodNoneExplicit",
			&oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
				Request: oauth2.Request{
					Client:  &TestPKCEClient{EnforcePKCE: false, DefaultClient: &oauth2.DefaultClient{ID: "test", Public: true}},
					Session: &oauth2.DefaultSession{},
					Form: url.Values{
						consts.FormParameterAuthorizationCode: []string{"authelia_ac_abc123.sig"},
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
						consts.FormParameterAuthorizationCode: []string{"authelia_ac_abc123.sig"},
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
				)
			},
			oauth2.ErrInvalidRequest,
			"The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Authorization was requested with 'code_challenge_method' value 'S256', but the authorization server policy does not allow method 'S256' and requires method 'plain'. The registered client with id 'test' is configured in a way that enforces the use of 'code_challenge_method' with a value of 'plain' but the authorization request included method 'S256'.",
		},
		{
			"ShouldFailMethodS256ClientRequiresNone",
			&oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
				Request: oauth2.Request{
					Client:  &TestPKCEClient{EnforcePKCE: false, EnforcePKCEChallengeMethod: false, PKCEChallengeMethod: consts.PKCEChallengeMethodPlain, DefaultClient: &oauth2.DefaultClient{ID: "test", Public: true}},
					Session: &oauth2.DefaultSession{},
					Form: url.Values{
						consts.FormParameterAuthorizationCode: []string{"authelia_ac_abc123.sig"},
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
						consts.FormParameterAuthorizationCode: []string{"authelia_ac_abc123.sig"},
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
						consts.FormParameterAuthorizationCode: []string{"authelia_ac_abc123.sig"},
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
						consts.FormParameterAuthorizationCode: []string{"authelia_ac_abc123.sig"},
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
						consts.FormParameterAuthorizationCode: []string{"authelia_ac_abc123.sig"},
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
						consts.FormParameterAuthorizationCode: []string{"authelia_ac_abc123.sig"},
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
	assert.ErrorIs(t, handler.PopulateTokenEndpointResponse(t.Context(), oauth2.NewAccessRequest(&oauth2.DefaultSession{}), oauth2.NewAccessResponse()), oauth2.ErrUnknownRequest)
}

func TestHandler_PopulateTokenEndpointResponse(t *testing.T) {
	testCases := []struct {
		name     string
		setup    func(t *testing.T, store *mock.MockPKCERequestStorage)
		expected string
	}{
		{
			"ShouldDeletePKCERequestSession",
			func(t *testing.T, store *mock.MockPKCERequestStorage) {
				store.EXPECT().DeletePKCERequestSession(t.Context(), "sig").Return(nil)
			},
			"",
		},
		{
			"ShouldPassPKCERequestSessionNotFound",
			func(t *testing.T, store *mock.MockPKCERequestStorage) {
				store.EXPECT().DeletePKCERequestSession(t.Context(), "sig").Return(oauth2.ErrNotFound)
			},
			"",
		},
		{
			"ShouldFailStorageDeleteError",
			func(t *testing.T, store *mock.MockPKCERequestStorage) {
				store.EXPECT().DeletePKCERequestSession(t.Context(), "sig").Return(errors.New("bad connection"))
			},
			"The authorization server encountered an unexpected condition that prevented it from fulfilling the request. Error occurred attempting delete PKCE request session: bad connection.",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			store := mock.NewMockPKCERequestStorage(ctrl)
			config := &oauth2.Config{GlobalSecret: []byte("foofoofoofoofoofoofoofoofoofoofoo")}

			tc.setup(t, store)

			handler := &Handler{
				AuthorizeCodeStrategy: hoauth2.NewCoreStrategy(config, "authelia_%s_", nil),
				Storage:               store,
				Config:                config,
			}

			requester := &oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
				Request: oauth2.Request{
					Form: url.Values{consts.FormParameterAuthorizationCode: []string{"authelia_ac_abc123.sig"}},
				},
			}

			err := handler.PopulateTokenEndpointResponse(t.Context(), requester, oauth2.NewAccessResponse())

			if tc.expected == "" {
				assert.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
			} else {
				assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.expected)
			}
		})
	}
}

func TestPKCERequestSessionSurvivesAFailedTokenRequest(t *testing.T) {
	config := &oauth2.Config{
		GlobalSecret:          []byte("foobarfoobarfoobarfoobarfoobarfoobarfoobarfoobar"),
		AccessTokenLifespan:   time.Hour,
		AuthorizeCodeLifespan: time.Minute,
		ScopeStrategy:         oauth2.HierarchicScopeStrategy,
		AudienceStrategy:      oauth2.DefaultAudienceStrategy,
	}

	store := storage.NewMemoryStore()
	client := &oauth2.DefaultClient{ID: "app", Public: true, GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode}}
	store.Clients[client.ID] = client

	strategy := hoauth2.NewHMACCoreStrategy(config, "authelia_%s_")

	config.TokenEndpointHandlers = oauth2.TokenEndpointHandlers{
		&hoauth2.AuthorizeExplicitGrantHandler{
			CoreStorage:            store,
			TokenRevocationStorage: store,
			AuthorizeCodeStrategy:  strategy,
			AccessTokenStrategy:    strategy,
			RefreshTokenStrategy:   strategy,
			Config:                 config,
		},
		&Handler{AuthorizeCodeStrategy: strategy, Storage: store, Config: config},
	}
	config.TokenEndpointBindingHandlers = oauth2.TokenEndpointBindingHandlers{&failOnceBindingHandler{}}

	provider := oauth2.New(store, config)

	verifier := strings.Repeat("a", 50)
	sum := sha256.Sum256([]byte(verifier))

	code, signature, err := strategy.GenerateAuthorizeCode(t.Context(), nil)
	require.NoError(t, err)

	authorizeRequest := &oauth2.AuthorizeRequest{
		Request: oauth2.Request{
			ID:     "req-id",
			Client: client,
			Form: url.Values{
				consts.FormParameterCodeChallenge:       {base64.RawURLEncoding.EncodeToString(sum[:])},
				consts.FormParameterCodeChallengeMethod: {consts.PKCEChallengeMethodSHA256},
			},
			Session:     &oauth2.DefaultSession{},
			RequestedAt: time.Now().UTC(),
		},
	}

	require.NoError(t, store.CreateAuthorizeCodeSession(t.Context(), signature, authorizeRequest))
	require.NoError(t, store.CreatePKCERequestSession(t.Context(), signature, authorizeRequest))

	post := func(verifier string) (oauth2.AccessRequester, error) {
		form := url.Values{
			consts.FormParameterGrantType:         {consts.GrantTypeAuthorizationCode},
			consts.FormParameterAuthorizationCode: {code},
			consts.FormParameterClientID:          {client.ID},
		}

		if verifier != "" {
			form.Set(consts.FormParameterCodeVerifier, verifier)
		}

		r := httptest.NewRequest(http.MethodPost, "https://auth.example.com/token", strings.NewReader(form.Encode()))
		r.Header.Set(consts.HeaderContentType, consts.ContentTypeApplicationURLEncodedForm)

		return provider.NewAccessRequest(t.Context(), r, &oauth2.DefaultSession{})
	}

	// RFC 9449 Section 8 asks the client to retry with a nonce after the binding phase rejects the first request.
	_, err = post(verifier)
	require.ErrorIs(t, err, oauth2.ErrUseDPoPNonce)

	_, err = post("")
	require.ErrorIs(t, err, oauth2.ErrInvalidGrant)

	requester, err := post(verifier)
	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

	response, err := provider.NewAccessResponse(t.Context(), requester)
	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
	assert.NotEmpty(t, response.GetAccessToken())

	_, err = store.GetPKCERequestSession(t.Context(), signature, nil)
	assert.ErrorIs(t, err, oauth2.ErrNotFound)
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

type failOnceBindingHandler struct {
	failed bool
}

func (h *failOnceBindingHandler) BindAccessRequest(_ context.Context, _ oauth2.AccessRequester) error {
	if !h.failed {
		h.failed = true

		return oauth2.ErrUseDPoPNonce
	}

	return nil
}

func (h *failOnceBindingHandler) PopulateBoundTokenEndpointResponse(_ context.Context, _ oauth2.AccessRequester, _ oauth2.AccessResponder) error {
	return nil
}
