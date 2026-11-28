// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/x/errorsx"
)

func TestClientAuthenticationEndpointErrors(t *testing.T) {
	const challenge = `Basic realm=`

	testCases := []struct {
		name   string
		inject error
		basic  string
		post   bool
		status int
		field  string

		// challenged requires a 'WWW-Authenticate' challenge, and helper limits the case to the endpoints which classify
		// client authentication errors, as the token and revocation endpoints answer them as they are.
		challenged bool
		helper     bool
	}{
		// RFC 6749 Section 5.2.
		{name: "ShouldAnswerMoreThanOneMethodAsInvalidRequest", basic: clientAuthenticationEndpointErrorSecret, post: true, status: http.StatusBadRequest, field: "invalid_request"},
		{name: "ShouldChallengeAWrongSecretInTheAuthorizationHeader", basic: "wrong", status: http.StatusUnauthorized, field: "invalid_client", challenged: true},
		{name: "ShouldAnswerAnInvalidRequest", inject: errorsx.WithStack(ErrInvalidRequest), status: http.StatusBadRequest, field: "invalid_request"},
		{name: "ShouldAnswerAServerError", inject: errorsx.WithStack(ErrServerError), status: http.StatusInternalServerError, field: "server_error"},
		{name: "ShouldAnswerTemporarilyUnavailable", inject: errorsx.WithStack(ErrTemporarilyUnavailable), status: http.StatusServiceUnavailable, field: "temporarily_unavailable"},
		{name: "ShouldAnswerAPlainErrorAsAServerError", inject: errors.New("store failed"), status: http.StatusInternalServerError, field: "server_error", helper: true},
		{name: "ShouldAnswerAnotherErrorAsInvalidClient", inject: errorsx.WithStack(ErrInvalidGrant), status: http.StatusUnauthorized, field: "invalid_client", helper: true},
		{name: "ShouldChallengeAnotherErrorAsInvalidClientWithTheAuthorizationHeader", inject: errorsx.WithStack(ErrInvalidGrant), basic: clientAuthenticationEndpointErrorSecret, status: http.StatusUnauthorized, field: "invalid_client", challenged: true, helper: true},
		{name: "ShouldNotChallengeAServerErrorWithTheAuthorizationHeader", inject: errorsx.WithStack(ErrTemporarilyUnavailable), basic: clientAuthenticationEndpointErrorSecret, status: http.StatusServiceUnavailable, field: "temporarily_unavailable"},
	}

	endpoints := []struct {
		name   string
		helper bool
		do     func(t *testing.T, provider *Fosite, r *http.Request) *httptest.ResponseRecorder
	}{
		{name: "Token", do: clientAuthenticationEndpointErrorTestToken},
		{name: "Revocation", do: clientAuthenticationEndpointErrorTestRevocation},
		{name: "Introspection", helper: true, do: clientAuthenticationEndpointErrorTestIntrospection},
		{name: "PushedAuthorization", helper: true, do: clientAuthenticationEndpointErrorTestPAR},
		{name: "DeviceAuthorization", helper: true, do: clientAuthenticationEndpointErrorTestDevice},
		{name: "BackChannelAuthentication", helper: true, do: clientAuthenticationEndpointErrorTestCIBA},
	}

	for _, endpoint := range endpoints {
		t.Run(endpoint.name, func(t *testing.T) {
			for _, tc := range testCases {
				if tc.helper && !endpoint.helper {
					continue
				}

				t.Run(tc.name, func(t *testing.T) {
					store := storage.NewMemoryStore()

					store.Clients[clientAuthenticationEndpointErrorClientID] = &DefaultClient{
						ID:           clientAuthenticationEndpointErrorClientID,
						ClientSecret: NewPlainTextClientSecret(clientAuthenticationEndpointErrorSecret),
						GrantTypes:   []string{consts.GrantTypeClientCredentials},
					}

					config := &Config{
						GlobalSecret:          []byte("foofoofoofoofoofoofoofoofoofoofoo"),
						TokenEndpointHandlers: TokenEndpointHandlers{&clientAuthenticationEndpointErrorGrant{}},
					}

					if tc.inject != nil {
						config.ClientAuthenticationStrategy = &clientAuthenticationEndpointErrorStrategy{err: tc.inject}
					}

					form := url.Values{consts.FormParameterClientID: {clientAuthenticationEndpointErrorClientID}}

					if tc.post {
						form.Set(consts.FormParameterClientSecret, clientAuthenticationEndpointErrorSecret)
					}

					r := httptest.NewRequest(http.MethodPost, "https://as.example.com/endpoint", strings.NewReader(form.Encode()))
					r.Header.Set(consts.HeaderContentType, "application/x-www-form-urlencoded")

					if tc.basic != "" {
						r.SetBasicAuth(clientAuthenticationEndpointErrorClientID, tc.basic)
					}

					rw := endpoint.do(t, &Fosite{Store: store, Config: config}, r)

					assert.Equal(t, tc.status, rw.Code)
					assert.Contains(t, rw.Body.String(), `"error":"`+tc.field+`"`)

					if tc.challenged {
						assert.Contains(t, rw.Header().Get(consts.HeaderWWWAuthenticate), challenge)
					} else {
						assert.Empty(t, rw.Header().Get(consts.HeaderWWWAuthenticate))
					}
				})
			}
		})
	}
}

const (
	clientAuthenticationEndpointErrorClientID = "client"
	clientAuthenticationEndpointErrorSecret   = "foobarfoobarfoobarfoobar"
)

type clientAuthenticationEndpointErrorStrategy struct {
	err error
}

func (s *clientAuthenticationEndpointErrorStrategy) AuthMethodsSupported(_ context.Context) []string {
	return []string{consts.ClientAuthMethodClientSecretPost}
}

func (s *clientAuthenticationEndpointErrorStrategy) AuthenticateClient(_ context.Context, _ *http.Request, _ url.Values, _ EndpointClientAuthStrategy) (Client, string, error) {
	return nil, "", s.err
}

type clientAuthenticationEndpointErrorGrant struct {
	TokenEndpointHandler
}

func (h *clientAuthenticationEndpointErrorGrant) PopulateTokenEndpointResponse(_ context.Context, _ AccessRequester, _ AccessResponder) error {
	return nil
}

func (h *clientAuthenticationEndpointErrorGrant) HandleTokenEndpointRequest(_ context.Context, _ AccessRequester) error {
	return nil
}

func (h *clientAuthenticationEndpointErrorGrant) CanSkipClientAuth(_ context.Context, _ AccessRequester) bool {
	return false
}

func (h *clientAuthenticationEndpointErrorGrant) CanHandleTokenEndpointRequest(_ context.Context, request AccessRequester) bool {
	return request.GetGrantTypes().ExactOne(consts.GrantTypeClientCredentials)
}

func clientAuthenticationEndpointErrorTestToken(t *testing.T, provider *Fosite, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()

	clientAuthenticationEndpointErrorTestForm(t, r, url.Values{consts.FormParameterGrantType: {consts.GrantTypeClientCredentials}})

	rw := httptest.NewRecorder()

	request, err := provider.NewAccessRequest(context.Background(), r, &DefaultSession{})
	require.Error(t, err)

	provider.WriteAccessError(context.Background(), rw, request, err)

	return rw
}

func clientAuthenticationEndpointErrorTestRevocation(t *testing.T, provider *Fosite, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()

	clientAuthenticationEndpointErrorTestForm(t, r, url.Values{consts.FormParameterToken: {"token"}})

	rw := httptest.NewRecorder()

	err := provider.NewRevocationRequest(context.Background(), r)
	require.Error(t, err)

	provider.WriteRevocationResponse(context.Background(), rw, err)

	return rw
}

func clientAuthenticationEndpointErrorTestIntrospection(t *testing.T, provider *Fosite, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()

	clientAuthenticationEndpointErrorTestForm(t, r, url.Values{consts.FormParameterToken: {"token"}})

	rw := httptest.NewRecorder()

	_, err := provider.NewIntrospectionRequest(context.Background(), r, &DefaultSession{})
	require.Error(t, err)

	provider.WriteIntrospectionError(context.Background(), rw, r, err)

	return rw
}

func clientAuthenticationEndpointErrorTestPAR(t *testing.T, provider *Fosite, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()

	clientAuthenticationEndpointErrorTestForm(t, r, url.Values{consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow}, consts.FormParameterRedirectURI: {"https://client.example.com/cb"}})

	rw := httptest.NewRecorder()

	request, err := provider.NewPushedAuthorizeRequest(context.Background(), r)
	require.Error(t, err)

	provider.WritePushedAuthorizeError(context.Background(), rw, request, err)

	return rw
}

func clientAuthenticationEndpointErrorTestDevice(t *testing.T, provider *Fosite, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()

	rw := httptest.NewRecorder()

	_, err := provider.NewRFC862DeviceAuthorizeRequest(context.Background(), r)
	require.Error(t, err)

	// RFC 8628 Section 3.2: the device authorization endpoint responds to errors as the token endpoint does.
	provider.WriteAccessError(context.Background(), rw, NewAccessRequest(&DefaultSession{}), err)

	return rw
}

func clientAuthenticationEndpointErrorTestCIBA(t *testing.T, provider *Fosite, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()

	clientAuthenticationEndpointErrorTestForm(t, r, url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterLoginHint: {"peter"}})

	rw := httptest.NewRecorder()

	request, err := provider.NewBackChannelAuthenticationRequest(context.Background(), r, &DefaultSession{})
	require.Error(t, err)

	provider.WriteBackChannelAuthenticationError(context.Background(), rw, request, err)

	return rw
}

func clientAuthenticationEndpointErrorTestForm(t *testing.T, r *http.Request, extra url.Values) {
	t.Helper()

	require.NoError(t, r.ParseForm())

	form := r.PostForm

	for key, values := range extra {
		form[key] = values
	}

	body := form.Encode()

	r.Body = http.NoBody
	r.PostForm, r.Form = nil, nil
	r.Body = newClientAuthenticationEndpointErrorBody(body)
	r.ContentLength = int64(len(body))
}

func newClientAuthenticationEndpointErrorBody(body string) *clientAuthenticationEndpointErrorReader {
	return &clientAuthenticationEndpointErrorReader{Reader: strings.NewReader(body)}
}

type clientAuthenticationEndpointErrorReader struct {
	*strings.Reader
}

func (r *clientAuthenticationEndpointErrorReader) Close() error {
	return nil
}
