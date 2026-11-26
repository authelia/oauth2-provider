// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestOpenIDConnectDeviceAuthorizeSessionValidation(t *testing.T) {
	stale, fresh := time.Now().UTC().Add(-time.Hour), time.Now().UTC().Add(-time.Second)

	testCases := []struct {
		name    string
		client  sessionValidationTestClient
		form    url.Values
		hint    string
		refused *time.Time
		code    string
	}{
		{
			name:    "ShouldRefuseWithLoginRequiredWhenMaxAgeIsExceeded",
			form:    url.Values{consts.FormParameterMaximumAge: {"60"}},
			refused: &stale,
			code:    "login_required",
		},
		{
			name:    "ShouldRefuseWithLoginRequiredWhenDefaultMaxAgeIsExceeded",
			client:  sessionValidationTestClient{maxAge: 60, hasMaxAge: true},
			refused: &stale,
			code:    "login_required",
		},
		{
			name:   "ShouldRefuseWithServerErrorWhenRequireAuthTimeHasNoAuthTime",
			client: sessionValidationTestClient{requireAuthTime: true},
			code:   "server_error",
		},
		{
			name: "ShouldRefuseWithServerErrorWhenMaxAgeHasNoAuthTime",
			form: url.Values{consts.FormParameterMaximumAge: {"60"}},
			code: "server_error",
		},
		{
			name:    "ShouldRefuseWithLoginRequiredWhenPromptLoginWasNotFollowedByAnAuthentication",
			form:    url.Values{consts.FormParameterPrompt: {consts.PromptTypeLogin}},
			refused: &stale,
			code:    "login_required",
		},
		{
			name:    "ShouldRefuseWithLoginRequiredWhenTheIDTokenHintIsForAnotherSubject",
			hint:    "mallory",
			refused: &fresh,
			code:    "login_required",
		},
	}

	for _, st := range sessionValidationTestStores {
		t.Run(st.name, func(t *testing.T) {
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					store, memory := st.new()

					client := tc.client
					client.DefaultClient = newDeviceOrderTestClient().(*oauth2.DefaultClient)
					memory.Clients[deviceOrderTestClientID] = &client

					provider := newSessionValidationTestProvider(store, nil)

					form := url.Values{}

					for key, values := range tc.form {
						form[key] = values
					}

					if tc.hint != "" {
						form.Set(consts.FormParameterIDTokenHint, newSessionValidationTestDeviceIDToken(t, provider, tc.hint))
					}

					grant := newSessionValidationTestDeviceGrant(t, provider, form)

					err := grant.approve(t, provider, deviceOrderTestSubject, tc.refused)

					assert.Equal(t, tc.code, deviceOrderTestErrorCode(err))
					assert.Empty(t, memory.IDSessions)

					_, err = grant.poll(t, provider)

					assert.Equal(t, "authorization_pending", deviceOrderTestErrorCode(err))

					if tc.hint != "" {
						return
					}

					now := time.Now().UTC()

					require.NoError(t, grant.approve(t, provider, deviceOrderTestSubject, &now))

					response, err := grant.poll(t, provider)

					require.NoError(t, err)
					assert.NotEmpty(t, response.GetAccessToken())
					assert.NotEmpty(t, response.GetExtra(consts.AccessResponseIDToken))
				})
			}

			t.Run("ShouldIssueAnIDTokenWhenTheAuthenticationMeetsTheRequest", func(t *testing.T) {
				store, memory := st.new()

				memory.Clients[deviceOrderTestClientID] = &sessionValidationTestClient{
					DefaultClient:   newDeviceOrderTestClient().(*oauth2.DefaultClient),
					maxAge:          600,
					hasMaxAge:       true,
					requireAuthTime: true,
				}

				provider := newSessionValidationTestProvider(store, nil)

				grant := newSessionValidationTestDeviceGrant(t, provider, url.Values{
					consts.FormParameterMaximumAge:  {"300"},
					consts.FormParameterIDTokenHint: {newSessionValidationTestDeviceIDToken(t, provider, deviceOrderTestSubject)},
					consts.FormParameterNonce:       {deviceOrderTestNonce},
				})

				require.NoError(t, grant.approve(t, provider, deviceOrderTestSubject, &fresh))

				response, err := grant.poll(t, provider)

				require.NoError(t, err)
				assert.NotEmpty(t, response.GetExtra(consts.AccessResponseIDToken))
			})
		})
	}
}

func TestOpenIDConnectDeviceAuthorizeRequestValidation(t *testing.T) {
	testCases := []struct {
		name string
		form url.Values
		code string
	}{
		{
			name: "ShouldRejectAMalformedMaxAge",
			form: url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterMaximumAge: {"abc"}},
			code: "invalid_request",
		},
		{
			name: "ShouldRejectANegativeMaxAge",
			form: url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterMaximumAge: {"-1"}},
			code: "invalid_request",
		},
		{
			name: "ShouldRejectAnUnknownPrompt",
			form: url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterPrompt: {"unknown"}},
			code: "invalid_request",
		},
		{
			name: "ShouldRejectPromptNoneWithAnotherValue",
			form: url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterPrompt: {"none login"}},
			code: "invalid_request",
		},
		{
			name: "ShouldRejectAnIDTokenHintWhichIsNotAnIDToken",
			form: url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterIDTokenHint: {"abc"}},
			code: "invalid_request",
		},
		{
			name: "ShouldAcceptAMalformedMaxAgeWithoutTheOpenIDScope",
			form: url.Values{consts.FormParameterMaximumAge: {"abc"}},
		},
		{
			name: "ShouldAcceptAValidMaxAgeAndPrompt",
			form: url.Values{consts.FormParameterScope: {consts.ScopeOpenID}, consts.FormParameterMaximumAge: {"0"}, consts.FormParameterPrompt: {"login consent"}},
		},
	}

	for _, st := range sessionValidationTestStores {
		t.Run(st.name, func(t *testing.T) {
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					store, memory := st.new()

					memory.Clients[deviceOrderTestClientID] = newDeviceOrderTestClient()

					provider := newSessionValidationTestProvider(store, nil)

					form := url.Values{consts.FormParameterClientID: {deviceOrderTestClientID}}

					for key, values := range tc.form {
						form[key] = values
					}

					_, err := provider.NewRFC862DeviceAuthorizeRequest(context.Background(), newDeviceOrderTestRequest(form))

					assert.Equal(t, tc.code, deviceOrderTestErrorCode(err))
					assert.Empty(t, memory.DeviceCodes)
				})
			}
		})
	}
}

func TestOpenIDConnectCIBASessionValidation(t *testing.T) {
	stale, missing := time.Now().UTC().Add(-time.Hour), time.Time{}

	testCases := []struct {
		name    string
		client  sessionValidationTestClient
		refused time.Time
		code    string
	}{
		{
			name:    "ShouldRefuseWithLoginRequiredWhenDefaultMaxAgeIsExceeded",
			client:  sessionValidationTestClient{maxAge: 60, hasMaxAge: true},
			refused: stale,
			code:    "login_required",
		},
		{
			name:    "ShouldRefuseWithServerErrorWhenRequireAuthTimeHasNoAuthTime",
			client:  sessionValidationTestClient{requireAuthTime: true},
			refused: missing,
			code:    "server_error",
		},
	}

	for _, st := range sessionValidationTestStores {
		t.Run(st.name, func(t *testing.T) {
			for _, mode := range []string{consts.CIBAModePoll, consts.CIBAModePush} {
				t.Run(mode, func(t *testing.T) {
					for _, tc := range testCases {
						t.Run(tc.name, func(t *testing.T) {
							store, memory := st.new()

							client := tc.client
							memory.Clients[sessionValidationTestCIBAClientID] = newSessionValidationTestCIBAClient(mode, &client)

							notifier := &sessionValidationTestNotifier{}
							provider := newSessionValidationTestProvider(store, notifier)

							flow := newSessionValidationTestCIBAFlow(t, provider, mode)

							result, err := flow.approve(t, provider, tc.refused)

							assert.Nil(t, result)
							assert.Equal(t, tc.code, deviceOrderTestErrorCode(err))
							assert.Empty(t, memory.IDSessions)
							assert.Empty(t, notifier.notifications)

							result, err = flow.approve(t, provider, time.Now().UTC())

							require.NoError(t, err)
							assert.Equal(t, oauth2.CIBAStatusApproved, result.Status)

							flow.requireIDToken(t, provider, notifier)
						})
					}

					t.Run("ShouldIssueAnIDTokenWhenTheAuthenticationMeetsTheClientRegistration", func(t *testing.T) {
						store, memory := st.new()

						memory.Clients[sessionValidationTestCIBAClientID] = newSessionValidationTestCIBAClient(mode, &sessionValidationTestClient{maxAge: 60, hasMaxAge: true, requireAuthTime: true})

						notifier := &sessionValidationTestNotifier{}
						provider := newSessionValidationTestProvider(store, notifier)

						flow := newSessionValidationTestCIBAFlow(t, provider, mode)

						result, err := flow.approve(t, provider, time.Now().UTC())

						require.NoError(t, err)
						assert.Equal(t, oauth2.CIBAStatusApproved, result.Status)

						flow.requireIDToken(t, provider, notifier)
					})
				})
			}
		})
	}
}

const (
	sessionValidationTestCIBAClientID = "ciba"
	sessionValidationTestCIBASecret   = "foobar"
)

var sessionValidationTestStores = []struct {
	name string
	new  func() (store any, memory *storage.MemoryStore)
}{
	{
		name: "MemoryStore",
		new: func() (any, *storage.MemoryStore) {
			store := storage.NewMemoryStore()

			return store, store
		},
	},
	{
		name: "HydratingMemoryStore",
		new: func() (any, *storage.MemoryStore) {
			store := storage.NewHydratingMemoryStore()

			return store, store.MemoryStore
		},
	},
}

type sessionValidationTestClient struct {
	*oauth2.DefaultClient

	maxAge          int64
	hasMaxAge       bool
	requireAuthTime bool
}

func (c *sessionValidationTestClient) GetDefaultMaxAge() (maxAge int64, ok bool) {
	return c.maxAge, c.hasMaxAge
}

func (c *sessionValidationTestClient) GetRequireAuthTime() (require bool) {
	return c.requireAuthTime
}

type sessionValidationTestCIBAClient struct {
	*oauth2.DefaultCIBAClient

	registration *sessionValidationTestClient
}

func (c *sessionValidationTestCIBAClient) GetDefaultMaxAge() (maxAge int64, ok bool) {
	return c.registration.GetDefaultMaxAge()
}

func (c *sessionValidationTestCIBAClient) GetRequireAuthTime() (require bool) {
	return c.registration.GetRequireAuthTime()
}

type sessionValidationTestNotifier struct {
	mu            sync.Mutex
	notifications []*oauth2.BackChannelNotification
}

func (n *sessionValidationTestNotifier) NotifyBackChannelClient(_ context.Context, notification *oauth2.BackChannelNotification) (err error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.notifications = append(n.notifications, notification)

	return nil
}

type sessionValidationTestDeviceGrant struct {
	deviceCode, userCode string
}

type sessionValidationTestCIBAFlow struct {
	mode, requestID, authReqID string
}

func newSessionValidationTestProvider(store any, notifier oauth2.BackChannelNotifier) (provider oauth2.Provider) {
	config := &oauth2.Config{
		GlobalSecret:                          []byte("some-cool-secret-that-is-32bytes"),
		RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b"),
		Issuer:                                "https://www.authelia.com",
		RFC8628UserVerificationURL:            "https://www.authelia.com/device",
		RFC8628TokenPollingInterval:           time.Nanosecond,
		CIBAPollingInterval:                   time.Nanosecond,
	}

	if notifier != nil {
		config.BackChannelNotifier = notifier
	}

	strategy := &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(gen.MustRSAKey())}

	factories := append([]Factory{
		RFC8628DeviceAuthorizeFactory,
		RFC8628DeviceAuthorizeTokenFactory,
		OpenIDConnectDeviceAuthorizeFactory,
		RFC8628UserAuthorizeFactory,
	}, CIBAFactories()...)

	return Compose(
		config,
		store,
		&CommonStrategy{
			CoreStrategy:               NewOAuth2HMACStrategy(config),
			OpenIDConnectTokenStrategy: NewOpenIDConnectStrategy(nil, strategy, config),
			Strategy:                   strategy,
		},
		factories...,
	)
}

func newSessionValidationTestSession(subject string, authTime *time.Time) (session *openid.DefaultSession) {
	session = openid.NewDefaultSession()

	session.Subject, session.Claims.Subject = subject, subject

	if authTime != nil && !authTime.IsZero() {
		session.Claims.AuthTime = jwt.NewNumericDate(*authTime)
	}

	return session
}

func newSessionValidationTestDeviceGrant(t *testing.T, provider oauth2.Provider, parameters url.Values) (grant sessionValidationTestDeviceGrant) {
	t.Helper()

	form := url.Values{consts.FormParameterClientID: {deviceOrderTestClientID}, consts.FormParameterScope: {consts.ScopeOpenID}}

	for key, values := range parameters {
		form[key] = values
	}

	ctx := context.Background()

	request, err := provider.NewRFC862DeviceAuthorizeRequest(ctx, newDeviceOrderTestRequest(form))

	require.NoError(t, err)

	response, err := provider.NewRFC862DeviceAuthorizeResponse(ctx, request, newSessionValidationTestSession("", nil))

	require.NoError(t, err)

	return sessionValidationTestDeviceGrant{deviceCode: response.GetDeviceCode(), userCode: response.GetUserCode()}
}

func newSessionValidationTestDeviceIDToken(t *testing.T, provider oauth2.Provider, subject string) (token string) {
	t.Helper()

	grant := newSessionValidationTestDeviceGrant(t, provider, nil)

	now := time.Now().UTC()

	require.NoError(t, grant.approve(t, provider, subject, &now))

	response, err := grant.poll(t, provider)

	require.NoError(t, err)

	token, _ = response.GetExtra(consts.AccessResponseIDToken).(string)

	require.NotEmpty(t, token)

	return token
}

func (g sessionValidationTestDeviceGrant) approve(t *testing.T, provider oauth2.Provider, subject string, authTime *time.Time) (err error) {
	t.Helper()

	ctx := context.Background()

	request, err := provider.NewRFC8628UserAuthorizeRequest(ctx, newDeviceOrderTestRequest(url.Values{consts.FormParameterUserCode: {g.userCode}}), newSessionValidationTestSession(subject, nil))

	require.NoError(t, err)

	for _, scope := range request.GetRequestedScopes() {
		request.GrantScope(scope)
	}

	request.SetStatus(oauth2.DeviceAuthorizeStatusApproved)

	_, err = provider.NewRFC8628UserAuthorizeResponse(ctx, request, newSessionValidationTestSession(subject, authTime))

	return err
}

func (g sessionValidationTestDeviceGrant) poll(t *testing.T, provider oauth2.Provider) (response oauth2.AccessResponder, err error) {
	t.Helper()

	ctx := context.Background()

	form := url.Values{
		consts.FormParameterClientID:   {deviceOrderTestClientID},
		consts.FormParameterGrantType:  {consts.GrantTypeOAuthDeviceCode},
		consts.FormParameterDeviceCode: {g.deviceCode},
	}

	request, err := provider.NewAccessRequest(ctx, newDeviceOrderTestRequest(form), newSessionValidationTestSession("", nil))
	if err != nil {
		return nil, err
	}

	return provider.NewAccessResponse(ctx, request)
}

func newSessionValidationTestCIBAClient(mode string, registration *sessionValidationTestClient) (client oauth2.Client) {
	base := &oauth2.DefaultCIBAClient{
		BackChannelTokenDeliveryMode: mode,
		DefaultClient: &oauth2.DefaultClient{
			ID:           sessionValidationTestCIBAClientID,
			ClientSecret: oauth2.NewPlainTextClientSecret(sessionValidationTestCIBASecret),
			Scopes:       []string{consts.ScopeOpenID},
		},
	}

	if mode == consts.CIBAModePush {
		base.BackChannelClientNotificationEndpoint = "https://client.example.com/notify"
	} else {
		base.GrantTypes = []string{consts.GrantTypeOpenIDCIBA}
	}

	return &sessionValidationTestCIBAClient{DefaultCIBAClient: base, registration: registration}
}

func newSessionValidationTestCIBARequest(form url.Values) (r *http.Request) {
	r = httptest.NewRequest(http.MethodPost, "https://www.authelia.com/", strings.NewReader(form.Encode()))

	r.Header.Set(consts.HeaderContentType, consts.ContentTypeApplicationURLEncodedForm)
	r.SetBasicAuth(sessionValidationTestCIBAClientID, sessionValidationTestCIBASecret)

	return r
}

func newSessionValidationTestCIBAFlow(t *testing.T, provider oauth2.Provider, mode string) (flow sessionValidationTestCIBAFlow) {
	t.Helper()

	ctx := context.Background()

	form := url.Values{
		consts.FormParameterScope:          {consts.ScopeOpenID},
		consts.FormParameterLoginHint:      {deviceOrderTestSubject},
		consts.FormParameterBindingMessage: {"W4SCT"},
	}

	if mode == consts.CIBAModePush {
		form.Set(consts.FormParameterClientNotificationToken, "token")
	}

	session := openid.NewDefaultSession()

	request, err := provider.NewBackChannelAuthenticationRequest(ctx, newSessionValidationTestCIBARequest(form), session)

	require.NoError(t, err)

	session.Subject, session.Claims.Subject = deviceOrderTestSubject, deviceOrderTestSubject

	request.(*oauth2.BackChannelAuthenticationRequest).RequestedAt = request.GetRequestedAt().Add(-time.Minute)

	response, err := provider.NewBackChannelAuthenticationResponse(ctx, request)

	require.NoError(t, err)

	return sessionValidationTestCIBAFlow{mode: mode, requestID: request.GetID(), authReqID: response.GetAuthRequestID()}
}

func (f sessionValidationTestCIBAFlow) approve(t *testing.T, provider oauth2.Provider, authTime time.Time) (result *oauth2.BackChannelAuthenticationDecisionResult, err error) {
	t.Helper()

	ctx := context.Background()

	decision, err := provider.NewBackChannelAuthenticationDecisionRequest(ctx, f.requestID, openid.NewDefaultSession())

	require.NoError(t, err)

	decision.GrantScope(consts.ScopeOpenID)

	return provider.ApproveBackChannelAuthentication(ctx, decision, newSessionValidationTestSession(deviceOrderTestSubject, &authTime))
}

func (f sessionValidationTestCIBAFlow) requireIDToken(t *testing.T, provider oauth2.Provider, notifier *sessionValidationTestNotifier) {
	t.Helper()

	if f.mode == consts.CIBAModePush {
		require.Len(t, notifier.notifications, 1)
		assert.Contains(t, string(notifier.notifications[0].Body), `"id_token"`)

		return
	}

	ctx := context.Background()

	form := url.Values{
		consts.FormParameterGrantType: {consts.GrantTypeOpenIDCIBA},
		consts.FormParameterAuthReqID: {f.authReqID},
	}

	request, err := provider.NewAccessRequest(ctx, newSessionValidationTestCIBARequest(form), openid.NewDefaultSession())

	require.NoError(t, err)

	response, err := provider.NewAccessResponse(ctx, request)

	require.NoError(t, err)
	assert.NotEmpty(t, response.GetAccessToken())
	assert.NotEmpty(t, response.GetExtra(consts.AccessResponseIDToken))
}
