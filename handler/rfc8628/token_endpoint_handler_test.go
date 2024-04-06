package rfc8628_test

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	. "authelia.com/provider/oauth2/handler/rfc8628"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/testing/mock"
	"authelia.com/provider/oauth2/token/hmac"
)

var o2hmacshaStrategy = hoauth2.HMACCoreStrategy{
	Enigma: &hmac.HMACStrategy{Config: &oauth2.Config{GlobalSecret: []byte("foobarfoobarfoobarfoobarfoobarfoobarfoobarfoobar")}},
	Config: &oauth2.Config{
		AccessTokenLifespan:   time.Hour * 24,
		AuthorizeCodeLifespan: time.Hour * 24,
	},
}

func TestDeviceAuthorizeCode_PopulateTokenEndpointResponse(t *testing.T) {
	for k, strategy := range map[string]struct {
		hoauth2.CoreStrategy
	}{
		"hmac": {&o2hmacshaStrategy},
	} {
		t.Run("strategy="+k, func(t *testing.T) {
			store := storage.NewMemoryStore()

			var h hoauth2.GenericCodeTokenEndpointHandler
			for _, c := range []struct {
				areq        *oauth2.AccessRequest
				description string
				setup       func(t *testing.T, areq *oauth2.AccessRequest, config *oauth2.Config)
				check       func(t *testing.T, aresp *oauth2.AccessResponse)
				expectErr   error
			}{
				{
					areq: &oauth2.AccessRequest{
						GrantTypes: oauth2.Arguments{"123"},
					},
					description: "should fail because not responsible",
					expectErr:   oauth2.ErrUnknownRequest,
				},
				{
					areq: &oauth2.AccessRequest{
						GrantTypes: oauth2.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
						Request: oauth2.Request{
							Form: url.Values{},
							Client: &oauth2.DefaultClient{
								GrantTypes: oauth2.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
							},
							Session:     &oauth2.DefaultSession{},
							RequestedAt: time.Now().UTC(),
						},
					},
					description: "should fail because device code not found",
					setup: func(t *testing.T, areq *oauth2.AccessRequest, config *oauth2.Config) {
						code, _, err := strategy.GenerateRFC8628DeviceCode(context.TODO())
						require.NoError(t, err)
						areq.Form.Set("device_code", code)
					},
					expectErr: oauth2.ErrServerError,
				},
				{
					areq: &oauth2.AccessRequest{
						GrantTypes: oauth2.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
						Request: oauth2.Request{
							Form: url.Values{},
							Client: &oauth2.DefaultClient{
								GrantTypes: oauth2.Arguments{"urn:ietf:params:oauth:grant-type:device_code", "refresh_token"},
							},
							GrantedScope: oauth2.Arguments{"foo", "offline"},
							Session:      &oauth2.DefaultSession{},
							RequestedAt:  time.Now().UTC(),
						},
					},
					setup: func(t *testing.T, areq *oauth2.AccessRequest, config *oauth2.Config) {
						dar := oauth2.NewDeviceAuthorizeRequest()
						dar.Merge(areq)
						dCode, dSig, err := strategy.GenerateRFC8628DeviceCode(context.TODO())
						require.NoError(t, err)
						_, uSig, err := strategy.GenerateRFC8628UserCode(context.TODO())
						require.NoError(t, err)
						dar.SetDeviceCodeSignature(dSig)
						dar.SetUserCodeSignature(uSig)

						require.NoError(t, store.CreateDeviceCodeSession(context.TODO(), dSig, dar))
						dar.SetStatus(oauth2.DeviceAuthorizeStatusApproved)
						require.NoError(t, store.CreateDeviceUserCodeSession(context.TODO(), uSig, dar))

						areq.Form.Add("device_code", dCode)
					},
					description: "should pass with offline scope and refresh token",
					check: func(t *testing.T, aresp *oauth2.AccessResponse) {
						assert.NotEmpty(t, aresp.AccessToken)
						assert.Equal(t, "bearer", aresp.TokenType)
						assert.NotEmpty(t, aresp.GetExtra("refresh_token"))
						assert.NotEmpty(t, aresp.GetExtra("expires_in"))
						assert.Equal(t, "foo offline", aresp.GetExtra("scope"))
					},
				},
				{
					areq: &oauth2.AccessRequest{
						GrantTypes: oauth2.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
						Request: oauth2.Request{
							Form: url.Values{},
							Client: &oauth2.DefaultClient{
								GrantTypes: oauth2.Arguments{"urn:ietf:params:oauth:grant-type:device_code", "refresh_token"},
							},
							GrantedScope: oauth2.Arguments{"foo"},
							Session:      &oauth2.DefaultSession{},
							RequestedAt:  time.Now().UTC(),
						},
					},
					setup: func(t *testing.T, areq *oauth2.AccessRequest, config *oauth2.Config) {
						config.RefreshTokenScopes = []string{}

						dar := oauth2.NewDeviceAuthorizeRequest()
						dar.Merge(areq)
						dCode, dSig, err := strategy.GenerateRFC8628DeviceCode(context.TODO())
						require.NoError(t, err)
						_, uSig, err := strategy.GenerateRFC8628UserCode(context.TODO())
						require.NoError(t, err)
						dar.SetDeviceCodeSignature(dSig)
						dar.SetUserCodeSignature(uSig)

						require.NoError(t, store.CreateDeviceCodeSession(context.TODO(), dSig, dar))
						dar.SetStatus(oauth2.DeviceAuthorizeStatusApproved)
						require.NoError(t, store.CreateDeviceUserCodeSession(context.TODO(), uSig, dar))

						areq.Form.Add("device_code", dCode)
					},
					description: "should pass with refresh token always provided",
					check: func(t *testing.T, aresp *oauth2.AccessResponse) {
						assert.NotEmpty(t, aresp.AccessToken)
						assert.Equal(t, "bearer", aresp.TokenType)
						assert.NotEmpty(t, aresp.GetExtra("refresh_token"))
						assert.NotEmpty(t, aresp.GetExtra("expires_in"))
						assert.Equal(t, "foo", aresp.GetExtra("scope"))
					},
				},
				{
					areq: &oauth2.AccessRequest{
						GrantTypes: oauth2.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
						Request: oauth2.Request{
							Form: url.Values{},
							Client: &oauth2.DefaultClient{
								GrantTypes: oauth2.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
							},
							GrantedScope: oauth2.Arguments{},
							Session:      &oauth2.DefaultSession{},
							RequestedAt:  time.Now().UTC(),
						},
					},
					setup: func(t *testing.T, areq *oauth2.AccessRequest, config *oauth2.Config) {
						config.RefreshTokenScopes = []string{}

						dar := oauth2.NewDeviceAuthorizeRequest()
						dar.Merge(areq)
						dCode, dSig, err := strategy.GenerateRFC8628DeviceCode(context.TODO())
						require.NoError(t, err)
						_, uSig, err := strategy.GenerateRFC8628UserCode(context.TODO())
						require.NoError(t, err)
						dar.SetDeviceCodeSignature(dSig)
						dar.SetUserCodeSignature(uSig)

						require.NoError(t, store.CreateDeviceCodeSession(context.TODO(), dSig, dar))
						dar.SetStatus(oauth2.DeviceAuthorizeStatusApproved)
						require.NoError(t, store.CreateDeviceUserCodeSession(context.TODO(), uSig, dar))

						areq.Form.Add("device_code", dCode)
					},
					description: "should pass with no refresh token",
					check: func(t *testing.T, aresp *oauth2.AccessResponse) {
						assert.NotEmpty(t, aresp.AccessToken)
						assert.Equal(t, "bearer", aresp.TokenType)
						assert.Empty(t, aresp.GetExtra("refresh_token"))
						assert.NotEmpty(t, aresp.GetExtra("expires_in"))
						assert.Empty(t, aresp.GetExtra("scope"))
					},
				},
				{
					areq: &oauth2.AccessRequest{
						GrantTypes: oauth2.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
						Request: oauth2.Request{
							Form: url.Values{},
							Client: &oauth2.DefaultClient{
								GrantTypes: oauth2.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
							},
							GrantedScope: oauth2.Arguments{"foo"},
							Session:      &oauth2.DefaultSession{},
							RequestedAt:  time.Now().UTC(),
						},
					},
					setup: func(t *testing.T, areq *oauth2.AccessRequest, config *oauth2.Config) {
						dar := oauth2.NewDeviceAuthorizeRequest()
						dar.Merge(areq)
						dCode, dSig, err := strategy.GenerateRFC8628DeviceCode(context.TODO())
						require.NoError(t, err)
						_, uSig, err := strategy.GenerateRFC8628UserCode(context.TODO())
						require.NoError(t, err)
						dar.SetDeviceCodeSignature(dSig)
						dar.SetUserCodeSignature(uSig)

						require.NoError(t, store.CreateDeviceCodeSession(context.TODO(), dSig, dar))
						dar.SetStatus(oauth2.DeviceAuthorizeStatusApproved)
						require.NoError(t, store.CreateDeviceUserCodeSession(context.TODO(), uSig, dar))

						areq.Form.Add("device_code", dCode)
					},
					description: "should not have refresh token",
					check: func(t *testing.T, aresp *oauth2.AccessResponse) {
						assert.NotEmpty(t, aresp.AccessToken)
						assert.Equal(t, "bearer", aresp.TokenType)
						assert.Empty(t, aresp.GetExtra("refresh_token"))
						assert.NotEmpty(t, aresp.GetExtra("expires_in"))
						assert.Equal(t, "foo", aresp.GetExtra("scope"))
					},
				},
			} {
				t.Run("case="+c.description, func(t *testing.T) {
					config := &oauth2.Config{
						ScopeStrategy:            oauth2.HierarchicScopeStrategy,
						AudienceMatchingStrategy: oauth2.DefaultAudienceMatchingStrategy,
						AccessTokenLifespan:      time.Minute,
						RefreshTokenScopes:       []string{"offline"},
					}
					h = hoauth2.GenericCodeTokenEndpointHandler{
						CodeTokenEndpointHandler: &DeviceCodeTokenHandler{
							Strategy: strategy,
							Storage:  store,
							Config:   config,
						},
						AccessTokenStrategy:    strategy.CoreStrategy,
						RefreshTokenStrategy:   strategy.CoreStrategy,
						Config:                 config,
						CoreStorage:            store,
						TokenRevocationStorage: store,
					}

					if c.setup != nil {
						c.setup(t, c.areq, config)
					}

					aresp := oauth2.NewAccessResponse()
					err := h.PopulateTokenEndpointResponse(context.TODO(), c.areq, aresp)

					if c.expectErr != nil {
						require.EqualError(t, err, c.expectErr.Error(), "%+v", err)
					} else {
						require.NoError(t, err, "%+v", err)
					}

					if c.check != nil {
						c.check(t, aresp)
					}
				})
			}
		})
	}
}

func TestDeviceAuthorizeCode_HandleTokenEndpointRequest(t *testing.T) {
	for k, strategy := range map[string]struct {
		hoauth2.CoreStrategy
	}{
		"hmac": {&o2hmacshaStrategy},
	} {
		t.Run("strategy="+k, func(t *testing.T) {
			store := storage.NewMemoryStore()
			config := &oauth2.Config{
				ScopeStrategy:            oauth2.HierarchicScopeStrategy,
				AudienceMatchingStrategy: oauth2.DefaultAudienceMatchingStrategy,
				AccessTokenLifespan:      time.Minute,
				RefreshTokenScopes:       []string{"offline"},
			}
			h := hoauth2.GenericCodeTokenEndpointHandler{
				CodeTokenEndpointHandler: &DeviceCodeTokenHandler{
					Strategy: strategy,
					Storage:  store,
					Config:   config,
				},
				CoreStorage:          store,
				AccessTokenStrategy:  strategy.CoreStrategy,
				RefreshTokenStrategy: strategy.CoreStrategy,
				Config:               config,
			}
			for i, c := range []struct {
				areq        *oauth2.AccessRequest
				authreq     *oauth2.DeviceAuthorizeRequest
				description string
				setup       func(t *testing.T, areq *oauth2.AccessRequest, authreq *oauth2.DeviceAuthorizeRequest)
				check       func(t *testing.T, areq *oauth2.AccessRequest, authreq *oauth2.DeviceAuthorizeRequest)
				expectErr   error
			}{
				{
					areq: &oauth2.AccessRequest{
						GrantTypes: oauth2.Arguments{"12345678"},
					},
					description: "should fail because not responsible",
					expectErr:   oauth2.ErrUnknownRequest,
				},
				{
					areq: &oauth2.AccessRequest{
						GrantTypes: oauth2.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
						Request: oauth2.Request{
							Client:      &oauth2.DefaultClient{ID: "foo", GrantTypes: []string{""}},
							Session:     &oauth2.DefaultSession{},
							RequestedAt: time.Now().UTC(),
						},
					},
					description: "should fail because client is not granted this grant type",
					expectErr:   oauth2.ErrUnauthorizedClient,
				},
				{
					areq: &oauth2.AccessRequest{
						GrantTypes: oauth2.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
						Request: oauth2.Request{
							Client:      &oauth2.DefaultClient{GrantTypes: []string{"urn:ietf:params:oauth:grant-type:device_code"}},
							Session:     &oauth2.DefaultSession{},
							RequestedAt: time.Now().UTC(),
						},
					},
					description: "should fail because device code could not be retrieved",
					setup: func(t *testing.T, areq *oauth2.AccessRequest, authreq *oauth2.DeviceAuthorizeRequest) {
						deviceCode, _, err := strategy.GenerateRFC8628DeviceCode(context.TODO())
						require.NoError(t, err)
						areq.Form = url.Values{"device_code": {deviceCode}}
					},
					expectErr: oauth2.ErrInvalidGrant,
				},
				{
					areq: &oauth2.AccessRequest{
						GrantTypes: oauth2.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
						Request: oauth2.Request{
							Form:        url.Values{"device_code": {"AAAA"}},
							Client:      &oauth2.DefaultClient{GrantTypes: []string{"urn:ietf:params:oauth:grant-type:device_code"}},
							Session:     &oauth2.DefaultSession{},
							RequestedAt: time.Now().UTC(),
						},
					},
					description: "should fail because device code validation failed",
					expectErr:   oauth2.ErrInvalidGrant,
				},
				{
					areq: &oauth2.AccessRequest{
						GrantTypes: oauth2.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
						Request: oauth2.Request{
							Client:      &oauth2.DefaultClient{ID: "foo", GrantTypes: []string{"urn:ietf:params:oauth:grant-type:device_code"}},
							Session:     &oauth2.DefaultSession{},
							RequestedAt: time.Now().UTC(),
						},
					},
					authreq: &oauth2.DeviceAuthorizeRequest{
						Request: oauth2.Request{
							Client:         &oauth2.DefaultClient{ID: "bar"},
							RequestedScope: oauth2.Arguments{"a", "b"},
							Session:        openid.NewDefaultSession(),
						},
					},
					description: "should fail because client mismatch",
					setup: func(t *testing.T, areq *oauth2.AccessRequest, authreq *oauth2.DeviceAuthorizeRequest) {
						dCode, dSig, err := strategy.GenerateRFC8628DeviceCode(context.TODO())
						require.NoError(t, err)
						_, uSig, err := strategy.GenerateRFC8628UserCode(context.TODO())
						require.NoError(t, err)
						authreq.SetDeviceCodeSignature(dSig)
						authreq.SetUserCodeSignature(uSig)
						authreq.GetSession().SetExpiresAt(oauth2.UserCode, time.Now().UTC().Add(time.Hour))
						authreq.GetSession().SetExpiresAt(oauth2.DeviceCode, time.Now().UTC().Add(time.Hour))
						require.NoError(t, store.CreateDeviceCodeSession(context.TODO(), dSig, authreq))
						authreq.SetStatus(oauth2.DeviceAuthorizeStatusApproved)
						require.NoError(t, store.CreateDeviceUserCodeSession(context.TODO(), uSig, authreq))

						areq.Form = url.Values{"device_code": {dCode}}
					},
					expectErr: oauth2.ErrInvalidGrant,
				},
				{
					areq: &oauth2.AccessRequest{
						GrantTypes: oauth2.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
						Request: oauth2.Request{
							Client:      &oauth2.DefaultClient{ID: "foo", GrantTypes: []string{"urn:ietf:params:oauth:grant-type:device_code"}},
							Session:     &oauth2.DefaultSession{},
							RequestedAt: time.Now().UTC(),
						},
					},
					authreq: &oauth2.DeviceAuthorizeRequest{
						Request: oauth2.Request{
							Client:         &oauth2.DefaultClient{ID: "foo", GrantTypes: []string{"urn:ietf:params:oauth:grant-type:device_code"}},
							Session:        &oauth2.DefaultSession{},
							RequestedScope: oauth2.Arguments{"a", "b"},
							RequestedAt:    time.Now().UTC(),
						},
					},
					description: "should pass",
					setup: func(t *testing.T, areq *oauth2.AccessRequest, authreq *oauth2.DeviceAuthorizeRequest) {
						dCode, dSig, err := strategy.GenerateRFC8628DeviceCode(context.TODO())
						require.NoError(t, err)
						_, uSig, err := strategy.GenerateRFC8628UserCode(context.TODO())
						require.NoError(t, err)
						authreq.SetDeviceCodeSignature(dSig)
						authreq.SetUserCodeSignature(uSig)
						require.NoError(t, store.CreateDeviceCodeSession(context.TODO(), dSig, authreq))
						authreq.SetStatus(oauth2.DeviceAuthorizeStatusApproved)
						require.NoError(t, store.CreateDeviceUserCodeSession(context.TODO(), uSig, authreq))

						areq.Form = url.Values{"device_code": {dCode}}
					},
				},
				{
					areq: &oauth2.AccessRequest{
						GrantTypes: oauth2.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
						Request: oauth2.Request{
							Form: url.Values{},
							Client: &oauth2.DefaultClient{
								GrantTypes: oauth2.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
							},
							GrantedScope: oauth2.Arguments{"foo", "offline"},
							Session:      &oauth2.DefaultSession{},
							RequestedAt:  time.Now().UTC(),
						},
					},
					check: func(t *testing.T, areq *oauth2.AccessRequest, authreq *oauth2.DeviceAuthorizeRequest) {
						assert.Equal(t, time.Now().Add(time.Minute).UTC().Round(time.Second), areq.GetSession().GetExpiresAt(oauth2.AccessToken))
						assert.Equal(t, time.Now().Add(time.Minute).UTC().Round(time.Second), areq.GetSession().GetExpiresAt(oauth2.RefreshToken))
					},
					setup: func(t *testing.T, areq *oauth2.AccessRequest, authreq *oauth2.DeviceAuthorizeRequest) {
						authreq = oauth2.NewDeviceAuthorizeRequest()
						authreq.SetSession(openid.NewDefaultSession())
						authreq.GetSession().SetExpiresAt(oauth2.UserCode,
							time.Now().Add(-time.Hour).UTC().Round(time.Second))
						authreq.GetSession().SetExpiresAt(oauth2.DeviceCode,
							time.Now().Add(-time.Hour).UTC().Round(time.Second))
						dCode, dSig, err := strategy.GenerateRFC8628DeviceCode(context.TODO())
						require.NoError(t, err)
						_, uSig, err := strategy.GenerateRFC8628UserCode(context.TODO())
						require.NoError(t, err)
						authreq.SetDeviceCodeSignature(dSig)
						authreq.SetUserCodeSignature(uSig)
						require.NoError(t, store.CreateDeviceCodeSession(context.TODO(), dSig, authreq))
						authreq.SetStatus(oauth2.DeviceAuthorizeStatusApproved)
						require.NoError(t, store.CreateDeviceUserCodeSession(context.TODO(), uSig, authreq))

						areq.Form.Add("device_code", dCode)
					},
					description: "should fail because device code has expired",
					expectErr:   oauth2.ErrDeviceExpiredToken,
				},
			} {
				t.Run(fmt.Sprintf("case=%d/description=%s", i, c.description), func(t *testing.T) {
					if c.setup != nil {
						c.setup(t, c.areq, c.authreq)
					}

					t.Logf("Processing %+v", c.areq.Client)

					err := h.HandleTokenEndpointRequest(context.Background(), c.areq)
					if c.expectErr != nil {
						require.EqualError(t, err, c.expectErr.Error(), "%+v", err)
					} else {
						require.NoError(t, err, "%+v", err)
						if c.check != nil {
							c.check(t, c.areq, c.authreq)
						}
					}
				})
			}
		})
	}
}

func TestDeviceAuthorizeCodeTransactional_HandleTokenEndpointRequest(t *testing.T) {
	var mockTransactional *mock.MockTransactional
	var mockCoreStore *mock.MockCoreStorage
	var mockDeviceStore *mock.MockRFC8628Storage
	strategy := o2hmacshaStrategy
	deviceStrategy := o2hmacshaStrategy
	request := &oauth2.AccessRequest{
		GrantTypes: oauth2.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
		Request: oauth2.Request{
			Client: &oauth2.DefaultClient{
				GrantTypes: oauth2.Arguments{"urn:ietf:params:oauth:grant-type:device_code", "refresh_token"},
			},
			GrantedScope: oauth2.Arguments{"offline"},
			Session:      &oauth2.DefaultSession{},
			RequestedAt:  time.Now().UTC(),
		},
	}
	deviceAuthReq := &oauth2.DeviceAuthorizeRequest{
		Request: oauth2.Request{
			Client: &oauth2.DefaultClient{
				GrantTypes: oauth2.Arguments{"urn:ietf:params:oauth:grant-type:device_code", "refresh_token"},
			},
			GrantedScope: oauth2.Arguments{"offline"},
			Session:      &oauth2.DefaultSession{},
			RequestedAt:  time.Now().UTC(),
		},
		Status: oauth2.DeviceAuthorizeStatusApproved,
	}
	token, _, err := deviceStrategy.GenerateRFC8628DeviceCode(context.TODO())
	require.NoError(t, err)
	request.Form = url.Values{"device_code": {token}}
	response := oauth2.NewAccessResponse()
	propagatedContext := context.Background()

	// some storage implementation that has support for transactions, notice the embedded type `storage.Transactional`
	type coreTransactionalStore struct {
		storage.Transactional
		hoauth2.CoreStorage
	}

	type deviceTransactionalStore struct {
		storage.Transactional
		Storage
	}

	for _, testCase := range []struct {
		description string
		setup       func()
		expectError error
	}{
		{
			description: "transaction should be committed successfully if no errors occur",
			setup: func() {
				mockDeviceStore.
					EXPECT().
					GetDeviceCodeSession(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(deviceAuthReq, nil).
					Times(1)
				mockDeviceStore.
					EXPECT().
					GetDeviceUserCodeSession(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(deviceAuthReq, nil).
					Times(1)
				mockTransactional.
					EXPECT().
					BeginTX(propagatedContext).
					Return(propagatedContext, nil)
				mockDeviceStore.
					EXPECT().
					InvalidateDeviceCodeSession(gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
				mockDeviceStore.
					EXPECT().
					InvalidateDeviceUserCodeSession(gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
				mockCoreStore.
					EXPECT().
					CreateAccessTokenSession(propagatedContext, gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
				mockCoreStore.
					EXPECT().
					CreateRefreshTokenSession(propagatedContext, gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
				mockTransactional.
					EXPECT().
					Commit(propagatedContext).
					Return(nil).
					Times(1)
			},
		},
		{
			description: "transaction should be rolled back if `InvalidateDeviceCodeSession` returns an error",
			setup: func() {
				mockDeviceStore.
					EXPECT().
					GetDeviceCodeSession(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(deviceAuthReq, nil).
					Times(1)
				mockDeviceStore.
					EXPECT().
					GetDeviceUserCodeSession(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(deviceAuthReq, nil).
					Times(1)
				mockTransactional.
					EXPECT().
					BeginTX(propagatedContext).
					Return(propagatedContext, nil)
				mockDeviceStore.
					EXPECT().
					InvalidateDeviceCodeSession(gomock.Any(), gomock.Any()).
					Return(errors.New("Whoops, a nasty database error occurred!")).
					Times(1)
				mockTransactional.
					EXPECT().
					Rollback(propagatedContext).
					Return(nil).
					Times(1)
			},
			expectError: oauth2.ErrServerError,
		},
		{
			description: "transaction should be rolled back if `CreateAccessTokenSession` returns an error",
			setup: func() {
				mockDeviceStore.
					EXPECT().
					GetDeviceCodeSession(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(deviceAuthReq, nil).
					Times(1)
				mockDeviceStore.
					EXPECT().
					GetDeviceUserCodeSession(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(deviceAuthReq, nil).
					Times(1)
				mockTransactional.
					EXPECT().
					BeginTX(propagatedContext).
					Return(propagatedContext, nil)
				mockDeviceStore.
					EXPECT().
					InvalidateDeviceCodeSession(gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
				mockDeviceStore.
					EXPECT().
					InvalidateDeviceUserCodeSession(gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
				mockCoreStore.
					EXPECT().
					CreateAccessTokenSession(propagatedContext, gomock.Any(), gomock.Any()).
					Return(errors.New("Whoops, a nasty database error occurred!")).
					Times(1)
				mockTransactional.
					EXPECT().
					Rollback(propagatedContext).
					Return(nil).
					Times(1)
			},
			expectError: oauth2.ErrServerError,
		},
		{
			description: "should result in a server error if transaction cannot be created",
			setup: func() {
				mockDeviceStore.
					EXPECT().
					GetDeviceCodeSession(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(deviceAuthReq, nil).
					Times(1)
				mockDeviceStore.
					EXPECT().
					GetDeviceUserCodeSession(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(deviceAuthReq, nil).
					Times(1)
				mockTransactional.
					EXPECT().
					BeginTX(propagatedContext).
					Return(nil, errors.New("Whoops, unable to create transaction!"))
			},
			expectError: oauth2.ErrServerError,
		},
		{
			description: "should result in a server error if transaction cannot be rolled back",
			setup: func() {
				mockDeviceStore.
					EXPECT().
					GetDeviceCodeSession(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(deviceAuthReq, nil).
					Times(1)
				mockDeviceStore.
					EXPECT().
					GetDeviceUserCodeSession(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(deviceAuthReq, nil).
					Times(1)
				mockTransactional.
					EXPECT().
					BeginTX(propagatedContext).
					Return(propagatedContext, nil)
				mockDeviceStore.
					EXPECT().
					InvalidateDeviceCodeSession(gomock.Any(), gomock.Any()).
					Return(errors.New("Whoops, a nasty database error occurred!")).
					Times(1)
				mockTransactional.
					EXPECT().
					Rollback(propagatedContext).
					Return(errors.New("Whoops, unable to rollback transaction!")).
					Times(1)
			},
			expectError: oauth2.ErrServerError,
		},
		{
			description: "should result in a server error if transaction cannot be committed",
			setup: func() {
				mockDeviceStore.
					EXPECT().
					GetDeviceCodeSession(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(deviceAuthReq, nil).
					Times(1)
				mockDeviceStore.
					EXPECT().
					GetDeviceUserCodeSession(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(deviceAuthReq, nil).
					Times(1)
				mockTransactional.
					EXPECT().
					BeginTX(propagatedContext).
					Return(propagatedContext, nil)
				mockDeviceStore.
					EXPECT().
					InvalidateDeviceCodeSession(gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
				mockDeviceStore.
					EXPECT().
					InvalidateDeviceUserCodeSession(gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
				mockCoreStore.
					EXPECT().
					CreateAccessTokenSession(propagatedContext, gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
				mockCoreStore.
					EXPECT().
					CreateRefreshTokenSession(propagatedContext, gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
				mockTransactional.
					EXPECT().
					Commit(propagatedContext).
					Return(errors.New("Whoops, unable to commit transaction!")).
					Times(1)
				mockTransactional.
					EXPECT().
					Rollback(propagatedContext).
					Return(nil).
					Times(1)
			},
			expectError: oauth2.ErrServerError,
		},
	} {
		t.Run(fmt.Sprintf("scenario=%s", testCase.description), func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockTransactional = mock.NewMockTransactional(ctrl)
			mockCoreStore = mock.NewMockCoreStorage(ctrl)
			mockDeviceStore = mock.NewMockRFC8628Storage(ctrl)
			testCase.setup()
			handler := hoauth2.GenericCodeTokenEndpointHandler{
				CodeTokenEndpointHandler: &DeviceCodeTokenHandler{
					Strategy: &deviceStrategy,
					Storage: deviceTransactionalStore{
						mockTransactional,
						mockDeviceStore,
					},
					Config: &oauth2.Config{
						ScopeStrategy:            oauth2.HierarchicScopeStrategy,
						AudienceMatchingStrategy: oauth2.DefaultAudienceMatchingStrategy,
						AccessTokenLifespan:      time.Minute,
						RefreshTokenScopes:       []string{"offline"},
					},
				},
				CoreStorage: coreTransactionalStore{
					mockTransactional,
					mockCoreStore,
				},
				AccessTokenStrategy:  &strategy,
				RefreshTokenStrategy: &strategy,
				Config: &oauth2.Config{
					ScopeStrategy:            oauth2.HierarchicScopeStrategy,
					AudienceMatchingStrategy: oauth2.DefaultAudienceMatchingStrategy,
					RFC8628CodeLifespan:      time.Minute,
				},
			}

			if err := handler.PopulateTokenEndpointResponse(propagatedContext, request, response); testCase.expectError != nil {
				assert.EqualError(t, err, testCase.expectError.Error())
			}
		})
	}
}
