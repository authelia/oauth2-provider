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
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/testing/mock"
	"authelia.com/provider/oauth2/token/hmac"
	"authelia.com/provider/oauth2/token/jwt"
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
				requester *oauth2.AccessRequest
				name      string
				setup     func(t *testing.T, requester *oauth2.AccessRequest, config *oauth2.Config)
				check     func(t *testing.T, responder *oauth2.AccessResponse)
				expectErr error
			}{
				{
					requester: &oauth2.AccessRequest{
						GrantTypes: oauth2.Arguments{"123"},
					},
					name:      "should fail because not responsible",
					expectErr: oauth2.ErrUnknownRequest,
				},
				{
					requester: &oauth2.AccessRequest{
						GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthDeviceCode},
						Request: oauth2.Request{
							Form: url.Values{},
							Client: &oauth2.DefaultClient{
								GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthDeviceCode},
							},
							Session:     &oauth2.DefaultSession{},
							RequestedAt: time.Now().UTC(),
						},
					},
					name: "should fail because device code not found",
					setup: func(t *testing.T, requester *oauth2.AccessRequest, config *oauth2.Config) {
						code, _, err := strategy.GenerateRFC8628DeviceCode(t.Context())
						require.NoError(t, err)
						requester.Form.Set(consts.FormParameterDeviceCode, code)
					},
					expectErr: oauth2.ErrServerError,
				},
				{
					requester: &oauth2.AccessRequest{
						GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthDeviceCode},
						Request: oauth2.Request{
							Form: url.Values{},
							Client: &oauth2.DefaultClient{
								GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthDeviceCode, consts.GrantTypeRefreshToken},
							},
							GrantedScope: oauth2.Arguments{"foo", consts.ScopeOffline},
							Session:      &oauth2.DefaultSession{},
							RequestedAt:  time.Now().UTC(),
						},
					},
					setup: func(t *testing.T, requester *oauth2.AccessRequest, config *oauth2.Config) {
						dar := oauth2.NewDeviceAuthorizeRequest()
						dar.Merge(requester)
						dCode, dSig, err := strategy.GenerateRFC8628DeviceCode(t.Context())
						require.NoError(t, err)
						_, uSig, err := strategy.GenerateRFC8628UserCode(t.Context())
						require.NoError(t, err)
						dar.SetDeviceCodeSignature(dSig)
						dar.SetUserCodeSignature(uSig)
						dar.SetStatus(oauth2.DeviceAuthorizeStatusApproved)

						require.NoError(t, store.CreateDeviceCodeSession(t.Context(), dSig, dar))

						requester.Form.Add(consts.FormParameterDeviceCode, dCode)
					},
					name: "should pass with offline scope and refresh token",
					check: func(t *testing.T, responder *oauth2.AccessResponse) {
						assert.NotEmpty(t, responder.AccessToken)
						assert.Equal(t, "bearer", responder.TokenType)
						assert.NotEmpty(t, responder.GetExtra(consts.AccessResponseRefreshToken))
						assert.NotEmpty(t, responder.GetExtra(consts.AccessResponseExpiresIn))
						assert.Equal(t, "foo offline", responder.GetExtra(consts.AccessResponseScope))
					},
				},
				{
					requester: &oauth2.AccessRequest{
						GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthDeviceCode},
						Request: oauth2.Request{
							Form: url.Values{},
							Client: &oauth2.DefaultClient{
								GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthDeviceCode, consts.GrantTypeRefreshToken},
							},
							GrantedScope: oauth2.Arguments{"foo"},
							Session:      &oauth2.DefaultSession{},
							RequestedAt:  time.Now().UTC(),
						},
					},
					setup: func(t *testing.T, requester *oauth2.AccessRequest, config *oauth2.Config) {
						config.RefreshTokenScopes = []string{}

						dar := oauth2.NewDeviceAuthorizeRequest()
						dar.Merge(requester)
						dCode, dSig, err := strategy.GenerateRFC8628DeviceCode(t.Context())
						require.NoError(t, err)
						_, uSig, err := strategy.GenerateRFC8628UserCode(t.Context())
						require.NoError(t, err)
						dar.SetDeviceCodeSignature(dSig)
						dar.SetUserCodeSignature(uSig)
						dar.SetStatus(oauth2.DeviceAuthorizeStatusApproved)

						require.NoError(t, store.CreateDeviceCodeSession(t.Context(), dSig, dar))

						requester.Form.Add(consts.FormParameterDeviceCode, dCode)
					},
					name: "should pass with refresh token always provided",
					check: func(t *testing.T, responder *oauth2.AccessResponse) {
						assert.NotEmpty(t, responder.AccessToken)
						assert.Equal(t, "bearer", responder.TokenType)
						assert.NotEmpty(t, responder.GetExtra(consts.AccessResponseRefreshToken))
						assert.NotEmpty(t, responder.GetExtra(consts.AccessResponseExpiresIn))
						assert.Equal(t, "foo", responder.GetExtra(consts.AccessResponseScope))
					},
				},
				{
					requester: &oauth2.AccessRequest{
						GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthDeviceCode},
						Request: oauth2.Request{
							Form: url.Values{},
							Client: &oauth2.DefaultClient{
								GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthDeviceCode},
							},
							GrantedScope: oauth2.Arguments{},
							Session:      &oauth2.DefaultSession{},
							RequestedAt:  time.Now().UTC(),
						},
					},
					setup: func(t *testing.T, requester *oauth2.AccessRequest, config *oauth2.Config) {
						config.RefreshTokenScopes = []string{}

						dar := oauth2.NewDeviceAuthorizeRequest()
						dar.Merge(requester)
						dCode, dSig, err := strategy.GenerateRFC8628DeviceCode(t.Context())
						require.NoError(t, err)
						_, uSig, err := strategy.GenerateRFC8628UserCode(t.Context())
						require.NoError(t, err)
						dar.SetDeviceCodeSignature(dSig)
						dar.SetUserCodeSignature(uSig)
						dar.SetStatus(oauth2.DeviceAuthorizeStatusApproved)

						require.NoError(t, store.CreateDeviceCodeSession(t.Context(), dSig, dar))

						requester.Form.Add(consts.FormParameterDeviceCode, dCode)
					},
					name: "should pass with no refresh token",
					check: func(t *testing.T, responder *oauth2.AccessResponse) {
						assert.NotEmpty(t, responder.AccessToken)
						assert.Equal(t, "bearer", responder.TokenType)
						assert.Empty(t, responder.GetExtra(consts.AccessResponseRefreshToken))
						assert.NotEmpty(t, responder.GetExtra(consts.AccessResponseExpiresIn))
						assert.Empty(t, responder.GetExtra(consts.AccessResponseScope))
					},
				},
				{
					requester: &oauth2.AccessRequest{
						GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthDeviceCode},
						Request: oauth2.Request{
							Form: url.Values{},
							Client: &oauth2.DefaultClient{
								GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthDeviceCode},
							},
							GrantedScope: oauth2.Arguments{"foo"},
							Session:      &oauth2.DefaultSession{},
							RequestedAt:  time.Now().UTC(),
						},
					},
					setup: func(t *testing.T, requester *oauth2.AccessRequest, config *oauth2.Config) {
						deviceRequester := oauth2.NewDeviceAuthorizeRequest()
						deviceRequester.Merge(requester)
						dCode, dSig, err := strategy.GenerateRFC8628DeviceCode(t.Context())
						require.NoError(t, err)
						_, uSig, err := strategy.GenerateRFC8628UserCode(t.Context())
						require.NoError(t, err)
						deviceRequester.SetDeviceCodeSignature(dSig)
						deviceRequester.SetUserCodeSignature(uSig)
						deviceRequester.SetStatus(oauth2.DeviceAuthorizeStatusApproved)

						require.NoError(t, store.CreateDeviceCodeSession(t.Context(), dSig, deviceRequester))

						requester.Form.Add(consts.FormParameterDeviceCode, dCode)
					},
					name: "should not have refresh token",
					check: func(t *testing.T, responder *oauth2.AccessResponse) {
						assert.NotEmpty(t, responder.AccessToken)
						assert.Equal(t, "bearer", responder.TokenType)
						assert.Empty(t, responder.GetExtra(consts.AccessResponseRefreshToken))
						assert.NotEmpty(t, responder.GetExtra(consts.AccessResponseExpiresIn))
						assert.Equal(t, "foo", responder.GetExtra(consts.AccessResponseScope))
					},
				},
			} {
				t.Run("case="+c.name, func(t *testing.T) {
					config := &oauth2.Config{
						ScopeStrategy:            oauth2.HierarchicScopeStrategy,
						AudienceMatchingStrategy: oauth2.DefaultAudienceMatchingStrategy,
						AccessTokenLifespan:      time.Minute,
						RefreshTokenScopes:       []string{consts.ScopeOffline},
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
						c.setup(t, c.requester, config)
					}

					responder := oauth2.NewAccessResponse()
					err := h.PopulateTokenEndpointResponse(t.Context(), c.requester, responder)

					if c.expectErr != nil {
						require.EqualError(t, err, c.expectErr.Error(), "%+v", err)
					} else {
						require.NoError(t, err, "%+v", err)
					}

					if c.check != nil {
						c.check(t, responder)
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
				RefreshTokenScopes:       []string{consts.ScopeOffline},
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
				requester       *oauth2.AccessRequest
				deviceRequester *oauth2.DeviceAuthorizeRequest
				description     string
				setup           func(t *testing.T, requester *oauth2.AccessRequest, deviceRequester *oauth2.DeviceAuthorizeRequest)
				check           func(t *testing.T, requester *oauth2.AccessRequest, deviceRequester *oauth2.DeviceAuthorizeRequest)
				expectErr       error
			}{
				{
					requester: &oauth2.AccessRequest{
						GrantTypes: oauth2.Arguments{"12345678"},
					},
					description: "should fail because not responsible",
					expectErr:   oauth2.ErrUnknownRequest,
				},
				{
					requester: &oauth2.AccessRequest{
						GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthDeviceCode},
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
					requester: &oauth2.AccessRequest{
						GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthDeviceCode},
						Request: oauth2.Request{
							Client:      &oauth2.DefaultClient{GrantTypes: []string{consts.GrantTypeOAuthDeviceCode}},
							Session:     &oauth2.DefaultSession{},
							RequestedAt: time.Now().UTC(),
						},
					},
					description: "should fail because device code could not be retrieved",
					setup: func(t *testing.T, requester *oauth2.AccessRequest, deviceRequester *oauth2.DeviceAuthorizeRequest) {
						deviceCode, _, err := strategy.GenerateRFC8628DeviceCode(t.Context())
						require.NoError(t, err)
						requester.Form = url.Values{consts.FormParameterDeviceCode: {deviceCode}}
					},
					expectErr: oauth2.ErrInvalidGrant,
				},
				{
					requester: &oauth2.AccessRequest{
						GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthDeviceCode},
						Request: oauth2.Request{
							Form:        url.Values{consts.FormParameterDeviceCode: {"AAAA"}},
							Client:      &oauth2.DefaultClient{GrantTypes: []string{consts.GrantTypeOAuthDeviceCode}},
							Session:     &oauth2.DefaultSession{},
							RequestedAt: time.Now().UTC(),
						},
					},
					description: "should fail because device code validation failed",
					expectErr:   oauth2.ErrInvalidGrant,
				},
				{
					requester: &oauth2.AccessRequest{
						GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthDeviceCode},
						Request: oauth2.Request{
							Client:      &oauth2.DefaultClient{ID: "foo", GrantTypes: []string{consts.GrantTypeOAuthDeviceCode}},
							Session:     &oauth2.DefaultSession{},
							RequestedAt: time.Now().UTC(),
						},
					},
					deviceRequester: &oauth2.DeviceAuthorizeRequest{
						Request: oauth2.Request{
							Client:         &oauth2.DefaultClient{ID: "bar"},
							RequestedScope: oauth2.Arguments{"a", "b"},
							Session:        openid.NewDefaultSession(),
						},
					},
					description: "should fail because client mismatch",
					setup: func(t *testing.T, requester *oauth2.AccessRequest, deviceRequester *oauth2.DeviceAuthorizeRequest) {
						dCode, dSig, err := strategy.GenerateRFC8628DeviceCode(t.Context())
						require.NoError(t, err)
						_, uSig, err := strategy.GenerateRFC8628UserCode(t.Context())
						require.NoError(t, err)
						deviceRequester.SetDeviceCodeSignature(dSig)
						deviceRequester.SetUserCodeSignature(uSig)
						deviceRequester.GetSession().SetExpiresAt(oauth2.UserCode, time.Now().UTC().Add(time.Hour))
						deviceRequester.GetSession().SetExpiresAt(oauth2.DeviceCode, time.Now().UTC().Add(time.Hour))
						deviceRequester.SetStatus(oauth2.DeviceAuthorizeStatusApproved)
						require.NoError(t, store.CreateDeviceCodeSession(t.Context(), dSig, deviceRequester))

						requester.Form = url.Values{consts.FormParameterDeviceCode: {dCode}}
					},
					expectErr: oauth2.ErrInvalidGrant,
				},
				{
					requester: &oauth2.AccessRequest{
						GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthDeviceCode},
						Request: oauth2.Request{
							Client:      &oauth2.DefaultClient{ID: "foo", GrantTypes: []string{consts.GrantTypeOAuthDeviceCode}},
							Session:     &oauth2.DefaultSession{},
							RequestedAt: time.Now().UTC(),
						},
					},
					deviceRequester: &oauth2.DeviceAuthorizeRequest{
						Request: oauth2.Request{
							Client:         &oauth2.DefaultClient{ID: "foo", GrantTypes: []string{consts.GrantTypeOAuthDeviceCode}},
							Session:        &oauth2.DefaultSession{},
							RequestedScope: oauth2.Arguments{"a", "b"},
							RequestedAt:    time.Now().UTC(),
						},
					},
					description: "should pass",
					setup: func(t *testing.T, requester *oauth2.AccessRequest, deviceRequester *oauth2.DeviceAuthorizeRequest) {
						dCode, dSig, err := strategy.GenerateRFC8628DeviceCode(t.Context())
						require.NoError(t, err)
						_, uSig, err := strategy.GenerateRFC8628UserCode(t.Context())
						require.NoError(t, err)
						deviceRequester.SetDeviceCodeSignature(dSig)
						deviceRequester.SetUserCodeSignature(uSig)
						deviceRequester.SetStatus(oauth2.DeviceAuthorizeStatusApproved)
						require.NoError(t, store.CreateDeviceCodeSession(t.Context(), dSig, deviceRequester))

						requester.Form = url.Values{consts.FormParameterDeviceCode: {dCode}}
					},
				},
				{
					requester: &oauth2.AccessRequest{
						GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthDeviceCode},
						Request: oauth2.Request{
							Form: url.Values{},
							Client: &oauth2.DefaultClient{
								GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthDeviceCode},
							},
							GrantedScope: oauth2.Arguments{"foo", consts.ScopeOffline},
							Session:      &oauth2.DefaultSession{},
							RequestedAt:  time.Now().UTC(),
						},
					},
					check: func(t *testing.T, requester *oauth2.AccessRequest, deviceRequester *oauth2.DeviceAuthorizeRequest) {
						assert.Equal(t, time.Now().Add(time.Minute).UTC().Truncate(jwt.TimePrecision), requester.GetSession().GetExpiresAt(oauth2.AccessToken))
						assert.Equal(t, time.Now().Add(time.Minute).UTC().Truncate(jwt.TimePrecision), requester.GetSession().GetExpiresAt(oauth2.RefreshToken))
					},
					setup: func(t *testing.T, requester *oauth2.AccessRequest, deviceRequester *oauth2.DeviceAuthorizeRequest) {
						deviceRequester = oauth2.NewDeviceAuthorizeRequest()
						deviceRequester.SetSession(openid.NewDefaultSession())
						deviceRequester.GetSession().SetExpiresAt(oauth2.UserCode,
							time.Now().Add(-time.Hour).UTC().Truncate(jwt.TimePrecision))
						deviceRequester.GetSession().SetExpiresAt(oauth2.DeviceCode,
							time.Now().Add(-time.Hour).UTC().Truncate(jwt.TimePrecision))
						dCode, dSig, err := strategy.GenerateRFC8628DeviceCode(t.Context())
						require.NoError(t, err)
						_, uSig, err := strategy.GenerateRFC8628UserCode(t.Context())
						require.NoError(t, err)
						deviceRequester.SetDeviceCodeSignature(dSig)
						deviceRequester.SetUserCodeSignature(uSig)
						deviceRequester.SetStatus(oauth2.DeviceAuthorizeStatusApproved)
						require.NoError(t, store.CreateDeviceCodeSession(t.Context(), dSig, deviceRequester))

						requester.Form.Add(consts.FormParameterDeviceCode, dCode)
					},
					description: "should fail because device code has expired",
					expectErr:   oauth2.ErrDeviceExpiredToken,
				},
			} {
				t.Run(fmt.Sprintf("case=%d/description=%s", i, c.description), func(t *testing.T) {
					if c.setup != nil {
						c.setup(t, c.requester, c.deviceRequester)
					}

					err := h.HandleTokenEndpointRequest(context.Background(), c.requester)
					if c.expectErr != nil {
						require.EqualError(t, err, c.expectErr.Error(), "%+v", err)
					} else {
						require.NoError(t, err, "%+v", err)
						if c.check != nil {
							c.check(t, c.requester, c.deviceRequester)
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
		GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthDeviceCode},
		Request: oauth2.Request{
			Client: &oauth2.DefaultClient{
				GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthDeviceCode, consts.GrantTypeRefreshToken},
			},
			GrantedScope: oauth2.Arguments{consts.ScopeOffline},
			Session:      &oauth2.DefaultSession{},
			RequestedAt:  time.Now().UTC(),
		},
	}
	deviceAuthReq := &oauth2.DeviceAuthorizeRequest{
		Request: oauth2.Request{
			Client: &oauth2.DefaultClient{
				GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthDeviceCode, consts.GrantTypeRefreshToken},
			},
			GrantedScope: oauth2.Arguments{consts.ScopeOffline},
			Session:      &oauth2.DefaultSession{},
			RequestedAt:  time.Now().UTC(),
		},
		Status: oauth2.DeviceAuthorizeStatusApproved,
	}
	token, _, err := deviceStrategy.GenerateRFC8628DeviceCode(t.Context())
	require.NoError(t, err)
	request.Form = url.Values{consts.FormParameterDeviceCode: {token}}
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
					GetDeviceCodeSessionByUserCode(gomock.Any(), gomock.Any(), gomock.Any()).
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
					GetDeviceCodeSessionByUserCode(gomock.Any(), gomock.Any(), gomock.Any()).
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
					GetDeviceCodeSessionByUserCode(gomock.Any(), gomock.Any(), gomock.Any()).
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
					GetDeviceCodeSessionByUserCode(gomock.Any(), gomock.Any(), gomock.Any()).
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
					GetDeviceCodeSessionByUserCode(gomock.Any(), gomock.Any(), gomock.Any()).
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
					GetDeviceCodeSessionByUserCode(gomock.Any(), gomock.Any(), gomock.Any()).
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
						RefreshTokenScopes:       []string{consts.ScopeOffline},
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
