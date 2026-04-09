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

func TestDeviceAuthorizeCode_PopulateTokenEndpointResponseHMAC(t *testing.T) {
	strategy := &o2hmacshaStrategy

	store := storage.NewMemoryStore()

	testCases := []struct {
		requester *oauth2.AccessRequest
		name      string
		setup     func(t *testing.T, requester *oauth2.AccessRequest, config *oauth2.Config)
		check     func(t *testing.T, responder *oauth2.AccessResponse)
		err       string
	}{
		{
			requester: &oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{"123"},
			},
			name: "ShouldFailNotResponsible",
			err:  "The handler is not responsible for this request.",
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
			name: "ShouldFailDeviceCodeNotFound",
			setup: func(t *testing.T, requester *oauth2.AccessRequest, config *oauth2.Config) {
				code, _, err := strategy.GenerateRFC8628DeviceCode(t.Context())
				require.NoError(t, err)
				requester.Form.Set(consts.FormParameterDeviceCode, code)
			},
			err: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. Could not find the requested resource(s).",
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
			name: "ShouldPassWithOfflineScopeAndRefreshToken",
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
			name: "ShouldPassWithRefreshTokenAlwaysProvided",
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
			name: "ShouldPassWithNoRefreshToken",
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
			name: "ShouldNotHaveRefreshToken",
			check: func(t *testing.T, responder *oauth2.AccessResponse) {
				assert.NotEmpty(t, responder.AccessToken)
				assert.Equal(t, "bearer", responder.TokenType)
				assert.Empty(t, responder.GetExtra(consts.AccessResponseRefreshToken))
				assert.NotEmpty(t, responder.GetExtra(consts.AccessResponseExpiresIn))
				assert.Equal(t, "foo", responder.GetExtra(consts.AccessResponseScope))
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
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
				AccessTokenStrategy:    strategy,
				RefreshTokenStrategy:   strategy,
				Config:                 config,
				CoreStorage:            store,
				TokenRevocationStorage: store,
			}

			if tc.setup != nil {
				tc.setup(t, tc.requester, config)
			}

			responder := oauth2.NewAccessResponse()
			err := h.PopulateTokenEndpointResponse(t.Context(), tc.requester, responder)

			if tc.err != "" {
				require.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.err, "%+v", err)
			} else {
				require.NoError(t, err, "%+v", err)
			}

			if tc.check != nil {
				tc.check(t, responder)
			}
		})
	}
}

func TestDeviceAuthorizeCode_HandleTokenEndpointRequest(t *testing.T) {
	strategy := &o2hmacshaStrategy

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
		AccessTokenStrategy:  strategy,
		RefreshTokenStrategy: strategy,
		Config:               config,
	}

	expiredAt := time.Now().Add(-time.Hour).UTC().Truncate(jwt.TimePrecision)

	testCases := []struct {
		requester       *oauth2.AccessRequest
		deviceRequester *oauth2.DeviceAuthorizeRequest
		name            string
		setup           func(t *testing.T, requester *oauth2.AccessRequest, deviceRequester *oauth2.DeviceAuthorizeRequest)
		check           func(t *testing.T, requester *oauth2.AccessRequest, deviceRequester *oauth2.DeviceAuthorizeRequest)
		err             string
	}{
		{
			requester: &oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{"12345678"},
			},
			name: "ShouldFailNotResponsible",
			err:  "The handler is not responsible for this request.",
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
			name: "ShouldFailClientNotGrantedGrantType",
			err:  "The client is not authorized to request a token using this method. The OAuth 2.0 Client is not allowed to use authorization grant 'urn:ietf:params:oauth:grant-type:device_code'.",
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
			name: "ShouldFailDeviceCodeNotRetrieved",
			setup: func(t *testing.T, requester *oauth2.AccessRequest, deviceRequester *oauth2.DeviceAuthorizeRequest) {
				deviceCode, _, err := strategy.GenerateRFC8628DeviceCode(t.Context())
				require.NoError(t, err)
				requester.Form = url.Values{consts.FormParameterDeviceCode: {deviceCode}}
			},
			err: "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. Could not find the requested resource(s).",
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
			name: "ShouldFailDeviceCodeValidationFailed",
			err:  "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. Could not find the requested resource(s).",
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
			name: "ShouldFailClientMismatch",
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
			err: "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. The OAuth 2.0 Client ID from this request does not match the one from the authorize request.",
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
			name: "ShouldPass",
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
				deviceRequester.GetSession().SetExpiresAt(oauth2.UserCode, expiredAt)
				deviceRequester.GetSession().SetExpiresAt(oauth2.DeviceCode, expiredAt)
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
			name: "ShouldFailDeviceCodeExpired",
			err:  fmt.Sprintf("The device_code has expired, and the device authorization session has concluded. Device Code expired at '%s'.", expiredAt),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.setup != nil {
				tc.setup(t, tc.requester, tc.deviceRequester)
			}

			err := h.HandleTokenEndpointRequest(context.Background(), tc.requester)
			if tc.err != "" {
				require.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.err, "%+v", err)
			} else {
				require.NoError(t, err, "%+v", err)
				if tc.check != nil {
					tc.check(t, tc.requester, tc.deviceRequester)
				}
			}
		})
	}
}

func TestDeviceAuthorizeCodeTransactional_HandleTokenEndpointRequest(t *testing.T) {
	strategy := o2hmacshaStrategy
	deviceStrategy := o2hmacshaStrategy

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

	type coreTransactionalStore struct {
		storage.Transactional
		hoauth2.CoreStorage
	}

	type deviceTransactionalStore struct {
		storage.Transactional
		Storage
	}

	testCases := []struct {
		name  string
		setup func(ctx context.Context, mockTransactional *mock.MockTransactional, mockCoreStore *mock.MockCoreStorage, mockDeviceStore *mock.MockRFC8628Storage)
		err   string
	}{
		{
			name: "ShouldCommitTransactionWhenNoErrors",
			setup: func(propagatedContext context.Context, mockTransactional *mock.MockTransactional, mockCoreStore *mock.MockCoreStorage, mockDeviceStore *mock.MockRFC8628Storage) {
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
			name: "ShouldRollbackWhenInvalidateDeviceCodeSessionReturnsError",
			err:  "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. Whoops, a nasty database error occurred!",
			setup: func(propagatedContext context.Context, mockTransactional *mock.MockTransactional, mockCoreStore *mock.MockCoreStorage, mockDeviceStore *mock.MockRFC8628Storage) {
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
		},
		{
			name: "ShouldRollbackWhenCreateAccessTokenSessionReturnsError",
			err:  "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. Whoops, a nasty database error occurred!",
			setup: func(propagatedContext context.Context, mockTransactional *mock.MockTransactional, mockCoreStore *mock.MockCoreStorage, mockDeviceStore *mock.MockRFC8628Storage) {
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
		},
		{
			name: "ShouldFailWhenTransactionCannotBeCreated",
			err:  "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. Whoops, unable to create transaction!",
			setup: func(propagatedContext context.Context, mockTransactional *mock.MockTransactional, mockCoreStore *mock.MockCoreStorage, mockDeviceStore *mock.MockRFC8628Storage) {
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
		},
		{
			name: "ShouldFailWhenTransactionCannotBeRolledBack",
			err:  "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. error: server_error; rollback error: Whoops, unable to rollback transaction!",
			setup: func(propagatedContext context.Context, mockTransactional *mock.MockTransactional, mockCoreStore *mock.MockCoreStorage, mockDeviceStore *mock.MockRFC8628Storage) {
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
		},
		{
			name: "ShouldFailWhenTransactionCannotBeCommitted",
			err:  "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. Whoops, unable to commit transaction!",
			setup: func(propagatedContext context.Context, mockTransactional *mock.MockTransactional, mockCoreStore *mock.MockCoreStorage, mockDeviceStore *mock.MockRFC8628Storage) {
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
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			propagatedContext := context.Background()

			mockTransactional := mock.NewMockTransactional(ctrl)
			mockCoreStore := mock.NewMockCoreStorage(ctrl)
			mockDeviceStore := mock.NewMockRFC8628Storage(ctrl)

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
			token, _, err := deviceStrategy.GenerateRFC8628DeviceCode(t.Context())
			require.NoError(t, err)
			request.Form = url.Values{consts.FormParameterDeviceCode: {token}}
			response := oauth2.NewAccessResponse()

			tc.setup(propagatedContext, mockTransactional, mockCoreStore, mockDeviceStore)

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

			err = handler.PopulateTokenEndpointResponse(propagatedContext, request, response)
			if tc.err != "" {
				assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
