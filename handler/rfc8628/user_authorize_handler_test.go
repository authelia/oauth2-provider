package rfc8628_test

import (
	"context"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	. "authelia.com/provider/oauth2/handler/rfc8628"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestUserAuthorizeHandler_PopulateRFC8628UserAuthorizeEndpointResponse(t *testing.T) {
	type fields struct {
		Storage  Storage
		Strategy CodeStrategy
		Config   interface {
			oauth2.RFC9628DeviceAuthorizeConfigProvider
			oauth2.ClockConfigProvider
		}
	}
	type args struct {
		ctx    context.Context
		req    oauth2.DeviceAuthorizeRequester
		resp   oauth2.DeviceUserAuthorizeResponder
		status oauth2.DeviceAuthorizeStatus
	}

	defaultSetupFunc := func(t *testing.T, dar oauth2.DeviceAuthorizeRequester, f *fields, a *args) {
		dar.SetSession(openid.NewDefaultSession())
		dar.GetSession().SetExpiresAt(oauth2.UserCode,
			time.Now().UTC().Add(
				f.Config.GetRFC8628CodeLifespan(a.ctx)).Truncate(jwt.TimePrecision))
		code, sig, err := f.Strategy.GenerateRFC8628UserCode(a.ctx)
		require.NoError(t, err)
		dar.SetUserCodeSignature(sig)
		err = f.Storage.CreateDeviceCodeSession(a.ctx, sig, dar)
		require.NoError(t, err)

		dar.GetRequestForm().Set("user_code", code)
		dar.SetStatus(a.status)
	}

	defaultCheckFunc := func(t *testing.T, duvr oauth2.DeviceUserAuthorizeResponder, a *args) {
		assert.NotEmpty(t, duvr)
		assert.Equal(t, oauth2.DeviceAuthorizeStatusToString(a.status), duvr.GetStatus())
	}

	strategy := hoauth2.NewHMACCoreStrategy(&oauth2.Config{
		GlobalSecret:          []byte("foobarfoobarfoobarfoobarfoobarfoobarfoobarfoobar"),
		AccessTokenLifespan:   time.Minute * 24,
		AuthorizeCodeLifespan: time.Minute * 24,
		RFC8628CodeLifespan:   time.Minute * 24,
	}, "authelia_%s_")

	tests := []struct {
		name    string
		fields  fields
		args    args
		setup   func(t *testing.T, dar oauth2.DeviceAuthorizeRequester, f *fields, a *args)
		check   func(t *testing.T, duvr oauth2.DeviceUserAuthorizeResponder, a *args)
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "approved",
			fields: fields{
				Storage:  storage.NewMemoryStore(),
				Strategy: strategy,
				Config: &oauth2.Config{
					RFC8628CodeLifespan:         time.Minute * 10,
					RFC8628TokenPollingInterval: time.Second * 10,
					RFC8628UserVerificationURL:  "https://www.test.com",
					AccessTokenLifespan:         time.Hour,
					RefreshTokenLifespan:        time.Hour,
					ScopeStrategy:               oauth2.HierarchicScopeStrategy,
					AudienceMatchingStrategy:    oauth2.DefaultAudienceMatchingStrategy,
					RefreshTokenScopes:          []string{"offline"},
				},
			},
			args: args{
				ctx:    t.Context(),
				req:    oauth2.NewDeviceAuthorizeRequest(),
				resp:   oauth2.NewRFC8628UserAuthorizeResponse(),
				status: oauth2.DeviceAuthorizeStatusApproved,
			},
			setup: defaultSetupFunc,
			check: defaultCheckFunc,
			wantErr: func(t assert.TestingT, err error, i ...any) bool {
				assert.NoError(t, err)
				return err == nil
			},
		},
		{
			name: "denied",
			fields: fields{
				Storage:  storage.NewMemoryStore(),
				Strategy: strategy,
				Config: &oauth2.Config{
					RFC8628CodeLifespan:         time.Minute * 10,
					RFC8628TokenPollingInterval: time.Second * 10,
					RFC8628UserVerificationURL:  "https://www.test.com",
					AccessTokenLifespan:         time.Hour,
					RefreshTokenLifespan:        time.Hour,
					ScopeStrategy:               oauth2.HierarchicScopeStrategy,
					AudienceMatchingStrategy:    oauth2.DefaultAudienceMatchingStrategy,
					RefreshTokenScopes:          []string{"offline"},
				},
			},
			args: args{
				ctx:    t.Context(),
				req:    oauth2.NewDeviceAuthorizeRequest(),
				resp:   oauth2.NewRFC8628UserAuthorizeResponse(),
				status: oauth2.DeviceAuthorizeStatusDenied,
			},
			setup: defaultSetupFunc,
			check: defaultCheckFunc,
			wantErr: func(t assert.TestingT, err error, i ...any) bool {
				assert.NoError(t, err)
				return err == nil
			},
		},
		{
			name: "new",
			fields: fields{
				Storage:  storage.NewMemoryStore(),
				Strategy: strategy,
				Config: &oauth2.Config{
					RFC8628CodeLifespan:         time.Minute * 10,
					RFC8628TokenPollingInterval: time.Second * 10,
					RFC8628UserVerificationURL:  "https://www.test.com",
					AccessTokenLifespan:         time.Hour,
					RefreshTokenLifespan:        time.Hour,
					ScopeStrategy:               oauth2.HierarchicScopeStrategy,
					AudienceMatchingStrategy:    oauth2.DefaultAudienceMatchingStrategy,
					RefreshTokenScopes:          []string{"offline"},
				},
			},
			args: args{
				ctx:    t.Context(),
				req:    oauth2.NewDeviceAuthorizeRequest(),
				resp:   oauth2.NewRFC8628UserAuthorizeResponse(),
				status: oauth2.DeviceAuthorizeStatusNew,
			},
			setup: defaultSetupFunc,
			check: nil,
			wantErr: func(t assert.TestingT, err error, i ...any) bool {
				assert.ErrorIs(t, err, oauth2.ErrInvalidRequest)
				return errors.Is(err, oauth2.ErrInvalidRequest)
			},
		},
		{
			name: "invalid",
			fields: fields{
				Storage:  storage.NewMemoryStore(),
				Strategy: strategy,
				Config: &oauth2.Config{
					RFC8628CodeLifespan:         time.Minute * 10,
					RFC8628TokenPollingInterval: time.Second * 10,
					RFC8628UserVerificationURL:  "https://www.test.com",
					AccessTokenLifespan:         time.Hour,
					RefreshTokenLifespan:        time.Hour,
					ScopeStrategy:               oauth2.HierarchicScopeStrategy,
					AudienceMatchingStrategy:    oauth2.DefaultAudienceMatchingStrategy,
					RefreshTokenScopes:          []string{"offline"},
				},
			},
			args: args{
				ctx:    t.Context(),
				req:    oauth2.NewDeviceAuthorizeRequest(),
				resp:   oauth2.NewRFC8628UserAuthorizeResponse(),
				status: 1234,
			},
			setup: defaultSetupFunc,
			check: nil,
			wantErr: func(t assert.TestingT, err error, i ...any) bool {
				assert.ErrorIs(t, err, oauth2.ErrInvalidRequest)
				return errors.Is(err, oauth2.ErrInvalidRequest)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &UserAuthorizeHandler{
				Storage:  tt.fields.Storage,
				Strategy: tt.fields.Strategy,
				Config:   tt.fields.Config,
			}
			if tt.setup != nil {
				tt.setup(t, tt.args.req, &tt.fields, &tt.args)
			}
			if tt.wantErr != nil {
				tt.wantErr(t, d.PopulateRFC8628UserAuthorizeEndpointResponse(tt.args.ctx, tt.args.req, tt.args.resp),
					fmt.Sprintf("PopulateRFC8628UserAuthorizeEndpointResponse(%v, %v, %v)",
						tt.args.ctx, tt.args.req, tt.args.resp))
			}
			if tt.check != nil {
				tt.check(t, tt.args.resp, &tt.args)
			}
		})
	}
}

func TestUserAuthorizeHandler_PopulateRFC8628UserAuthorizeEndpointResponse_HandleRFC8628UserAuthorizeEndpointRequest(t *testing.T) {
	type fields struct {
		Storage  Storage
		Strategy CodeStrategy
		Config   interface {
			oauth2.RFC9628DeviceAuthorizeConfigProvider
			oauth2.ClockConfigProvider
		}
	}
	type args struct {
		ctx    context.Context
		req    oauth2.DeviceAuthorizeRequester
		status oauth2.DeviceAuthorizeStatus
	}

	NewDeviceAuthorizeRequest := func(grantTypes []string) *oauth2.DeviceAuthorizeRequest {
		req := &oauth2.DeviceAuthorizeRequest{
			Request: oauth2.Request{
				Client: &oauth2.DefaultClient{
					GrantTypes: grantTypes,
				},
				RequestedScope:    oauth2.Arguments{},
				RequestedAudience: oauth2.Arguments{},
				GrantedAudience:   oauth2.Arguments{},
				GrantedScope:      oauth2.Arguments{},
				Form:              url.Values{},
				RequestedAt:       time.Now().UTC(),
			},
		}

		return req
	}

	defaultSetupFunc := func(t *testing.T, dar oauth2.DeviceAuthorizeRequester, f *fields, a *args) {
		dar.SetSession(openid.NewDefaultSession())
		dar.GetSession().SetExpiresAt(oauth2.UserCode,
			time.Now().UTC().Add(
				f.Config.GetRFC8628CodeLifespan(a.ctx)).Truncate(jwt.TimePrecision))
		code, sig, err := f.Strategy.GenerateRFC8628UserCode(a.ctx)
		require.NoError(t, err)
		dar.SetUserCodeSignature(sig)
		err = f.Storage.CreateDeviceCodeSession(a.ctx, sig, dar)
		require.NoError(t, err)

		dar.GetRequestForm().Set("user_code", code)
		dar.SetStatus(a.status)
	}

	strategy := hoauth2.NewHMACCoreStrategy(&oauth2.Config{
		GlobalSecret:          []byte("foobarfoobarfoobarfoobarfoobarfoobarfoobarfoobar"),
		AccessTokenLifespan:   time.Minute * 24,
		AuthorizeCodeLifespan: time.Minute * 24,
		RFC8628CodeLifespan:   time.Minute * 24,
	}, "authelia_%s_")

	tests := []struct {
		name    string
		fields  fields
		args    args
		setup   func(t *testing.T, dar oauth2.DeviceAuthorizeRequester, f *fields, a *args)
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "success",
			fields: fields{
				Storage:  storage.NewMemoryStore(),
				Strategy: strategy,
				Config: &oauth2.Config{
					RFC8628CodeLifespan:         time.Minute * 10,
					RFC8628TokenPollingInterval: time.Second * 10,
					RFC8628UserVerificationURL:  "https://www.test.com",
					AccessTokenLifespan:         time.Hour,
					RefreshTokenLifespan:        time.Hour,
					ScopeStrategy:               oauth2.HierarchicScopeStrategy,
					AudienceMatchingStrategy:    oauth2.DefaultAudienceMatchingStrategy,
					RefreshTokenScopes:          []string{"offline"},
				},
			},
			args: args{
				ctx: t.Context(),
				req: NewDeviceAuthorizeRequest(
					[]string{
						string(oauth2.GrantTypeDeviceCode),
						string(oauth2.GrantTypeImplicit),
						string(oauth2.GrantTypePassword),
						string(oauth2.GrantTypeClientCredentials),
					}),
				status: oauth2.DeviceAuthorizeStatusNew,
			},
			setup: defaultSetupFunc,
			wantErr: func(t assert.TestingT, err error, i ...any) bool {
				assert.NoError(t, err)
				return err == nil
			},
		},
		{
			name: "invalid client grant types",
			fields: fields{
				Storage:  storage.NewMemoryStore(),
				Strategy: strategy,
				Config: &oauth2.Config{
					RFC8628CodeLifespan:         time.Minute * 10,
					RFC8628TokenPollingInterval: time.Second * 10,
					RFC8628UserVerificationURL:  "https://www.test.com",
					AccessTokenLifespan:         time.Hour,
					RefreshTokenLifespan:        time.Hour,
					ScopeStrategy:               oauth2.HierarchicScopeStrategy,
					AudienceMatchingStrategy:    oauth2.DefaultAudienceMatchingStrategy,
					RefreshTokenScopes:          []string{"offline"},
				},
			},
			args: args{
				ctx: t.Context(),
				req: NewDeviceAuthorizeRequest(
					[]string{
						string(oauth2.GrantTypeImplicit),
						string(oauth2.GrantTypePassword),
						string(oauth2.GrantTypeClientCredentials),
					}),
				status: oauth2.DeviceAuthorizeStatusNew,
			},
			setup: defaultSetupFunc,
			wantErr: func(t assert.TestingT, err error, i ...any) bool {
				assert.ErrorIs(t, err, oauth2.ErrInvalidGrant)
				return errors.Is(err, oauth2.ErrInvalidGrant)
			},
		},
		{
			name: "invalid request no user_code in form",
			fields: fields{
				Storage:  storage.NewMemoryStore(),
				Strategy: strategy,
				Config: &oauth2.Config{
					RFC8628CodeLifespan:         time.Minute * 10,
					RFC8628TokenPollingInterval: time.Second * 10,
					RFC8628UserVerificationURL:  "https://www.test.com",
					AccessTokenLifespan:         time.Hour,
					RefreshTokenLifespan:        time.Hour,
					ScopeStrategy:               oauth2.HierarchicScopeStrategy,
					AudienceMatchingStrategy:    oauth2.DefaultAudienceMatchingStrategy,
					RefreshTokenScopes:          []string{"offline"},
				},
			},
			args: args{
				ctx: t.Context(),
				req: NewDeviceAuthorizeRequest(
					[]string{
						string(oauth2.GrantTypeDeviceCode),
						string(oauth2.GrantTypeImplicit),
						string(oauth2.GrantTypePassword),
						string(oauth2.GrantTypeClientCredentials),
					}),
				status: oauth2.DeviceAuthorizeStatusApproved,
			},
			setup: func(t *testing.T, dar oauth2.DeviceAuthorizeRequester, f *fields, a *args) {
				defaultSetupFunc(t, dar, f, a)
				dar.GetRequestForm().Del("user_code")
			},
			wantErr: func(t assert.TestingT, err error, i ...any) bool {
				assert.ErrorIs(t, err, oauth2.ErrInvalidRequest)
				return errors.Is(err, oauth2.ErrInvalidRequest)
			},
		},
		{
			name: "invalid request no user code session",
			fields: fields{
				Storage:  storage.NewMemoryStore(),
				Strategy: strategy,
				Config: &oauth2.Config{
					RFC8628CodeLifespan:         time.Minute * 10,
					RFC8628TokenPollingInterval: time.Second * 10,
					RFC8628UserVerificationURL:  "https://www.test.com",
					AccessTokenLifespan:         time.Hour,
					RefreshTokenLifespan:        time.Hour,
					ScopeStrategy:               oauth2.HierarchicScopeStrategy,
					AudienceMatchingStrategy:    oauth2.DefaultAudienceMatchingStrategy,
					RefreshTokenScopes:          []string{"offline"},
				},
			},
			args: args{
				ctx: t.Context(),
				req: NewDeviceAuthorizeRequest(
					[]string{
						string(oauth2.GrantTypeDeviceCode),
						string(oauth2.GrantTypeImplicit),
						string(oauth2.GrantTypePassword),
						string(oauth2.GrantTypeClientCredentials),
					}),
				status: oauth2.DeviceAuthorizeStatusApproved,
			},
			setup: func(t *testing.T, dar oauth2.DeviceAuthorizeRequester, f *fields, a *args) {
				dar.SetSession(openid.NewDefaultSession())
				dar.GetSession().SetExpiresAt(oauth2.UserCode,
					time.Now().UTC().Add(
						f.Config.GetRFC8628CodeLifespan(a.ctx)).Truncate(jwt.TimePrecision))
				code, sig, err := f.Strategy.GenerateRFC8628UserCode(a.ctx)
				require.NoError(t, err)
				dar.SetUserCodeSignature(sig)
				dar.GetRequestForm().Set("user_code", code)
				dar.SetStatus(a.status)
			},
			wantErr: func(t assert.TestingT, err error, i ...any) bool {
				assert.ErrorIs(t, err, oauth2.ErrInvalidGrant)
				return errors.Is(err, oauth2.ErrInvalidGrant)
			},
		},
		{
			name: "invalid request user code expired",
			fields: fields{
				Storage:  storage.NewMemoryStore(),
				Strategy: strategy,
				Config: &oauth2.Config{
					RFC8628CodeLifespan:         time.Minute * 10,
					RFC8628TokenPollingInterval: time.Second * 10,
					RFC8628UserVerificationURL:  "https://www.test.com",
					AccessTokenLifespan:         time.Hour,
					RefreshTokenLifespan:        time.Hour,
					ScopeStrategy:               oauth2.HierarchicScopeStrategy,
					AudienceMatchingStrategy:    oauth2.DefaultAudienceMatchingStrategy,
					RefreshTokenScopes:          []string{"offline"},
				},
			},
			args: args{
				ctx: t.Context(),
				req: NewDeviceAuthorizeRequest(
					[]string{
						string(oauth2.GrantTypeDeviceCode),
						string(oauth2.GrantTypeImplicit),
						string(oauth2.GrantTypePassword),
						string(oauth2.GrantTypeClientCredentials),
					}),
				status: oauth2.DeviceAuthorizeStatusApproved,
			},
			setup: func(t *testing.T, dar oauth2.DeviceAuthorizeRequester, f *fields, a *args) {
				dar.SetSession(openid.NewDefaultSession())
				dar.GetSession().SetExpiresAt(oauth2.UserCode,
					time.Now().UTC().Add(time.Duration(-1)*
						f.Config.GetRFC8628CodeLifespan(a.ctx)).Truncate(jwt.TimePrecision))
				code, sig, err := f.Strategy.GenerateRFC8628UserCode(a.ctx)
				require.NoError(t, err)
				dar.SetUserCodeSignature(sig)
				err = f.Storage.CreateDeviceCodeSession(a.ctx, sig, dar)
				require.NoError(t, err)

				dar.GetRequestForm().Set("user_code", code)
				dar.SetStatus(a.status)
			},
			wantErr: func(t assert.TestingT, err error, i ...any) bool {
				assert.ErrorIs(t, err, oauth2.ErrInvalidGrant)
				return errors.Is(err, oauth2.ErrInvalidGrant)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &UserAuthorizeHandler{
				Storage:  tt.fields.Storage,
				Strategy: tt.fields.Strategy,
				Config:   tt.fields.Config,
			}
			if tt.setup != nil {
				tt.setup(t, tt.args.req, &tt.fields, &tt.args)
			}
			if tt.wantErr != nil {
				tt.wantErr(t, d.HandleRFC8628UserAuthorizeEndpointRequest(tt.args.ctx, tt.args.req),
					fmt.Sprintf("HandleRFC8628UserAuthorizeEndpointRequest(%v, %v)", tt.args.ctx, tt.args.req))
			}
		})
	}
}
