// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"authelia.com/provider/oauth2"
	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/compose"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/testing/mock"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestIntrospectionResponseTokenUse(t *testing.T) {
	ctrl := gomock.NewController(t)
	validator := mock.NewMockTokenIntrospector(ctrl)
	defer ctrl.Finish()

	ctx := gomock.AssignableToTypeOf(context.WithValue(context.TODO(), ContextKey("test"), nil))

	config := new(Config)
	provider := compose.ComposeAllEnabled(config, storage.NewExampleStore(), nil).(*Fosite)
	httpreq := &http.Request{
		Method: "POST",
		Header: http.Header{
			consts.HeaderAuthorization: []string{"bearer some-token"},
		},
		PostForm: url.Values{
			"token": []string{"introspect-token"},
		},
	}
	for k, c := range []struct {
		description string
		setup       func()
		expectedTU  TokenUse
		expectedATT string
	}{
		{
			description: "introspecting access token",
			setup: func() {
				config.TokenIntrospectionHandlers = TokenIntrospectionHandlers{validator}
				validator.EXPECT().IntrospectToken(ctx, "some-token", gomock.Any(), gomock.Any(), gomock.Any()).Return(TokenUse(""), nil)
				validator.EXPECT().IntrospectToken(ctx, "introspect-token", gomock.Any(), gomock.Any(), gomock.Any()).Return(AccessToken, nil)
			},
			expectedATT: BearerAccessToken,
			expectedTU:  AccessToken,
		},
		{
			description: "introspecting refresh token",
			setup: func() {
				config.TokenIntrospectionHandlers = TokenIntrospectionHandlers{validator}
				validator.EXPECT().IntrospectToken(ctx, "some-token", gomock.Any(), gomock.Any(), gomock.Any()).Return(TokenUse(""), nil)
				validator.EXPECT().IntrospectToken(ctx, "introspect-token", gomock.Any(), gomock.Any(), gomock.Any()).Return(RefreshToken, nil)
			},
			expectedATT: "",
			expectedTU:  RefreshToken,
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			c.setup()
			res, err := provider.NewIntrospectionRequest(context.TODO(), httpreq, &DefaultSession{})
			require.NoError(t, err)
			assert.Equal(t, c.expectedATT, res.GetAccessTokenType())
			assert.Equal(t, c.expectedTU, res.GetTokenUse())
		})
	}
}

func TestIntrospectionResponse(t *testing.T) {
	r := &oauth2.IntrospectionResponse{
		AccessRequester: oauth2.NewAccessRequest(nil),
		Active:          true,
	}

	assert.Equal(t, r.AccessRequester, r.GetAccessRequester())
	assert.Equal(t, r.Active, r.IsActive())
}

func TestNewIntrospectionRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	validator := mock.NewMockTokenIntrospector(ctrl)
	defer ctrl.Finish()

	ctx := gomock.AssignableToTypeOf(context.WithValue(context.TODO(), ContextKey("test"), nil))

	config := new(Config)
	f := compose.ComposeAllEnabled(config, storage.NewExampleStore(), nil).(*Fosite)
	httpreq := &http.Request{
		Method: "POST",
		Header: http.Header{},
		Form:   url.Values{},
	}
	newErr := errors.New("asdf")

	for k, c := range []struct {
		name      string
		setup     func()
		expectErr error
		isActive  bool
	}{
		{
			name: "should fail",
			setup: func() {
			},
			expectErr: ErrInvalidRequest,
		},
		{
			name: "should fail",
			setup: func() {
				config.TokenIntrospectionHandlers = TokenIntrospectionHandlers{validator}
				httpreq = &http.Request{
					Method: "POST",
					Header: http.Header{
						consts.HeaderAuthorization: []string{"bearer some-token"},
					},
					PostForm: url.Values{
						"token": []string{"introspect-token"},
					},
				}
				validator.EXPECT().IntrospectToken(ctx, "some-token", gomock.Any(), gomock.Any(), gomock.Any()).Return(TokenUse(""), nil)
				validator.EXPECT().IntrospectToken(ctx, "introspect-token", gomock.Any(), gomock.Any(), gomock.Any()).Return(TokenUse(""), newErr)
			},
			isActive:  false,
			expectErr: ErrInactiveToken,
		},
		{
			name: "should pass",
			setup: func() {
				config.TokenIntrospectionHandlers = TokenIntrospectionHandlers{validator}
				httpreq = &http.Request{
					Method: "POST",
					Header: http.Header{
						consts.HeaderAuthorization: []string{"bearer some-token"},
					},
					PostForm: url.Values{
						"token": []string{"introspect-token"},
					},
				}
				validator.EXPECT().IntrospectToken(ctx, "some-token", gomock.Any(), gomock.Any(), gomock.Any()).Return(TokenUse(""), nil)
				validator.EXPECT().IntrospectToken(ctx, "introspect-token", gomock.Any(), gomock.Any(), gomock.Any()).Return(TokenUse(""), nil)
			},
			isActive: true,
		},
		{
			name: "should pass with basic auth if username and password encoded",
			setup: func() {
				config.TokenIntrospectionHandlers = TokenIntrospectionHandlers{validator}
				httpreq = &http.Request{
					Method: "POST",
					Header: http.Header{
						// Basic Authorization with username=encoded:client and password=encoded&password
						consts.HeaderAuthorization: []string{"Basic ZW5jb2RlZCUzQWNsaWVudDplbmNvZGVkJTI2cGFzc3dvcmQ="},
					},
					PostForm: url.Values{
						"token": []string{"introspect-token"},
					},
				}
				validator.EXPECT().IntrospectToken(ctx, "introspect-token", gomock.Any(), gomock.Any(), gomock.Any()).Return(TokenUse(""), nil)
			},
			isActive: true,
		},
		{
			name: "should pass with basic auth if username and password not encoded",
			setup: func() {
				config.TokenIntrospectionHandlers = TokenIntrospectionHandlers{validator}
				httpreq = &http.Request{
					Method: "POST",
					Header: http.Header{
						// Basic Authorization with username=my-client and password=foobar
						consts.HeaderAuthorization: []string{"Basic bXktY2xpZW50OmZvb2Jhcg=="},
					},
					PostForm: url.Values{
						"token": []string{"introspect-token"},
					},
				}
				validator.EXPECT().IntrospectToken(ctx, "introspect-token", gomock.Any(), gomock.Any(), gomock.Any()).Return(TokenUse(""), nil)
			},
			isActive: true,
		},
		{
			name: "should pass with basic auth if username and password not encoded",
			setup: func() {
				config.TokenIntrospectionHandlers = TokenIntrospectionHandlers{validator}
				httpreq = &http.Request{
					Method: "POST",
					Header: http.Header{
						// Basic Authorization with username=my-client and password=foobar
						consts.HeaderAuthorization: []string{"Basic bXktY2xpZW50OmZvb2Jhcg=="},
					},
					PostForm: url.Values{
						"token": []string{"introspect-token"},
					},
				}
				validator.EXPECT().IntrospectToken(ctx, "introspect-token", gomock.Any(), gomock.Any(), gomock.Any()).Return(TokenUse(""), nil)
			},
			isActive: true,
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			c.setup()
			res, err := f.NewIntrospectionRequest(context.TODO(), httpreq, &DefaultSession{})

			if c.expectErr != nil {
				assert.EqualError(t, err, c.expectErr.Error())
			} else {
				require.NoError(t, err)
				assert.Equal(t, c.isActive, res.IsActive())
			}
		})
	}
}

func TestIntrospectionResponseToMap(t *testing.T) {
	testCases := []struct {
		name        string
		have        IntrospectionResponder
		expectedaud []string
		expected    map[string]any
	}{
		{
			"ShouldDecodeInactive",
			&IntrospectionResponse{},
			nil,
			map[string]any{consts.ClaimActive: false},
		},
		{
			"ShouldReturnActiveWithoutAccessRequester",
			&IntrospectionResponse{
				Active: true,
			},
			nil,
			map[string]any{consts.ClaimActive: true},
		},
		{
			"ShouldReturnActiveWithAccessRequester",
			&IntrospectionResponse{
				Active: true,
				AccessRequester: &AccessRequest{
					Request: Request{
						RequestedAt:     time.Unix(100000, 0).UTC(),
						GrantedScope:    Arguments{consts.ScopeOpenID, "profile"},
						GrantedAudience: Arguments{"https://example.com", "aclient"},
						Client:          &DefaultClient{ID: "aclient"},
					},
				},
			},
			nil,
			map[string]any{
				consts.ClaimActive:           true,
				consts.ClaimScope:            "openid profile",
				consts.ClaimAudience:         []string{"https://example.com", "aclient"},
				consts.ClaimIssuedAt:         int64(100000),
				consts.ClaimClientIdentifier: "aclient",
			},
		},
		{
			"ShouldReturnActiveWithAccessRequesterAndSession",
			&IntrospectionResponse{
				Active: true,
				AccessRequester: &AccessRequest{
					Request: Request{
						RequestedAt:     time.Unix(100000, 0).UTC(),
						GrantedScope:    Arguments{consts.ScopeOpenID, "profile"},
						GrantedAudience: Arguments{"https://example.com", "aclient"},
						Client:          &DefaultClient{ID: "aclient"},
						Session: &openid.DefaultSession{
							ExpiresAt: map[TokenType]time.Time{
								AccessToken: time.Unix(1000000, 0).UTC(),
							},
							Subject: "asubj",
							Claims: &jwt.IDTokenClaims{
								Extra: map[string]any{
									"aclaim":                   1,
									consts.ClaimExpirationTime: 0,
								},
							},
						},
					},
				},
			},
			nil,
			map[string]any{
				consts.ClaimActive:           true,
				consts.ClaimScope:            "openid profile",
				consts.ClaimAudience:         []string{"https://example.com", "aclient"},
				consts.ClaimIssuedAt:         int64(100000),
				consts.ClaimClientIdentifier: "aclient",
				//"aclaim":                     1,
				//consts.ClaimSubject:          "asubj",
				//consts.ClaimExpirationTime:   int64(1000000),
			},
		},
		{
			"ShouldReturnActiveWithAccessRequesterAndSessionWithIDTokenClaimsAndUsername",
			&IntrospectionResponse{
				Client: &DefaultClient{
					ID:       "rclient",
					Audience: []string{"https://rs.example.com"},
				},
				Active: true,
				AccessRequester: &AccessRequest{
					Request: Request{
						RequestedAt:     time.Unix(100000, 0).UTC(),
						GrantedScope:    Arguments{consts.ScopeOpenID, "profile"},
						GrantedAudience: Arguments{"https://example.com", "aclient"},
						Client:          &DefaultClient{ID: "aclient"},
						Session: &openid.DefaultSession{
							ExpiresAt: map[TokenType]time.Time{
								AccessToken: time.Unix(1000000, 0).UTC(),
							},
							Username: "auser",
							Claims: &jwt.IDTokenClaims{
								Subject: "asubj",
								Extra: map[string]any{
									"aclaim":                   1,
									consts.ClaimExpirationTime: 0,
								},
							},
						},
					},
				},
			},
			[]string{"rclient"},
			map[string]any{
				consts.ClaimActive:           true,
				consts.ClaimScope:            "openid profile",
				consts.ClaimAudience:         []string{"https://example.com", "aclient"},
				consts.ClaimIssuedAt:         int64(100000),
				consts.ClaimClientIdentifier: "aclient",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			aud, introspection := tc.have.ToMap()

			assert.Equal(t, tc.expectedaud, aud)
			assert.Equal(t, tc.expected, introspection)
		})
	}
}
