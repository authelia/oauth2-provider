// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/compose"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/testing/mock"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestIntrospectionResponseTokenUse(t *testing.T) {
	httpreq := &http.Request{
		Method: "POST",
		Header: http.Header{
			consts.HeaderAuthorization: []string{"bearer some-token"},
		},
		PostForm: url.Values{
			"token": []string{"introspect-token"},
		},
	}

	testCases := []struct {
		name        string
		setup       func(config *Config, validator *mock.MockTokenIntrospector, ctx gomock.Matcher)
		expectedTU  TokenUse
		expectedATT string
	}{
		{
			name: "ShouldIntrospectAccessToken",
			setup: func(config *Config, validator *mock.MockTokenIntrospector, ctx gomock.Matcher) {
				config.TokenIntrospectionHandlers = TokenIntrospectionHandlers{validator}
				validator.EXPECT().IntrospectToken(ctx, "some-token", gomock.Any(), gomock.Any(), gomock.Any()).Return(TokenUse(""), nil)
				validator.EXPECT().IntrospectToken(ctx, "introspect-token", gomock.Any(), gomock.Any(), gomock.Any()).Return(AccessToken, nil)
			},
			expectedATT: BearerAccessToken,
			expectedTU:  AccessToken,
		},
		{
			name: "ShouldIntrospectRefreshToken",
			setup: func(config *Config, validator *mock.MockTokenIntrospector, ctx gomock.Matcher) {
				config.TokenIntrospectionHandlers = TokenIntrospectionHandlers{validator}
				validator.EXPECT().IntrospectToken(ctx, "some-token", gomock.Any(), gomock.Any(), gomock.Any()).Return(TokenUse(""), nil)
				validator.EXPECT().IntrospectToken(ctx, "introspect-token", gomock.Any(), gomock.Any(), gomock.Any()).Return(RefreshToken, nil)
			},
			expectedATT: "",
			expectedTU:  RefreshToken,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			validator := mock.NewMockTokenIntrospector(ctrl)
			ctx := gomock.AssignableToTypeOf(context.WithValue(t.Context(), ContextKey("test"), nil))

			config := new(Config)
			provider := compose.ComposeAllEnabled(config, storage.NewExampleStore(), nil).(*Fosite)

			tc.setup(config, validator, ctx)
			res, err := provider.NewIntrospectionRequest(t.Context(), httpreq, &DefaultSession{})
			require.NoError(t, err)
			assert.Equal(t, tc.expectedATT, res.GetAccessTokenType())
			assert.Equal(t, tc.expectedTU, res.GetTokenUse())
		})
	}
}

func TestIntrospectionResponse(t *testing.T) {
	r := &IntrospectionResponse{
		AccessRequester: NewAccessRequest(nil),
		Active:          true,
	}

	assert.Equal(t, r.AccessRequester, r.GetAccessRequester())
	assert.Equal(t, r.Active, r.IsActive())
}

func TestNewIntrospectionRequest(t *testing.T) {
	newErr := errors.New("asdf")

	testCases := []struct {
		name     string
		setup    func(config *Config, validator *mock.MockTokenIntrospector, ctx gomock.Matcher) *http.Request
		err      string
		isActive bool
	}{
		{
			name: "ShouldFailEmptyRequest",
			setup: func(config *Config, validator *mock.MockTokenIntrospector, ctx gomock.Matcher) *http.Request {
				return &http.Request{
					Method: "POST",
					Header: http.Header{},
					Form:   url.Values{},
				}
			},
			err: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The POST body can not be empty.",
		},
		{
			name: "ShouldFailIntrospectionError",
			setup: func(config *Config, validator *mock.MockTokenIntrospector, ctx gomock.Matcher) *http.Request {
				config.TokenIntrospectionHandlers = TokenIntrospectionHandlers{validator}
				validator.EXPECT().IntrospectToken(ctx, "some-token", gomock.Any(), gomock.Any(), gomock.Any()).Return(TokenUse(""), nil)
				validator.EXPECT().IntrospectToken(ctx, "introspect-token", gomock.Any(), gomock.Any(), gomock.Any()).Return(TokenUse(""), newErr)
				return &http.Request{
					Method: "POST",
					Header: http.Header{
						consts.HeaderAuthorization: []string{"bearer some-token"},
					},
					PostForm: url.Values{
						"token": []string{"introspect-token"},
					},
				}
			},
			isActive: false,
			err:      "Token is inactive because it is malformed, expired or otherwise invalid. An introspection strategy indicated that the token is inactive. The error is unrecognizable asdf",
		},
		{
			name: "ShouldPass",
			setup: func(config *Config, validator *mock.MockTokenIntrospector, ctx gomock.Matcher) *http.Request {
				config.TokenIntrospectionHandlers = TokenIntrospectionHandlers{validator}
				validator.EXPECT().IntrospectToken(ctx, "some-token", gomock.Any(), gomock.Any(), gomock.Any()).Return(TokenUse(""), nil)
				validator.EXPECT().IntrospectToken(ctx, "introspect-token", gomock.Any(), gomock.Any(), gomock.Any()).Return(TokenUse(""), nil)
				return &http.Request{
					Method: "POST",
					Header: http.Header{
						consts.HeaderAuthorization: []string{"bearer some-token"},
					},
					PostForm: url.Values{
						"token": []string{"introspect-token"},
					},
				}
			},
			isActive: true,
		},
		{
			name: "ShouldPassWithBasicAuthIfUsernameAndPasswordEncoded",
			setup: func(config *Config, validator *mock.MockTokenIntrospector, ctx gomock.Matcher) *http.Request {
				config.TokenIntrospectionHandlers = TokenIntrospectionHandlers{validator}
				validator.EXPECT().IntrospectToken(ctx, "introspect-token", gomock.Any(), gomock.Any(), gomock.Any()).Return(TokenUse(""), nil)
				return &http.Request{
					Method: "POST",
					Header: http.Header{
						// Basic Authorization with username=encoded:client and password=encoded&password
						consts.HeaderAuthorization: []string{"Basic ZW5jb2RlZCUzQWNsaWVudDplbmNvZGVkJTI2cGFzc3dvcmQ="},
					},
					PostForm: url.Values{
						"token": []string{"introspect-token"},
					},
				}
			},
			isActive: true,
		},
		{
			name: "ShouldPassWithBasicAuthIfUsernameAndPasswordNotEncoded",
			setup: func(config *Config, validator *mock.MockTokenIntrospector, ctx gomock.Matcher) *http.Request {
				config.TokenIntrospectionHandlers = TokenIntrospectionHandlers{validator}
				validator.EXPECT().IntrospectToken(ctx, "introspect-token", gomock.Any(), gomock.Any(), gomock.Any()).Return(TokenUse(""), nil)
				return &http.Request{
					Method: "POST",
					Header: http.Header{
						// Basic Authorization with username=my-client and password=foobar
						consts.HeaderAuthorization: []string{"Basic bXktY2xpZW50OmZvb2Jhcg=="},
					},
					PostForm: url.Values{
						"token": []string{"introspect-token"},
					},
				}
			},
			isActive: true,
		},
		{
			name: "ShouldPassWithBasicAuthIfUsernameAndPasswordNotEncodedDuplicate",
			setup: func(config *Config, validator *mock.MockTokenIntrospector, ctx gomock.Matcher) *http.Request {
				config.TokenIntrospectionHandlers = TokenIntrospectionHandlers{validator}
				validator.EXPECT().IntrospectToken(ctx, "introspect-token", gomock.Any(), gomock.Any(), gomock.Any()).Return(TokenUse(""), nil)
				return &http.Request{
					Method: "POST",
					Header: http.Header{
						// Basic Authorization with username=my-client and password=foobar
						consts.HeaderAuthorization: []string{"Basic bXktY2xpZW50OmZvb2Jhcg=="},
					},
					PostForm: url.Values{
						"token": []string{"introspect-token"},
					},
				}
			},
			isActive: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			validator := mock.NewMockTokenIntrospector(ctrl)
			ctx := gomock.AssignableToTypeOf(context.WithValue(t.Context(), ContextKey("test"), nil))

			config := new(Config)
			f := compose.ComposeAllEnabled(config, storage.NewExampleStore(), nil).(*Fosite)

			httpreq := tc.setup(config, validator, ctx)
			res, err := f.NewIntrospectionRequest(t.Context(), httpreq, &DefaultSession{})

			if tc.err != "" {
				assert.EqualError(t, ErrorToDebugRFC6749Error(err), tc.err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.isActive, res.IsActive())
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
			name:        "ShouldDecodeInactive",
			have:        &IntrospectionResponse{},
			expectedaud: nil,
			expected:    map[string]any{consts.ClaimActive: false},
		},
		{
			name: "ShouldReturnActiveWithoutAccessRequester",
			have: &IntrospectionResponse{
				Active: true,
			},
			expectedaud: nil,
			expected:    map[string]any{consts.ClaimActive: true},
		},
		{
			name: "ShouldReturnActiveWithAccessRequester",
			have: &IntrospectionResponse{
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
			expectedaud: nil,
			expected: map[string]any{
				consts.ClaimActive:           true,
				consts.ClaimScope:            "openid profile",
				consts.ClaimAudience:         []string{"https://example.com", "aclient"},
				consts.ClaimIssuedAt:         int64(100000),
				consts.ClaimClientIdentifier: "aclient",
			},
		},
		{
			name: "ShouldReturnActiveWithAccessRequesterAndSession",
			have: &IntrospectionResponse{
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
			expectedaud: nil,
			expected: map[string]any{
				consts.ClaimActive:           true,
				consts.ClaimScope:            "openid profile",
				consts.ClaimAudience:         []string{"https://example.com", "aclient"},
				consts.ClaimIssuedAt:         int64(100000),
				consts.ClaimClientIdentifier: "aclient",
			},
		},
		{
			name: "ShouldReturnActiveWithAccessRequesterAndSessionWithIDTokenClaimsAndUsername",
			have: &IntrospectionResponse{
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
			expectedaud: []string{"rclient"},
			expected: map[string]any{
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
