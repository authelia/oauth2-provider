// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"net/http"
	"net/http/httptest"
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
		Method: http.MethodPost,
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

			config := &Config{RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b")}
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
					Method: http.MethodPost,
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
					Method: http.MethodPost,
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
					Method: http.MethodPost,
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
					Method: http.MethodPost,
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
					Method: http.MethodPost,
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
					Method: http.MethodPost,
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

			config := &Config{RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b")}
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

func TestNewIntrospectionRequestAllowedAudiences(t *testing.T) {
	testCases := []struct {
		name     string
		allowed  []string
		audience []string
		resource []string
		err      string
	}{
		{
			name:     "ShouldPassWithoutConfiguredAudiencesGivenNoTokenAudience",
			allowed:  nil,
			audience: nil,
			resource: nil,
		},
		{
			name:     "ShouldPassWithoutConfiguredAudiencesGivenTokenAudience",
			allowed:  nil,
			audience: []string{"https://app.example.com"},
			resource: nil,
		},
		{
			name:     "ShouldPassWithEmptyConfiguredAudiences",
			allowed:  []string{},
			audience: []string{"https://app.example.com"},
			resource: nil,
		},
		{
			name:     "ShouldPassWithMatchingAudience",
			allowed:  []string{"https://introspection.example.com"},
			audience: []string{"https://introspection.example.com"},
			resource: nil,
		},
		{
			name:     "ShouldPassWithMatchingResource",
			allowed:  []string{"https://introspection.example.com"},
			audience: nil,
			resource: []string{"https://introspection.example.com"},
		},
		{
			name:     "ShouldPassWithOneMatchingAudienceOfSeveral",
			allowed:  []string{"https://introspection.example.com"},
			audience: []string{"https://app.example.com", "https://introspection.example.com"},
			resource: nil,
		},
		{
			name:     "ShouldPassWithOneMatchingConfiguredAudienceOfSeveral",
			allowed:  []string{"https://other.example.com", "https://introspection.example.com"},
			audience: []string{"https://introspection.example.com"},
			resource: nil,
		},
		{
			name:     "ShouldFailWithoutTokenAudience",
			allowed:  []string{"https://introspection.example.com"},
			audience: nil,
			resource: nil,
			err:      "The request could not be authorized. The Access Token used to authenticate the request does not have an audience which is permitted at the introspection endpoint. The Access Token used to authenticate the request was expected to have an audience which matches one of the values 'https://introspection.example.com' but it does not have an audience.",
		},
		{
			name:     "ShouldFailWithMismatchedAudience",
			allowed:  []string{"https://introspection.example.com"},
			audience: []string{"https://app.example.com"},
			resource: []string{"https://api.example.com"},
			err:      "The request could not be authorized. The Access Token used to authenticate the request does not have an audience which is permitted at the introspection endpoint. The Access Token used to authenticate the request was expected to have an audience which matches one of the values 'https://introspection.example.com' but the audience had the values 'https://app.example.com', 'https://api.example.com'.",
		},
		{
			name:     "ShouldFailWithPartiallyMatchingAudiencePrefix",
			allowed:  []string{"https://introspection.example.com"},
			audience: []string{"https://introspection.example.com.evil.com"},
			resource: nil,
			err:      "The request could not be authorized. The Access Token used to authenticate the request does not have an audience which is permitted at the introspection endpoint. The Access Token used to authenticate the request was expected to have an audience which matches one of the values 'https://introspection.example.com' but the audience had the values 'https://introspection.example.com.evil.com'.",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			validator := mock.NewMockTokenIntrospector(ctrl)
			ctx := gomock.AssignableToTypeOf(context.WithValue(t.Context(), ContextKey("test"), nil))

			config := &Config{AllowedIntrospectionAudiences: tc.allowed, RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b")}

			f := compose.ComposeAllEnabled(config, storage.NewExampleStore(), nil).(*Fosite)

			config.TokenIntrospectionHandlers = TokenIntrospectionHandlers{validator}

			validator.EXPECT().
				IntrospectToken(ctx, "some-token", gomock.Any(), gomock.Any(), gomock.Any()).
				DoAndReturn(func(_ context.Context, _ string, _ TokenUse, requester AccessRequester, _ []string) (TokenUse, error) {
					for _, aud := range tc.audience {
						requester.GrantAudience(aud)
					}

					for _, resource := range tc.resource {
						requester.GrantResource(resource)
					}

					return AccessToken, nil
				})

			// The introspected token is only reached when the authenticating token passes the audience check.
			validator.EXPECT().
				IntrospectToken(ctx, "introspect-token", gomock.Any(), gomock.Any(), gomock.Any()).
				Return(AccessToken, nil).
				AnyTimes()

			httpreq := &http.Request{
				Method: http.MethodPost,
				Header: http.Header{
					consts.HeaderAuthorization: []string{"bearer some-token"},
				},
				PostForm: url.Values{
					"token": []string{"introspect-token"},
				},
			}

			res, err := f.NewIntrospectionRequest(t.Context(), httpreq, &DefaultSession{})

			if tc.err == "" {
				require.NoError(t, err)
				assert.True(t, res.IsActive())

				return
			}

			assert.EqualError(t, ErrorToDebugRFC6749Error(err), tc.err)
			assert.False(t, res.IsActive())

			require.True(t, errors.Is(err, ErrRequestUnauthorized))

			rfc := ErrorToRFC6749Error(err)

			assert.Equal(t, http.StatusUnauthorized, rfc.CodeField)

			// The failure must be written out as an error rather than masked as an inactive token response.
			rw := httptest.NewRecorder()

			f.WriteIntrospectionError(t.Context(), rw, err)

			assert.Equal(t, http.StatusUnauthorized, rw.Code)
			assert.JSONEq(t, `{"error":"request_unauthorized","error_description":"The request could not be authorized. The Access Token used to authenticate the request does not have an audience which is permitted at the introspection endpoint."}`, rw.Body.String())
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
