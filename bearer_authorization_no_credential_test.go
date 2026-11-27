// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/testing/mock"
	"authelia.com/provider/oauth2/x/errorsx"
)

func TestProtectedResourceRequestWithoutCredential(t *testing.T) {
	const (
		bare     = "Bearer"
		bareDPoP = `Bearer, DPoP algs="ES256"`
	)

	endpoints := []struct {
		name      string
		do        func(t *testing.T, dpop bool, header string) *httptest.ResponseRecorder
		bareDPoP  string
		challenge string
		body      string
	}{
		{name: "UserInfo", do: doUserinfoWithoutCredential, bareDPoP: bareDPoP, challenge: `error="invalid_token"`, body: `"error":"invalid_token"`},
		{name: "SSFStream", do: doSSFStreamWithoutCredential, bareDPoP: bareDPoP, challenge: `error="invalid_token"`, body: `"error":"invalid_token"`},
		{name: "SSFPoll", do: doSSFPollWithoutCredential, bareDPoP: bareDPoP, challenge: `error="invalid_token"`, body: `"err":"authentication_failed"`},
		{name: "Introspection", do: doIntrospectionWithoutCredential, bareDPoP: bareDPoP, challenge: `error="invalid_token"`, body: `"error":"invalid_token"`},
		{name: "ClientRegistration", do: doClientRegistrationWithoutCredential, bareDPoP: bareDPoP, challenge: `error="invalid_token"`, body: `"error":"invalid_token"`},
		{name: "ClientConfiguration", do: doClientConfigurationWithoutCredential, bareDPoP: bare, challenge: bare, body: `"error":"request_unauthorized"`},
	}

	testCases := []struct {
		name   string
		dpop   bool
		header string
	}{
		{name: "ShouldOmitErrorInformationWithoutAHeader"},
		{name: "ShouldOmitErrorInformationForTheBasicScheme", header: "Basic cnM6c2VjcmV0"},
		{name: "ShouldOmitErrorInformationForTheDPoPSchemeWhileDisabled", header: "DPoP tok-a"},
		{name: "ShouldOmitErrorInformationForTheBearerSchemeWithoutAToken", header: "Bearer"},
		{name: "ShouldOmitErrorInformationForAnEmptyBearerToken", header: "Bearer "},
		{name: "ShouldOmitErrorInformationWithoutAHeaderWhileDPoPIsEnabled", dpop: true},
		{name: "ShouldOmitErrorInformationForTheBasicSchemeWhileDPoPIsEnabled", dpop: true, header: "Basic cnM6c2VjcmV0"},
		{name: "ShouldOmitErrorInformationForAnEmptyDPoPToken", dpop: true, header: "DPoP "},
	}

	for _, ec := range endpoints {
		t.Run(ec.name, func(t *testing.T) {
			// RFC 6750 Section 3.1.
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					rw := ec.do(t, tc.dpop, tc.header)

					expected := bare
					if tc.dpop {
						expected = ec.bareDPoP
					}

					assert.Equal(t, http.StatusUnauthorized, rw.Code)
					assert.Equal(t, []string{expected}, rw.Header().Values(consts.HeaderWWWAuthenticate))
					assert.Equal(t, consts.CacheControlNoStore, rw.Header().Get(consts.HeaderCacheControl))
					assert.Equal(t, consts.PragmaNoCache, rw.Header().Get(consts.HeaderPragma))
					assert.Empty(t, rw.Header().Values(consts.HeaderContentType))
					assert.Empty(t, rw.Body.Bytes())
				})
			}

			t.Run("ShouldKeepErrorInformationForAnInvalidToken", func(t *testing.T) {
				rw := ec.do(t, false, "Bearer tok-a")

				assert.Equal(t, http.StatusUnauthorized, rw.Code)
				assert.Contains(t, rw.Header().Get(consts.HeaderWWWAuthenticate), ec.challenge)
				assert.Equal(t, consts.ContentTypeApplicationJSON, rw.Header().Get(consts.HeaderContentType))
				assert.Contains(t, rw.Body.String(), ec.body)
			})
		})
	}
}

func TestWriteErrorWithoutRequestShouldKeepErrorInformation(t *testing.T) {
	provider := &Fosite{Config: new(Config)}

	testCases := []struct {
		name      string
		write     func(rw http.ResponseWriter, err error)
		challenge string
	}{
		{
			name: "Introspection",
			write: func(rw http.ResponseWriter, err error) {
				provider.WriteIntrospectionError(context.Background(), rw, nil, err)
			},
			challenge: `error="invalid_token"`,
		},
		{
			name: "ClientRegistration",
			write: func(rw http.ResponseWriter, err error) {
				provider.WriteRFC7591ClientRegistrationError(context.Background(), rw, nil, nil, err)
			},
			challenge: `error="invalid_token"`,
		},
		{
			name: "ClientConfiguration",
			write: func(rw http.ResponseWriter, err error) {
				provider.WriteRFC7592ClientConfigurationError(context.Background(), rw, nil, nil, err)
			},
			challenge: "Bearer",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rw := httptest.NewRecorder()
			tc.write(rw, errorsx.WithStack(ErrInvalidToken))

			assert.Equal(t, http.StatusUnauthorized, rw.Code)
			assert.Contains(t, rw.Header().Get(consts.HeaderWWWAuthenticate), tc.challenge)
			assert.Equal(t, consts.ContentTypeApplicationJSON, rw.Header().Get(consts.HeaderContentType))
			assert.Contains(t, rw.Body.String(), `"error":"invalid_token"`)
		})
	}
}

func TestWriteErrorShouldIgnoreTheRequestInTheContext(t *testing.T) {
	provider := &Fosite{Config: new(Config)}

	ctx := context.WithValue(context.Background(), RequestContextKey, withoutCredentialRequest(http.MethodGet, "https://auth.example.com/register/abc", "", ""))

	testCases := []struct {
		name  string
		write func(rw http.ResponseWriter, err error)
	}{
		{name: "Introspection", write: func(rw http.ResponseWriter, err error) { provider.WriteIntrospectionError(ctx, rw, nil, err) }},
		{name: "ClientRegistration", write: func(rw http.ResponseWriter, err error) {
			provider.WriteRFC7591ClientRegistrationError(ctx, rw, nil, nil, err)
		}},
		{name: "ClientConfiguration", write: func(rw http.ResponseWriter, err error) {
			provider.WriteRFC7592ClientConfigurationError(ctx, rw, nil, nil, err)
		}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rw := httptest.NewRecorder()
			tc.write(rw, errorsx.WithStack(ErrInvalidToken))

			assert.Equal(t, http.StatusUnauthorized, rw.Code)
			assert.Contains(t, rw.Body.String(), `"error":"invalid_token"`)
		})
	}
}

func newRejectingIntrospector(t *testing.T) TokenIntrospector {
	t.Helper()

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	introspector := mock.NewMockTokenIntrospector(ctrl)
	introspector.EXPECT().IntrospectToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Return(TokenUse(""), errorsx.WithStack(ErrTokenExpired)).AnyTimes()

	return introspector
}

func withoutCredentialRequest(method, target, body, header string) (r *http.Request) {
	r = httptest.NewRequest(method, target, strings.NewReader(body))

	if header != "" {
		r.Header.Set(consts.HeaderAuthorization, header)
	}

	return r
}

func doUserinfoWithoutCredential(t *testing.T, dpop bool, header string) (rw *httptest.ResponseRecorder) {
	provider, _ := newUserinfoProvider(newRejectingIntrospector(t), nil)

	config := provider.Config.(*Config)
	config.DPoPEnabled, config.DPoPAllowedJWSAlgorithms = dpop, []string{"ES256"}

	requester, err := provider.NewUserinfoRequest(context.Background(), withoutCredentialRequest(http.MethodGet, userinfoURL, "", header), &DefaultSession{})
	require.Error(t, err)

	rw = httptest.NewRecorder()
	provider.WriteUserinfoError(context.Background(), rw, requester, err)

	return rw
}

func newSSFProviderWithoutCredential(t *testing.T, dpop bool) (provider *Fosite) {
	h := newSSFHandlerHarness(t, nil)

	config := h.provider.Config.(*Config)
	config.TokenIntrospectionHandlers = TokenIntrospectionHandlers{newRejectingIntrospector(t)}
	config.DPoPEnabled, config.DPoPAllowedJWSAlgorithms = dpop, []string{"ES256"}

	return h.provider
}

func doSSFStreamWithoutCredential(t *testing.T, dpop bool, header string) (rw *httptest.ResponseRecorder) {
	provider := newSSFProviderWithoutCredential(t, dpop)

	r := withoutCredentialRequest(http.MethodGet, ssfHandlerURL, "", header)

	_, err := provider.NewSSFStreamRequest(context.Background(), r, &DefaultSession{})
	require.Error(t, err)

	rw = httptest.NewRecorder()
	provider.WriteSSFError(context.Background(), rw, r, err)

	return rw
}

func doSSFPollWithoutCredential(t *testing.T, dpop bool, header string) (rw *httptest.ResponseRecorder) {
	provider := newSSFProviderWithoutCredential(t, dpop)

	r := withoutCredentialRequest(http.MethodPost, ssfPollURL, `{}`, header)
	r.Header.Set(consts.HeaderContentType, consts.ContentTypeApplicationJSON)

	_, err := provider.NewSSFPollRequest(context.Background(), r, &DefaultSession{}, "stream")
	require.Error(t, err)

	rw = httptest.NewRecorder()
	provider.WriteSSFPollError(context.Background(), rw, r, err)

	return rw
}

func doIntrospectionWithoutCredential(t *testing.T, dpop bool, header string) (rw *httptest.ResponseRecorder) {
	provider := &Fosite{Config: &Config{
		IntrospectionEndpointClientAuthDisabled: true,
		DPoPEnabled:                             dpop,
		DPoPAllowedJWSAlgorithms:                []string{"ES256"},
		TokenIntrospectionHandlers:              TokenIntrospectionHandlers{newRejectingIntrospector(t)},
	}}

	r := withoutCredentialRequest(http.MethodPost, "https://auth.example.com/introspect", url.Values{consts.FormParameterToken: {"introspected"}}.Encode(), header)
	r.Header.Set(consts.HeaderContentType, consts.ContentTypeApplicationURLEncodedForm)

	_, err := provider.NewIntrospectionRequest(context.Background(), r, &DefaultSession{})
	require.Error(t, err)

	rw = httptest.NewRecorder()
	provider.WriteIntrospectionError(context.Background(), rw, r, err)

	return rw
}

func doClientRegistrationWithoutCredential(_ *testing.T, dpop bool, header string) (rw *httptest.ResponseRecorder) {
	provider := &Fosite{Config: &Config{DPoPEnabled: dpop, DPoPAllowedJWSAlgorithms: []string{"ES256"}}}

	r := withoutCredentialRequest(http.MethodPost, "https://auth.example.com/register", `{}`, header)

	rw = httptest.NewRecorder()
	provider.WriteRFC7591ClientRegistrationError(context.Background(), rw, r, nil, errorsx.WithStack(ErrInvalidToken))

	return rw
}

func doClientConfigurationWithoutCredential(_ *testing.T, dpop bool, header string) (rw *httptest.ResponseRecorder) {
	provider := &Fosite{Config: &Config{DPoPEnabled: dpop, DPoPAllowedJWSAlgorithms: []string{"ES256"}}}

	r := withoutCredentialRequest(http.MethodGet, "https://auth.example.com/register/abc", "", header)

	err := ErrInvalidToken
	if header == "Bearer tok-a" {
		err = ErrRequestUnauthorized
	}

	rw = httptest.NewRecorder()
	provider.WriteRFC7592ClientConfigurationError(context.Background(), rw, r, nil, errorsx.WithStack(err))

	return rw
}
