// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestWriteRFC862DeviceAuthorizeResponse(t *testing.T) {
	testCases := []struct {
		name     string
		setup    func(provider *Fosite) *DeviceAuthorizeResponse
		expected map[string]any
		headers  http.Header
	}{
		{
			name: "ShouldWriteAllFieldsWhenSet",
			setup: func(provider *Fosite) *DeviceAuthorizeResponse {
				resp := &DeviceAuthorizeResponse{Header: http.Header{}, Extra: map[string]any{}}
				resp.SetUserCode("AAAA")
				resp.SetDeviceCode("BBBB")
				resp.SetInterval(int(
					provider.Config.GetRFC8628TokenPollingInterval(t.Context()).Truncate(jwt.TimePrecision).Seconds(),
				))
				resp.SetExpiresIn(int64(
					time.Now().Truncate(jwt.TimePrecision).Add(provider.Config.GetRFC8628CodeLifespan(t.Context())).Second(),
				))
				resp.SetVerificationURI(provider.Config.GetRFC8628UserVerificationURL(t.Context()))
				resp.SetVerificationURIComplete(
					provider.Config.GetRFC8628UserVerificationURL(t.Context()) + "?user_code=" + resp.GetUserCode(),
				)
				return resp
			},
			headers: http.Header{
				consts.HeaderContentType:  []string{consts.ContentTypeApplicationJSON},
				consts.HeaderCacheControl: []string{consts.CacheControlNoStore},
				consts.HeaderPragma:       []string{consts.PragmaNoCache},
			},
		},
		{
			name: "ShouldCopyCustomHeadersFromResponder",
			setup: func(provider *Fosite) *DeviceAuthorizeResponse {
				resp := &DeviceAuthorizeResponse{
					Header: http.Header{
						"X-Custom-Header": []string{"custom-value"},
					},
					Extra: map[string]any{},
				}
				resp.SetUserCode("CCCC")
				resp.SetDeviceCode("DDDD")
				resp.SetVerificationURI("https://auth.example.com")
				return resp
			},
			headers: http.Header{
				"X-Custom-Header":         []string{"custom-value"},
				consts.HeaderContentType:  []string{consts.ContentTypeApplicationJSON},
				consts.HeaderCacheControl: []string{consts.CacheControlNoStore},
				consts.HeaderPragma:       []string{consts.PragmaNoCache},
			},
		},
		{
			name: "ShouldNotAllowResponderHeaderToOverrideContentType",
			setup: func(provider *Fosite) *DeviceAuthorizeResponse {
				resp := &DeviceAuthorizeResponse{
					Header: http.Header{
						consts.HeaderContentType: []string{"text/plain"},
					},
					Extra: map[string]any{},
				}
				resp.SetUserCode("EEEE")
				resp.SetDeviceCode("FFFF")
				return resp
			},
			headers: http.Header{
				consts.HeaderContentType:  []string{consts.ContentTypeApplicationJSON},
				consts.HeaderCacheControl: []string{consts.CacheControlNoStore},
				consts.HeaderPragma:       []string{consts.PragmaNoCache},
			},
		},
		{
			name: "ShouldIncludeExtraClaimsInResponse",
			setup: func(provider *Fosite) *DeviceAuthorizeResponse {
				resp := &DeviceAuthorizeResponse{
					Header: http.Header{},
					Extra: map[string]any{
						"custom_field": "custom_value",
					},
				}
				resp.SetUserCode("GGGG")
				resp.SetDeviceCode("HHHH")
				return resp
			},
			headers: http.Header{
				consts.HeaderContentType:  []string{consts.ContentTypeApplicationJSON},
				consts.HeaderCacheControl: []string{consts.CacheControlNoStore},
				consts.HeaderPragma:       []string{consts.PragmaNoCache},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider := &Fosite{Config: &Config{
				RFC8628CodeLifespan:         time.Minute,
				RFC8628TokenPollingInterval: time.Minute,
				RFC8628UserVerificationURL:  "https://auth.example.com",
			}}

			rw := httptest.NewRecorder()
			ar := &DeviceAuthorizeRequest{}
			resp := tc.setup(provider)

			provider.WriteRFC862DeviceAuthorizeResponse(context.Background(), rw, ar, resp)

			assert.Equal(t, http.StatusOK, rw.Code)
			assert.Equal(t, tc.headers, rw.Header())

			actual := DeviceAuthorizeResponse{Extra: map[string]any{}}
			require.NoError(t, actual.FromJson(rw.Body))

			assert.Equal(t, resp.GetUserCode(), actual.UserCode)
			assert.Equal(t, resp.GetDeviceCode(), actual.DeviceCode)
			assert.Equal(t, resp.GetVerificationURI(), actual.VerificationURI)
			assert.Equal(t, resp.GetVerificationURIComplete(), actual.VerificationURIComplete)
			assert.Equal(t, resp.GetInterval(), actual.Interval)
			assert.Equal(t, resp.GetExpiresIn(), actual.ExpiresIn)
		})
	}
}

func TestWriteRFC862DeviceAuthorizeResponseMarshalError(t *testing.T) {
	testCases := []struct {
		name     string
		setup    func() *DeviceAuthorizeResponse
		contains string
	}{
		{
			name: "ShouldRespondInternalServerErrorWhenToMapNotMarshalable",
			setup: func() *DeviceAuthorizeResponse {
				return &DeviceAuthorizeResponse{
					Header: http.Header{},
					Extra: map[string]any{
						// channels cannot be marshaled to JSON
						"bad": make(chan int),
					},
				}
			},
			contains: "json: unsupported type",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider := &Fosite{Config: &Config{}}
			rw := httptest.NewRecorder()
			ar := &DeviceAuthorizeRequest{}

			provider.WriteRFC862DeviceAuthorizeResponse(context.Background(), rw, ar, tc.setup())

			assert.Equal(t, http.StatusInternalServerError, rw.Code)
			assert.Contains(t, rw.Body.String(), tc.contains)
		})
	}
}

func TestWriteRFC862DeviceAuthorizeResponseBody(t *testing.T) {
	testCases := []struct {
		name     string
		setup    func() *DeviceAuthorizeResponse
		expected map[string]any
	}{
		{
			name: "ShouldEmitAllStandardClaims",
			setup: func() *DeviceAuthorizeResponse {
				resp := &DeviceAuthorizeResponse{Header: http.Header{}, Extra: map[string]any{}}
				resp.SetUserCode("USER-CODE")
				resp.SetDeviceCode("DEVICE-CODE")
				resp.SetVerificationURI("https://auth.example.com/device")
				resp.SetVerificationURIComplete("https://auth.example.com/device?user_code=USER-CODE")
				resp.SetExpiresIn(600)
				resp.SetInterval(5)
				return resp
			},
			expected: map[string]any{
				consts.DeviceCodeResponseDeviceCode:              "DEVICE-CODE",
				consts.DeviceCodeResponseUserCode:                "USER-CODE",
				consts.DeviceCodeResponseVerificationURI:         "https://auth.example.com/device",
				consts.DeviceCodeResponseVerificationURIComplete: "https://auth.example.com/device?user_code=USER-CODE",
				consts.DeviceCodeResponseExpiresIn:               float64(600),
				consts.DeviceCodeResponseInterval:                float64(5),
			},
		},
		{
			// ToMap unconditionally writes every standard claim into the Extra map. Because
			// map[string]any does not honor JSON's omitempty struct tag, zero-valued optional
			// fields (interval, verification_uri_complete) are also emitted.
			name: "ShouldEmitAllStandardClaimsIncludingZeroValuedOptionals",
			setup: func() *DeviceAuthorizeResponse {
				resp := &DeviceAuthorizeResponse{Header: http.Header{}, Extra: map[string]any{}}
				resp.SetUserCode("USER")
				resp.SetDeviceCode("DEVICE")
				resp.SetVerificationURI("https://auth.example.com/device")
				resp.SetExpiresIn(300)
				return resp
			},
			expected: map[string]any{
				consts.DeviceCodeResponseDeviceCode:              "DEVICE",
				consts.DeviceCodeResponseUserCode:                "USER",
				consts.DeviceCodeResponseVerificationURI:         "https://auth.example.com/device",
				consts.DeviceCodeResponseVerificationURIComplete: "",
				consts.DeviceCodeResponseExpiresIn:               float64(300),
				consts.DeviceCodeResponseInterval:                float64(0),
			},
		},
		{
			name: "ShouldPreserveExtraFieldsAlongsideStandardClaims",
			setup: func() *DeviceAuthorizeResponse {
				resp := &DeviceAuthorizeResponse{
					Header: http.Header{},
					Extra: map[string]any{
						"foo": "bar",
					},
				}
				resp.SetUserCode("X")
				resp.SetDeviceCode("Y")
				resp.SetVerificationURI("https://auth.example.com/device")
				resp.SetExpiresIn(100)
				return resp
			},
			expected: map[string]any{
				consts.DeviceCodeResponseDeviceCode:              "Y",
				consts.DeviceCodeResponseUserCode:                "X",
				consts.DeviceCodeResponseVerificationURI:         "https://auth.example.com/device",
				consts.DeviceCodeResponseVerificationURIComplete: "",
				consts.DeviceCodeResponseExpiresIn:               float64(100),
				consts.DeviceCodeResponseInterval:                float64(0),
				"foo":                                            "bar",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider := &Fosite{Config: &Config{}}
			rw := httptest.NewRecorder()
			ar := &DeviceAuthorizeRequest{}

			provider.WriteRFC862DeviceAuthorizeResponse(context.Background(), rw, ar, tc.setup())

			actual := map[string]any{}
			require.NoError(t, json.NewDecoder(rw.Body).Decode(&actual))

			for key, want := range tc.expected {
				assert.Equal(t, want, actual[key], "key=%s", key)
			}

			// Assert no extra/forbidden keys are emitted.
			for key := range actual {
				if _, ok := tc.expected[key]; !ok {
					assert.Failf(t, "unexpected key present", "key=%s value=%v", key, actual[key])
				}
			}
		})
	}
}
