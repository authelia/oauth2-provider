// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/testing/mock"
)

func TestWriteAuthorizeResponse(t *testing.T) {
	testCases := []struct {
		name   string
		setup  func(t *testing.T, rw *mock.MockResponseWriter, requester *mock.MockAuthorizeRequester, responder *mock.MockAuthorizeResponder, header http.Header)
		expect func(t *testing.T, rw *mock.MockResponseWriter, requester *mock.MockAuthorizeRequester, responder *mock.MockAuthorizeResponder, header http.Header)
	}{
		{
			name: "ShouldWriteResponseModeDefault",
			setup: func(t *testing.T, rw *mock.MockResponseWriter, requester *mock.MockAuthorizeRequester, responder *mock.MockAuthorizeResponder, header http.Header) {
				redir, _ := url.Parse("https://foobar.com/?foo=bar")
				requester.EXPECT().GetRedirectURI().Return(redir)
				requester.EXPECT().GetResponseMode().Return(ResponseModeDefault).Times(2)
				responder.EXPECT().GetParameters().Return(url.Values{})
				responder.EXPECT().GetHeader().Return(http.Header{})

				rw.EXPECT().Header().Return(header).Times(2)
				rw.EXPECT().WriteHeader(http.StatusSeeOther)
			},
			expect: func(t *testing.T, rw *mock.MockResponseWriter, requester *mock.MockAuthorizeRequester, responder *mock.MockAuthorizeResponder, header http.Header) {
				assert.Equal(t, http.Header{
					consts.HeaderLocation:     []string{"https://foobar.com/?foo=bar"},
					consts.HeaderCacheControl: []string{consts.CacheControlNoStore},
					consts.HeaderPragma:       []string{consts.PragmaNoCache},
				}, header)
			},
		},
		{
			name: "ShouldWriteResponseModeFragment",
			setup: func(t *testing.T, rw *mock.MockResponseWriter, requester *mock.MockAuthorizeRequester, responder *mock.MockAuthorizeResponder, header http.Header) {
				redir, _ := url.Parse("https://foobar.com/?foo=bar")
				requester.EXPECT().GetRedirectURI().Return(redir)
				requester.EXPECT().GetResponseMode().Return(ResponseModeFragment).Times(2)
				responder.EXPECT().GetParameters().Return(url.Values{"bar": {"baz"}})
				responder.EXPECT().GetHeader().Return(http.Header{})

				rw.EXPECT().Header().Return(header).Times(2)
				rw.EXPECT().WriteHeader(http.StatusSeeOther)
			},
			expect: func(t *testing.T, rw *mock.MockResponseWriter, requester *mock.MockAuthorizeRequester, responder *mock.MockAuthorizeResponder, header http.Header) {
				assert.Equal(t, http.Header{
					consts.HeaderLocation:     []string{"https://foobar.com/?foo=bar#bar=baz"},
					consts.HeaderCacheControl: []string{consts.CacheControlNoStore},
					consts.HeaderPragma:       []string{consts.PragmaNoCache},
				}, header)
			},
		},
		{
			name: "ShouldWriteResponseModeQuery",
			setup: func(t *testing.T, rw *mock.MockResponseWriter, requester *mock.MockAuthorizeRequester, responder *mock.MockAuthorizeResponder, header http.Header) {
				redir, _ := url.Parse("https://foobar.com/?foo=bar")
				requester.EXPECT().GetRedirectURI().Return(redir)
				requester.EXPECT().GetResponseMode().Return(ResponseModeQuery).Times(2)
				responder.EXPECT().GetParameters().Return(url.Values{"bar": {"baz"}})
				responder.EXPECT().GetHeader().Return(http.Header{})

				rw.EXPECT().Header().Return(header).Times(2)
				rw.EXPECT().WriteHeader(http.StatusSeeOther)
			},
			expect: func(t *testing.T, rw *mock.MockResponseWriter, requester *mock.MockAuthorizeRequester, responder *mock.MockAuthorizeResponder, header http.Header) {
				expectedUrl, _ := url.Parse("https://foobar.com/?foo=bar&bar=baz")
				actualUrl, err := url.Parse(header.Get(consts.HeaderLocation))
				assert.Nil(t, err)
				assert.Equal(t, expectedUrl.Query(), actualUrl.Query())
				assert.Equal(t, consts.PragmaNoCache, header.Get(consts.HeaderPragma))
				assert.Equal(t, consts.CacheControlNoStore, header.Get(consts.HeaderCacheControl))
			},
		},
		{
			name: "ShouldWriteResponseModeFragmentWithCustomHeaders",
			setup: func(t *testing.T, rw *mock.MockResponseWriter, requester *mock.MockAuthorizeRequester, responder *mock.MockAuthorizeResponder, header http.Header) {
				redir, _ := url.Parse("https://foobar.com/?foo=bar")
				requester.EXPECT().GetRedirectURI().Return(redir)
				requester.EXPECT().GetResponseMode().Return(ResponseModeFragment).Times(2)
				responder.EXPECT().GetParameters().Return(url.Values{"bar": {"b+az ab"}})
				responder.EXPECT().GetHeader().Return(http.Header{"X-Bar": {"baz"}})

				rw.EXPECT().Header().Return(header).Times(2)
				rw.EXPECT().WriteHeader(http.StatusSeeOther)
			},
			expect: func(t *testing.T, rw *mock.MockResponseWriter, requester *mock.MockAuthorizeRequester, responder *mock.MockAuthorizeResponder, header http.Header) {
				assert.Equal(t, http.Header{
					"X-Bar":                   {"baz"},
					consts.HeaderLocation:     {"https://foobar.com/?foo=bar#bar=b%2Baz+ab"},
					consts.HeaderCacheControl: []string{consts.CacheControlNoStore},
					consts.HeaderPragma:       []string{consts.PragmaNoCache},
				}, header)
			},
		},
		{
			name: "ShouldWriteResponseModeQueryWithCustomHeaders",
			setup: func(t *testing.T, rw *mock.MockResponseWriter, requester *mock.MockAuthorizeRequester, responder *mock.MockAuthorizeResponder, header http.Header) {
				redir, _ := url.Parse("https://foobar.com/?foo=bar")
				requester.EXPECT().GetRedirectURI().Return(redir)
				requester.EXPECT().GetResponseMode().Return(ResponseModeQuery).Times(2)
				responder.EXPECT().GetParameters().Return(url.Values{"bar": {"b+az"}, consts.FormParameterScope: {"a b"}})
				responder.EXPECT().GetHeader().Return(http.Header{"X-Bar": {"baz"}})

				rw.EXPECT().Header().Return(header).Times(2)
				rw.EXPECT().WriteHeader(http.StatusSeeOther)
			},
			expect: func(t *testing.T, rw *mock.MockResponseWriter, requester *mock.MockAuthorizeRequester, responder *mock.MockAuthorizeResponder, header http.Header) {
				expectedUrl, err := url.Parse("https://foobar.com/?foo=bar&bar=b%2Baz&scope=a+b")
				assert.Nil(t, err)
				actualUrl, err := url.Parse(header.Get(consts.HeaderLocation))
				assert.Nil(t, err)
				assert.Equal(t, expectedUrl.Query(), actualUrl.Query())
				assert.Equal(t, consts.PragmaNoCache, header.Get(consts.HeaderPragma))
				assert.Equal(t, consts.CacheControlNoStore, header.Get(consts.HeaderCacheControl))
				assert.Equal(t, "baz", header.Get("X-Bar"))
			},
		},
		{
			name: "ShouldWriteResponseModeFragmentWithCustomHeadersAndSpecialChars",
			setup: func(t *testing.T, rw *mock.MockResponseWriter, requester *mock.MockAuthorizeRequester, responder *mock.MockAuthorizeResponder, header http.Header) {
				redir, _ := url.Parse("https://foobar.com/?foo=bar")
				requester.EXPECT().GetRedirectURI().Return(redir)
				requester.EXPECT().GetResponseMode().Return(ResponseModeFragment).Times(2)
				responder.EXPECT().GetParameters().Return(url.Values{consts.FormParameterScope: {"api:*"}})
				responder.EXPECT().GetHeader().Return(http.Header{"X-Bar": {"baz"}})

				rw.EXPECT().Header().Return(header).Times(2)
				rw.EXPECT().WriteHeader(http.StatusSeeOther)
			},
			expect: func(t *testing.T, rw *mock.MockResponseWriter, requester *mock.MockAuthorizeRequester, responder *mock.MockAuthorizeResponder, header http.Header) {
				assert.Equal(t, http.Header{
					"X-Bar":                   {"baz"},
					consts.HeaderLocation:     {"https://foobar.com/?foo=bar#scope=api%3A%2A"},
					consts.HeaderCacheControl: []string{consts.CacheControlNoStore},
					consts.HeaderPragma:       []string{consts.PragmaNoCache},
				}, header)
			},
		},
		{
			name: "ShouldWriteResponseModeFragmentWithCustomParameters",
			setup: func(t *testing.T, rw *mock.MockResponseWriter, requester *mock.MockAuthorizeRequester, responder *mock.MockAuthorizeResponder, header http.Header) {
				redir, _ := url.Parse("https://foobar.com/?foo=bar#bar=baz")
				requester.EXPECT().GetRedirectURI().Return(redir)
				requester.EXPECT().GetResponseMode().Return(ResponseModeFragment).Times(2)
				responder.EXPECT().GetParameters().Return(url.Values{"qux": {"quux"}})
				responder.EXPECT().GetHeader().Return(http.Header{})

				rw.EXPECT().Header().Return(header).Times(2)
				rw.EXPECT().WriteHeader(http.StatusSeeOther)
			},
			expect: func(t *testing.T, rw *mock.MockResponseWriter, requester *mock.MockAuthorizeRequester, responder *mock.MockAuthorizeResponder, header http.Header) {
				assert.Equal(t, http.Header{
					consts.HeaderLocation:     {"https://foobar.com/?foo=bar#qux=quux"},
					consts.HeaderCacheControl: []string{consts.CacheControlNoStore},
					consts.HeaderPragma:       []string{consts.PragmaNoCache},
				}, header)
			},
		},
		{
			name: "ShouldWriteResponseModeFragmentWithEncodedState",
			setup: func(t *testing.T, rw *mock.MockResponseWriter, requester *mock.MockAuthorizeRequester, responder *mock.MockAuthorizeResponder, header http.Header) {
				redir, _ := url.Parse("https://foobar.com/?foo=bar")
				requester.EXPECT().GetRedirectURI().Return(redir)
				requester.EXPECT().GetResponseMode().Return(ResponseModeFragment).Times(2)
				responder.EXPECT().GetParameters().Return(url.Values{consts.FormParameterState: {"{\"a\":\"b=c&d=e\"}"}})
				responder.EXPECT().GetHeader().Return(http.Header{})

				rw.EXPECT().Header().Return(header).Times(2)
				rw.EXPECT().WriteHeader(http.StatusSeeOther)
			},
			expect: func(t *testing.T, rw *mock.MockResponseWriter, requester *mock.MockAuthorizeRequester, responder *mock.MockAuthorizeResponder, header http.Header) {
				assert.Equal(t, http.Header{
					consts.HeaderLocation:     {"https://foobar.com/?foo=bar#state=%7B%22a%22%3A%22b%3Dc%26d%3De%22%7D"},
					consts.HeaderCacheControl: []string{consts.CacheControlNoStore},
					consts.HeaderPragma:       []string{consts.PragmaNoCache},
				}, header)
			},
		},
		{
			name: "ShouldWriteResponseModeFormPostWithValues",
			setup: func(t *testing.T, rw *mock.MockResponseWriter, requester *mock.MockAuthorizeRequester, responder *mock.MockAuthorizeResponder, header http.Header) {
				redir, _ := url.Parse("https://foobar.com/?foo=bar")
				requester.EXPECT().GetRedirectURI().Return(redir)
				requester.EXPECT().GetResponseMode().Return(ResponseModeFormPost).Times(2)
				responder.EXPECT().GetHeader().Return(http.Header{"X-Bar": {"baz"}})
				responder.EXPECT().GetParameters().Return(url.Values{consts.FormParameterAuthorizationCode: {"poz65kqoneu"}, consts.FormParameterState: {"qm6dnsrn"}})

				rw.EXPECT().Header().Return(header).AnyTimes()
				rw.EXPECT().Write(gomock.Any()).AnyTimes()
			},
			expect: func(t *testing.T, rw *mock.MockResponseWriter, requester *mock.MockAuthorizeRequester, responder *mock.MockAuthorizeResponder, header http.Header) {
				assert.Equal(t, consts.ContentTypeTextHTML, header.Get(consts.HeaderContentType))
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider := &Fosite{Config: new(Config)}
			ctrl := gomock.NewController(t)

			rw := mock.NewMockResponseWriter(ctrl)
			requester := mock.NewMockAuthorizeRequester(ctrl)
			responder := mock.NewMockAuthorizeResponder(ctrl)

			defer ctrl.Finish()

			header := http.Header{}

			tc.setup(t, rw, requester, responder, header)
			provider.WriteAuthorizeResponse(context.TODO(), rw, requester, responder)
			tc.expect(t, rw, requester, responder, header)
		})
	}
}
