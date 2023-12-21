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
	. "authelia.com/provider/oauth2/internal"
	"authelia.com/provider/oauth2/internal/consts"
)

func TestWriteAuthorizeResponse(t *testing.T) {
	provider := &Fosite{Config: new(Config)}
	header := http.Header{}
	ctrl := gomock.NewController(t)
	rw := NewMockResponseWriter(ctrl)
	ar := NewMockAuthorizeRequester(ctrl)
	resp := NewMockAuthorizeResponder(ctrl)
	defer ctrl.Finish()

	for k, c := range []struct {
		setup  func()
		expect func()
	}{
		{
			setup: func() {
				redir, _ := url.Parse("https://foobar.com/?foo=bar")
				ar.EXPECT().GetRedirectURI().Return(redir)
				ar.EXPECT().GetResponseMode().Return(ResponseModeDefault)
				resp.EXPECT().GetParameters().Return(url.Values{})
				resp.EXPECT().GetHeader().Return(http.Header{})

				rw.EXPECT().Header().Return(header).Times(2)
				rw.EXPECT().WriteHeader(http.StatusSeeOther)
			},
			expect: func() {
				assert.Equal(t, http.Header{
					consts.HeaderLocation:     []string{"https://foobar.com/?foo=bar"},
					consts.HeaderCacheControl: []string{consts.CacheControlNoStore},
					consts.HeaderPragma:       []string{consts.PragmaNoCache},
				}, header)
			},
		},
		{
			setup: func() {
				redir, _ := url.Parse("https://foobar.com/?foo=bar")
				ar.EXPECT().GetRedirectURI().Return(redir)
				ar.EXPECT().GetResponseMode().Return(ResponseModeFragment)
				resp.EXPECT().GetParameters().Return(url.Values{"bar": {"baz"}})
				resp.EXPECT().GetHeader().Return(http.Header{})

				rw.EXPECT().Header().Return(header).Times(2)
				rw.EXPECT().WriteHeader(http.StatusSeeOther)
			},
			expect: func() {
				assert.Equal(t, http.Header{
					consts.HeaderLocation:     []string{"https://foobar.com/?foo=bar#bar=baz"},
					consts.HeaderCacheControl: []string{consts.CacheControlNoStore},
					consts.HeaderPragma:       []string{consts.PragmaNoCache},
				}, header)
			},
		},
		{
			setup: func() {
				redir, _ := url.Parse("https://foobar.com/?foo=bar")
				ar.EXPECT().GetRedirectURI().Return(redir)
				ar.EXPECT().GetResponseMode().Return(ResponseModeQuery)
				resp.EXPECT().GetParameters().Return(url.Values{"bar": {"baz"}})
				resp.EXPECT().GetHeader().Return(http.Header{})

				rw.EXPECT().Header().Return(header).Times(2)
				rw.EXPECT().WriteHeader(http.StatusSeeOther)
			},
			expect: func() {
				expectedUrl, _ := url.Parse("https://foobar.com/?foo=bar&bar=baz")
				actualUrl, err := url.Parse(header.Get(consts.HeaderLocation))
				assert.Nil(t, err)
				assert.Equal(t, expectedUrl.Query(), actualUrl.Query())
				assert.Equal(t, consts.PragmaNoCache, header.Get(consts.HeaderPragma))
				assert.Equal(t, consts.CacheControlNoStore, header.Get(consts.HeaderCacheControl))
			},
		},
		{
			setup: func() {
				redir, _ := url.Parse("https://foobar.com/?foo=bar")
				ar.EXPECT().GetRedirectURI().Return(redir)
				ar.EXPECT().GetResponseMode().Return(ResponseModeFragment)
				resp.EXPECT().GetParameters().Return(url.Values{"bar": {"b+az ab"}})
				resp.EXPECT().GetHeader().Return(http.Header{"X-Bar": {"baz"}})

				rw.EXPECT().Header().Return(header).Times(2)
				rw.EXPECT().WriteHeader(http.StatusSeeOther)
			},
			expect: func() {
				assert.Equal(t, http.Header{
					"X-Bar":                   {"baz"},
					consts.HeaderLocation:     {"https://foobar.com/?foo=bar#bar=b%2Baz+ab"},
					consts.HeaderCacheControl: []string{consts.CacheControlNoStore},
					consts.HeaderPragma:       []string{consts.PragmaNoCache},
				}, header)
			},
		},
		{
			setup: func() {
				redir, _ := url.Parse("https://foobar.com/?foo=bar")
				ar.EXPECT().GetRedirectURI().Return(redir)
				ar.EXPECT().GetResponseMode().Return(ResponseModeQuery)
				resp.EXPECT().GetParameters().Return(url.Values{"bar": {"b+az"}, consts.FormParameterScope: {"a b"}})
				resp.EXPECT().GetHeader().Return(http.Header{"X-Bar": {"baz"}})

				rw.EXPECT().Header().Return(header).Times(2)
				rw.EXPECT().WriteHeader(http.StatusSeeOther)
			},
			expect: func() {
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
			setup: func() {
				redir, _ := url.Parse("https://foobar.com/?foo=bar")
				ar.EXPECT().GetRedirectURI().Return(redir)
				ar.EXPECT().GetResponseMode().Return(ResponseModeFragment)
				resp.EXPECT().GetParameters().Return(url.Values{consts.FormParameterScope: {"api:*"}})
				resp.EXPECT().GetHeader().Return(http.Header{"X-Bar": {"baz"}})

				rw.EXPECT().Header().Return(header).Times(2)
				rw.EXPECT().WriteHeader(http.StatusSeeOther)
			},
			expect: func() {
				assert.Equal(t, http.Header{
					"X-Bar":                   {"baz"},
					consts.HeaderLocation:     {"https://foobar.com/?foo=bar#scope=api%3A%2A"},
					consts.HeaderCacheControl: []string{consts.CacheControlNoStore},
					consts.HeaderPragma:       []string{consts.PragmaNoCache},
				}, header)
			},
		},
		{
			setup: func() {
				redir, _ := url.Parse("https://foobar.com/?foo=bar#bar=baz")
				ar.EXPECT().GetRedirectURI().Return(redir)
				ar.EXPECT().GetResponseMode().Return(ResponseModeFragment)
				resp.EXPECT().GetParameters().Return(url.Values{"qux": {"quux"}})
				resp.EXPECT().GetHeader().Return(http.Header{})

				rw.EXPECT().Header().Return(header).Times(2)
				rw.EXPECT().WriteHeader(http.StatusSeeOther)
			},
			expect: func() {
				assert.Equal(t, http.Header{
					consts.HeaderLocation:     {"https://foobar.com/?foo=bar#qux=quux"},
					consts.HeaderCacheControl: []string{consts.CacheControlNoStore},
					consts.HeaderPragma:       []string{consts.PragmaNoCache},
				}, header)
			},
		},
		{
			setup: func() {
				redir, _ := url.Parse("https://foobar.com/?foo=bar")
				ar.EXPECT().GetRedirectURI().Return(redir)
				ar.EXPECT().GetResponseMode().Return(ResponseModeFragment)
				resp.EXPECT().GetParameters().Return(url.Values{consts.FormParameterState: {"{\"a\":\"b=c&d=e\"}"}})
				resp.EXPECT().GetHeader().Return(http.Header{})

				rw.EXPECT().Header().Return(header).Times(2)
				rw.EXPECT().WriteHeader(http.StatusSeeOther)
			},
			expect: func() {
				assert.Equal(t, http.Header{
					consts.HeaderLocation:     {"https://foobar.com/?foo=bar#state=%7B%22a%22%3A%22b%3Dc%26d%3De%22%7D"},
					consts.HeaderCacheControl: []string{consts.CacheControlNoStore},
					consts.HeaderPragma:       []string{consts.PragmaNoCache},
				}, header)
			},
		},
		{
			setup: func() {
				redir, _ := url.Parse("https://foobar.com/?foo=bar")
				ar.EXPECT().GetRedirectURI().Return(redir)
				ar.EXPECT().GetResponseMode().Return(ResponseModeFormPost)
				resp.EXPECT().GetHeader().Return(http.Header{"X-Bar": {"baz"}})
				resp.EXPECT().GetParameters().Return(url.Values{consts.FormParameterAuthorizationCode: {"poz65kqoneu"}, consts.FormParameterState: {"qm6dnsrn"}})

				rw.EXPECT().Header().Return(header).AnyTimes()
				rw.EXPECT().Write(gomock.Any()).AnyTimes()
			},
			expect: func() {
				assert.Equal(t, consts.ContentTypeTextHTML, header.Get(consts.HeaderContentType))
			},
		},
	} {
		t.Logf("Starting test case %d", k)
		c.setup()
		provider.WriteAuthorizeResponse(context.Background(), rw, ar, resp)
		c.expect()
		header = http.Header{}
		t.Logf("Passed test case %d", k)
	}
}
