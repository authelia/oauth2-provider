// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	. "authelia.com/provider/oauth2"
	. "authelia.com/provider/oauth2/internal"
	"authelia.com/provider/oauth2/internal/consts"
)

// Test for
//   - https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
//     If the request fails due to a missing, invalid, or mismatching
//     redirection URI, or if the client identifier is missing or invalid,
//     the authorization server SHOULD inform the resource owner of the
//     error and MUST NOT automatically redirect the user-agent to the
//     invalid redirection URI.
//   - https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2
//     The redirection endpoint URI MUST be an absolute URI as defined by
//     [RFC3986] Section 4.3.  The endpoint URI MAY include an
//     "application/x-www-form-urlencoded" formatted (per Appendix B) query
//     component ([RFC3986] Section 3.4), which MUST be retained when adding
//     additional query parameters.  The endpoint URI MUST NOT include a
//     fragment component.
func TestWriteAuthorizeError(t *testing.T) {
	var urls = []string{
		"https://foobar.com/",
		"https://foobar.com/?foo=bar",
	}
	var purls = []*url.URL{}
	for _, u := range urls {
		purl, _ := url.Parse(u)
		purls = append(purls, purl)
	}

	header := http.Header{}
	for k, c := range []struct {
		err                  *RFC6749Error
		debug                bool
		doNotUseLegacyFormat bool
		mock                 func(*MockResponseWriter, *MockAuthorizeRequester)
		checkHeader          func(*testing.T, int)
	}{
		// 0
		{
			err: ErrInvalidGrant,
			mock: func(rw *MockResponseWriter, req *MockAuthorizeRequester) {
				req.EXPECT().IsRedirectURIValid().Return(false)
				req.EXPECT().GetResponseMode().Return(ResponseModeDefault)
				rw.EXPECT().Header().Times(3).Return(header)
				rw.EXPECT().WriteHeader(http.StatusBadRequest)
				rw.EXPECT().Write(gomock.Any())
			},
			checkHeader: func(t *testing.T, k int) {
				assert.Equal(t, consts.ContentTypeApplicationJSON, header.Get(consts.HeaderContentType))
				assert.Equal(t, consts.CacheControlNoStore, header.Get(consts.HeaderCacheControl))
				assert.Equal(t, consts.PragmaNoCache, header.Get(consts.HeaderPragma))
			},
		},
		// 1
		{
			debug: true,
			err:   ErrInvalidRequest.WithDebug("with-debug"),
			mock: func(rw *MockResponseWriter, req *MockAuthorizeRequester) {
				req.EXPECT().IsRedirectURIValid().Return(true)
				req.EXPECT().GetRedirectURI().Return(copyUrl(purls[0]))
				req.EXPECT().GetState().Return("foostate")
				req.EXPECT().GetResponseTypes().AnyTimes().Return(Arguments([]string{consts.ResponseTypeAuthorizationCodeFlow}))
				req.EXPECT().GetResponseMode().Return(ResponseModeQuery).AnyTimes()
				rw.EXPECT().Header().Times(3).Return(header)
				rw.EXPECT().WriteHeader(http.StatusSeeOther)
			},
			checkHeader: func(t *testing.T, k int) {
				a, _ := url.Parse("https://foobar.com/?error=invalid_request&error_debug=with-debug&error_description=The+request+is+missing+a+required+parameter%2C+includes+an+invalid+parameter+value%2C+includes+a+parameter+more+than+once%2C+or+is+otherwise+malformed.&error_hint=Make+sure+that+the+various+parameters+are+correct%2C+be+aware+of+case+sensitivity+and+trim+your+parameters.+Make+sure+that+the+client+you+are+using+has+exactly+whitelisted+the+redirect_uri+you+specified.&state=foostate")
				b, _ := url.Parse(header.Get(consts.HeaderLocation))
				assert.Equal(t, a, b)
				assert.Equal(t, consts.CacheControlNoStore, header.Get(consts.HeaderCacheControl))
				assert.Equal(t, consts.PragmaNoCache, header.Get(consts.HeaderPragma))
			},
		},
		// 2
		{
			debug:                true,
			doNotUseLegacyFormat: true,
			err:                  ErrInvalidRequest.WithDebug("with-debug"),
			mock: func(rw *MockResponseWriter, req *MockAuthorizeRequester) {
				req.EXPECT().IsRedirectURIValid().Return(true)
				req.EXPECT().GetRedirectURI().Return(copyUrl(purls[0]))
				req.EXPECT().GetState().Return("foostate")
				req.EXPECT().GetResponseTypes().AnyTimes().Return(Arguments([]string{consts.ResponseTypeAuthorizationCodeFlow}))
				req.EXPECT().GetResponseMode().Return(ResponseModeQuery).AnyTimes()
				rw.EXPECT().Header().Times(3).Return(header)
				rw.EXPECT().WriteHeader(http.StatusSeeOther)
			},
			checkHeader: func(t *testing.T, k int) {
				a, _ := url.Parse("https://foobar.com/?error=invalid_request&error_description=The+request+is+missing+a+required+parameter%2C+includes+an+invalid+parameter+value%2C+includes+a+parameter+more+than+once%2C+or+is+otherwise+malformed.+Make+sure+that+the+various+parameters+are+correct%2C+be+aware+of+case+sensitivity+and+trim+your+parameters.+Make+sure+that+the+client+you+are+using+has+exactly+whitelisted+the+redirect_uri+you+specified.+with-debug&state=foostate")
				b, _ := url.Parse(header.Get(consts.HeaderLocation))
				assert.Equal(t, a, b)
				assert.Equal(t, consts.CacheControlNoStore, header.Get(consts.HeaderCacheControl))
				assert.Equal(t, consts.PragmaNoCache, header.Get(consts.HeaderPragma))
			},
		},
		// 3
		{
			doNotUseLegacyFormat: true,
			err:                  ErrInvalidRequest.WithDebug("with-debug"),
			mock: func(rw *MockResponseWriter, req *MockAuthorizeRequester) {
				req.EXPECT().IsRedirectURIValid().Return(true)
				req.EXPECT().GetRedirectURI().Return(copyUrl(purls[0]))
				req.EXPECT().GetState().Return("foostate")
				req.EXPECT().GetResponseTypes().AnyTimes().Return(Arguments([]string{consts.ResponseTypeAuthorizationCodeFlow}))
				req.EXPECT().GetResponseMode().Return(ResponseModeQuery).AnyTimes()
				rw.EXPECT().Header().Times(3).Return(header)
				rw.EXPECT().WriteHeader(http.StatusSeeOther)
			},
			checkHeader: func(t *testing.T, k int) {
				a, _ := url.Parse("https://foobar.com/?error=invalid_request&error_description=The+request+is+missing+a+required+parameter%2C+includes+an+invalid+parameter+value%2C+includes+a+parameter+more+than+once%2C+or+is+otherwise+malformed.+Make+sure+that+the+various+parameters+are+correct%2C+be+aware+of+case+sensitivity+and+trim+your+parameters.+Make+sure+that+the+client+you+are+using+has+exactly+whitelisted+the+redirect_uri+you+specified.&state=foostate")
				b, _ := url.Parse(header.Get(consts.HeaderLocation))
				assert.Equal(t, a, b)
				assert.Equal(t, consts.CacheControlNoStore, header.Get(consts.HeaderCacheControl))
				assert.Equal(t, consts.PragmaNoCache, header.Get(consts.HeaderPragma))
			},
		},
		// 4
		{
			err: ErrInvalidRequest.WithDebug("with-debug"),
			mock: func(rw *MockResponseWriter, req *MockAuthorizeRequester) {
				req.EXPECT().IsRedirectURIValid().Return(true)
				req.EXPECT().GetRedirectURI().Return(copyUrl(purls[0]))
				req.EXPECT().GetState().Return("foostate")
				req.EXPECT().GetResponseTypes().AnyTimes().Return(Arguments([]string{consts.ResponseTypeAuthorizationCodeFlow}))
				req.EXPECT().GetResponseMode().Return(ResponseModeDefault).AnyTimes()
				rw.EXPECT().Header().Times(3).Return(header)
				rw.EXPECT().WriteHeader(http.StatusSeeOther)
			},
			checkHeader: func(t *testing.T, k int) {
				a, _ := url.Parse("https://foobar.com/?error=invalid_request&error_description=The+request+is+missing+a+required+parameter%2C+includes+an+invalid+parameter+value%2C+includes+a+parameter+more+than+once%2C+or+is+otherwise+malformed.&error_hint=Make+sure+that+the+various+parameters+are+correct%2C+be+aware+of+case+sensitivity+and+trim+your+parameters.+Make+sure+that+the+client+you+are+using+has+exactly+whitelisted+the+redirect_uri+you+specified.&state=foostate")
				b, _ := url.Parse(header.Get(consts.HeaderLocation))
				assert.Equal(t, a, b)
				assert.Equal(t, consts.CacheControlNoStore, header.Get(consts.HeaderCacheControl))
				assert.Equal(t, consts.PragmaNoCache, header.Get(consts.HeaderPragma))
			},
		},
		// 5
		{
			err: ErrInvalidRequest,
			mock: func(rw *MockResponseWriter, req *MockAuthorizeRequester) {
				req.EXPECT().IsRedirectURIValid().Return(true)
				req.EXPECT().GetRedirectURI().Return(copyUrl(purls[1]))
				req.EXPECT().GetState().Return("foostate")
				req.EXPECT().GetResponseTypes().AnyTimes().Return(Arguments([]string{consts.ResponseTypeAuthorizationCodeFlow}))
				req.EXPECT().GetResponseMode().Return(ResponseModeQuery).AnyTimes()
				rw.EXPECT().Header().Times(3).Return(header)
				rw.EXPECT().WriteHeader(http.StatusSeeOther)
			},
			checkHeader: func(t *testing.T, k int) {
				a, _ := url.Parse("https://foobar.com/?error=invalid_request&error_description=The+request+is+missing+a+required+parameter%2C+includes+an+invalid+parameter+value%2C+includes+a+parameter+more+than+once%2C+or+is+otherwise+malformed.&error_hint=Make+sure+that+the+various+parameters+are+correct%2C+be+aware+of+case+sensitivity+and+trim+your+parameters.+Make+sure+that+the+client+you+are+using+has+exactly+whitelisted+the+redirect_uri+you+specified.&foo=bar&state=foostate")
				b, _ := url.Parse(header.Get(consts.HeaderLocation))
				assert.Equal(t, a, b)
				assert.Equal(t, consts.CacheControlNoStore, header.Get(consts.HeaderCacheControl))
				assert.Equal(t, consts.PragmaNoCache, header.Get(consts.HeaderPragma))
			},
		},
		// 6
		{
			err: ErrUnsupportedGrantType,
			mock: func(rw *MockResponseWriter, req *MockAuthorizeRequester) {
				req.EXPECT().IsRedirectURIValid().Return(true)
				req.EXPECT().GetRedirectURI().Return(copyUrl(purls[1]))
				req.EXPECT().GetState().Return("foostate")
				req.EXPECT().GetResponseTypes().AnyTimes().Return(Arguments([]string{"foobar"}))
				req.EXPECT().GetResponseMode().Return(ResponseModeFragment).AnyTimes()
				rw.EXPECT().Header().Times(3).Return(header)
				rw.EXPECT().WriteHeader(http.StatusSeeOther)
			},
			checkHeader: func(t *testing.T, k int) {
				a, _ := url.Parse("https://foobar.com/?foo=bar#error=unsupported_grant_type&error_description=The+authorization+grant+type+is+not+supported+by+the+authorization+server.&state=foostate")
				b, _ := url.Parse(header.Get(consts.HeaderLocation))
				assert.Equal(t, a, b)
				assert.Equal(t, consts.CacheControlNoStore, header.Get(consts.HeaderCacheControl))
				assert.Equal(t, consts.PragmaNoCache, header.Get(consts.HeaderPragma))
			},
		},
		// 7
		{
			err: ErrInvalidRequest,
			mock: func(rw *MockResponseWriter, req *MockAuthorizeRequester) {
				req.EXPECT().IsRedirectURIValid().Return(true)
				req.EXPECT().GetRedirectURI().Return(copyUrl(purls[0]))
				req.EXPECT().GetState().Return("foostate")
				req.EXPECT().GetResponseTypes().AnyTimes().Return(Arguments([]string{"token"}))
				req.EXPECT().GetResponseMode().Return(ResponseModeFragment).AnyTimes()
				rw.EXPECT().Header().Times(3).Return(header)
				rw.EXPECT().WriteHeader(http.StatusSeeOther)
			},
			checkHeader: func(t *testing.T, k int) {
				a, _ := url.Parse("https://foobar.com/#error=invalid_request&error_description=The+request+is+missing+a+required+parameter%2C+includes+an+invalid+parameter+value%2C+includes+a+parameter+more+than+once%2C+or+is+otherwise+malformed.&error_hint=Make+sure+that+the+various+parameters+are+correct%2C+be+aware+of+case+sensitivity+and+trim+your+parameters.+Make+sure+that+the+client+you+are+using+has+exactly+whitelisted+the+redirect_uri+you+specified.&state=foostate")
				b, _ := url.Parse(header.Get(consts.HeaderLocation))
				assert.Equal(t, a, b, "\n\t%s\n\t%s", header.Get(consts.HeaderLocation), a.String())
				assert.Equal(t, consts.CacheControlNoStore, header.Get(consts.HeaderCacheControl))
				assert.Equal(t, consts.PragmaNoCache, header.Get(consts.HeaderPragma))
			},
		},
		// 8
		{
			err: ErrInvalidRequest,
			mock: func(rw *MockResponseWriter, req *MockAuthorizeRequester) {
				req.EXPECT().IsRedirectURIValid().Return(true)
				req.EXPECT().GetRedirectURI().Return(copyUrl(purls[1]))
				req.EXPECT().GetState().Return("foostate")
				req.EXPECT().GetResponseTypes().AnyTimes().Return(Arguments([]string{"token"}))
				req.EXPECT().GetResponseMode().Return(ResponseModeFragment).AnyTimes()
				rw.EXPECT().Header().Times(3).Return(header)
				rw.EXPECT().WriteHeader(http.StatusSeeOther)
			},
			checkHeader: func(t *testing.T, k int) {
				a, _ := url.Parse("https://foobar.com/?foo=bar#error=invalid_request&error_description=The+request+is+missing+a+required+parameter%2C+includes+an+invalid+parameter+value%2C+includes+a+parameter+more+than+once%2C+or+is+otherwise+malformed.&error_hint=Make+sure+that+the+various+parameters+are+correct%2C+be+aware+of+case+sensitivity+and+trim+your+parameters.+Make+sure+that+the+client+you+are+using+has+exactly+whitelisted+the+redirect_uri+you+specified.&state=foostate")
				b, _ := url.Parse(header.Get(consts.HeaderLocation))
				assert.Equal(t, a, b, "\n\t%s\n\t%s", header.Get(consts.HeaderLocation), a.String())
				assert.Equal(t, consts.CacheControlNoStore, header.Get(consts.HeaderCacheControl))
				assert.Equal(t, consts.PragmaNoCache, header.Get(consts.HeaderPragma))
			},
		},
		// 9
		{
			err: ErrInvalidRequest.WithDebug("with-debug"),
			mock: func(rw *MockResponseWriter, req *MockAuthorizeRequester) {
				req.EXPECT().IsRedirectURIValid().Return(true)
				req.EXPECT().GetRedirectURI().Return(copyUrl(purls[0]))
				req.EXPECT().GetState().Return("foostate")
				req.EXPECT().GetResponseTypes().AnyTimes().Return(Arguments([]string{consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeImplicitFlowToken}))
				req.EXPECT().GetResponseMode().Return(ResponseModeFragment).AnyTimes()
				rw.EXPECT().Header().Times(3).Return(header)
				rw.EXPECT().WriteHeader(http.StatusSeeOther)
			},
			checkHeader: func(t *testing.T, k int) {
				a, _ := url.Parse("https://foobar.com/#error=invalid_request&error_description=The+request+is+missing+a+required+parameter%2C+includes+an+invalid+parameter+value%2C+includes+a+parameter+more+than+once%2C+or+is+otherwise+malformed.&error_hint=Make+sure+that+the+various+parameters+are+correct%2C+be+aware+of+case+sensitivity+and+trim+your+parameters.+Make+sure+that+the+client+you+are+using+has+exactly+whitelisted+the+redirect_uri+you+specified.&state=foostate")
				b, _ := url.Parse(header.Get(consts.HeaderLocation))
				assert.Equal(t, a, b, "\n\t%s\n\t%s", header.Get(consts.HeaderLocation), a.String())
				assert.Equal(t, consts.CacheControlNoStore, header.Get(consts.HeaderCacheControl))
				assert.Equal(t, consts.PragmaNoCache, header.Get(consts.HeaderPragma))
			},
		},
		// 10
		{
			err:   ErrInvalidRequest.WithDebug("with-debug"),
			debug: true,
			mock: func(rw *MockResponseWriter, req *MockAuthorizeRequester) {
				req.EXPECT().IsRedirectURIValid().Return(true)
				req.EXPECT().GetRedirectURI().Return(copyUrl(purls[0]))
				req.EXPECT().GetState().Return("foostate")
				req.EXPECT().GetResponseTypes().AnyTimes().Return(Arguments([]string{consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeImplicitFlowToken}))
				req.EXPECT().GetResponseMode().Return(ResponseModeFragment).AnyTimes()
				rw.EXPECT().Header().Times(3).Return(header)
				rw.EXPECT().WriteHeader(http.StatusSeeOther)
			},
			checkHeader: func(t *testing.T, k int) {
				a, _ := url.Parse("https://foobar.com/#error=invalid_request&error_debug=with-debug&error_description=The+request+is+missing+a+required+parameter%2C+includes+an+invalid+parameter+value%2C+includes+a+parameter+more+than+once%2C+or+is+otherwise+malformed.&error_hint=Make+sure+that+the+various+parameters+are+correct%2C+be+aware+of+case+sensitivity+and+trim+your+parameters.+Make+sure+that+the+client+you+are+using+has+exactly+whitelisted+the+redirect_uri+you+specified.&state=foostate")
				b, _ := url.Parse(header.Get(consts.HeaderLocation))
				assert.Equal(t, a, b, "\n\t%s\n\t%s", header.Get(consts.HeaderLocation), a.String())
				assert.Equal(t, consts.CacheControlNoStore, header.Get(consts.HeaderCacheControl))
				assert.Equal(t, consts.PragmaNoCache, header.Get(consts.HeaderPragma))
			},
		},
		// 11
		{
			err:                  ErrInvalidRequest.WithDebug("with-debug"),
			debug:                true,
			doNotUseLegacyFormat: true,
			mock: func(rw *MockResponseWriter, req *MockAuthorizeRequester) {
				req.EXPECT().IsRedirectURIValid().Return(true)
				req.EXPECT().GetRedirectURI().Return(copyUrl(purls[0]))
				req.EXPECT().GetState().Return("foostate")
				req.EXPECT().GetResponseTypes().AnyTimes().Return(Arguments([]string{consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeImplicitFlowToken}))
				req.EXPECT().GetResponseMode().Return(ResponseModeFragment).AnyTimes()
				rw.EXPECT().Header().Times(3).Return(header)
				rw.EXPECT().WriteHeader(http.StatusSeeOther)
			},
			checkHeader: func(t *testing.T, k int) {
				a, _ := url.Parse("https://foobar.com/#error=invalid_request&error_description=The+request+is+missing+a+required+parameter%2C+includes+an+invalid+parameter+value%2C+includes+a+parameter+more+than+once%2C+or+is+otherwise+malformed.+Make+sure+that+the+various+parameters+are+correct%2C+be+aware+of+case+sensitivity+and+trim+your+parameters.+Make+sure+that+the+client+you+are+using+has+exactly+whitelisted+the+redirect_uri+you+specified.+with-debug&state=foostate")
				b, _ := url.Parse(header.Get(consts.HeaderLocation))
				assert.NotContains(t, header.Get(consts.HeaderLocation), "error_hint")
				assert.NotContains(t, header.Get(consts.HeaderLocation), "error_debug")
				assert.Equal(t, a, b, "\n\t%s\n\t%s", header.Get(consts.HeaderLocation), a.String())
				assert.Equal(t, consts.CacheControlNoStore, header.Get(consts.HeaderCacheControl))
				assert.Equal(t, consts.PragmaNoCache, header.Get(consts.HeaderPragma))
			},
		},
		// 12
		{
			err:                  ErrInvalidRequest.WithDebug("with-debug"),
			doNotUseLegacyFormat: true,
			mock: func(rw *MockResponseWriter, req *MockAuthorizeRequester) {
				req.EXPECT().IsRedirectURIValid().Return(true)
				req.EXPECT().GetRedirectURI().Return(copyUrl(purls[0]))
				req.EXPECT().GetState().Return("foostate")
				req.EXPECT().GetResponseTypes().AnyTimes().Return(Arguments([]string{consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeImplicitFlowToken}))
				req.EXPECT().GetResponseMode().Return(ResponseModeFragment).AnyTimes()
				rw.EXPECT().Header().Times(3).Return(header)
				rw.EXPECT().WriteHeader(http.StatusSeeOther)
			},
			checkHeader: func(t *testing.T, k int) {
				a, _ := url.Parse("https://foobar.com/#error=invalid_request&error_description=The+request+is+missing+a+required+parameter%2C+includes+an+invalid+parameter+value%2C+includes+a+parameter+more+than+once%2C+or+is+otherwise+malformed.+Make+sure+that+the+various+parameters+are+correct%2C+be+aware+of+case+sensitivity+and+trim+your+parameters.+Make+sure+that+the+client+you+are+using+has+exactly+whitelisted+the+redirect_uri+you+specified.&state=foostate")
				b, _ := url.Parse(header.Get(consts.HeaderLocation))
				assert.NotContains(t, header.Get(consts.HeaderLocation), "error_hint")
				assert.NotContains(t, header.Get(consts.HeaderLocation), "error_debug")
				assert.NotContains(t, header.Get(consts.HeaderLocation), "with-debug")
				assert.Equal(t, a, b, "\n\t%s\n\t%s", header.Get(consts.HeaderLocation), a.String())
				assert.Equal(t, consts.CacheControlNoStore, header.Get(consts.HeaderCacheControl))
				assert.Equal(t, consts.PragmaNoCache, header.Get(consts.HeaderPragma))
			},
		},
		// 13
		{
			err: ErrInvalidRequest.WithDebug("with-debug"),
			mock: func(rw *MockResponseWriter, req *MockAuthorizeRequester) {
				req.EXPECT().IsRedirectURIValid().Return(true)
				req.EXPECT().GetRedirectURI().Return(copyUrl(purls[1]))
				req.EXPECT().GetState().Return("foostate")
				req.EXPECT().GetResponseTypes().AnyTimes().Return(Arguments([]string{consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeImplicitFlowToken}))
				req.EXPECT().GetResponseMode().Return(ResponseModeFragment).AnyTimes()
				rw.EXPECT().Header().Times(3).Return(header)
				rw.EXPECT().WriteHeader(http.StatusSeeOther)
			},
			checkHeader: func(t *testing.T, k int) {
				a, _ := url.Parse("https://foobar.com/?foo=bar#error=invalid_request&error_description=The+request+is+missing+a+required+parameter%2C+includes+an+invalid+parameter+value%2C+includes+a+parameter+more+than+once%2C+or+is+otherwise+malformed.&error_hint=Make+sure+that+the+various+parameters+are+correct%2C+be+aware+of+case+sensitivity+and+trim+your+parameters.+Make+sure+that+the+client+you+are+using+has+exactly+whitelisted+the+redirect_uri+you+specified.&state=foostate")
				b, _ := url.Parse(header.Get(consts.HeaderLocation))
				assert.Equal(t, a, b, "\n\t%s\n\t%s", header.Get(consts.HeaderLocation), a.String())
				assert.Equal(t, consts.CacheControlNoStore, header.Get(consts.HeaderCacheControl))
				assert.Equal(t, consts.PragmaNoCache, header.Get(consts.HeaderPragma))
			},
		},
		// 14
		{
			debug: true,
			err:   ErrInvalidRequest.WithDebug("with-debug"),
			mock: func(rw *MockResponseWriter, req *MockAuthorizeRequester) {
				req.EXPECT().IsRedirectURIValid().Return(true)
				req.EXPECT().GetRedirectURI().Return(copyUrl(purls[1]))
				req.EXPECT().GetState().Return("foostate")
				req.EXPECT().GetResponseTypes().AnyTimes().Return(Arguments([]string{consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeImplicitFlowToken}))
				req.EXPECT().GetResponseMode().Return(ResponseModeFragment).AnyTimes()
				rw.EXPECT().Header().Times(3).Return(header)
				rw.EXPECT().WriteHeader(http.StatusSeeOther)
			},
			checkHeader: func(t *testing.T, k int) {
				a, _ := url.Parse("https://foobar.com/?foo=bar#error=invalid_request&error_debug=with-debug&error_description=The+request+is+missing+a+required+parameter%2C+includes+an+invalid+parameter+value%2C+includes+a+parameter+more+than+once%2C+or+is+otherwise+malformed.&error_hint=Make+sure+that+the+various+parameters+are+correct%2C+be+aware+of+case+sensitivity+and+trim+your+parameters.+Make+sure+that+the+client+you+are+using+has+exactly+whitelisted+the+redirect_uri+you+specified.&state=foostate")
				b, _ := url.Parse(header.Get(consts.HeaderLocation))
				assert.Equal(t, a, b, "\n\t%s\n\t%s", header.Get(consts.HeaderLocation), a.String())
				assert.Equal(t, consts.CacheControlNoStore, header.Get(consts.HeaderCacheControl))
				assert.Equal(t, consts.PragmaNoCache, header.Get(consts.HeaderPragma))
			},
		},
		// 15
		{
			debug: true,
			err:   ErrInvalidRequest.WithDebug("with-debug"),
			mock: func(rw *MockResponseWriter, req *MockAuthorizeRequester) {
				req.EXPECT().IsRedirectURIValid().Return(true)
				req.EXPECT().GetRedirectURI().Return(copyUrl(purls[1]))
				req.EXPECT().GetState().Return("foostate")
				req.EXPECT().GetResponseTypes().AnyTimes().Return(Arguments([]string{consts.ResponseTypeImplicitFlowIDToken}))
				req.EXPECT().GetResponseMode().Return(ResponseModeFragment).AnyTimes()
				rw.EXPECT().Header().Times(3).Return(header)
				rw.EXPECT().WriteHeader(http.StatusSeeOther)
			},
			checkHeader: func(t *testing.T, k int) {
				a, _ := url.Parse("https://foobar.com/?foo=bar#error=invalid_request&error_debug=with-debug&error_description=The+request+is+missing+a+required+parameter%2C+includes+an+invalid+parameter+value%2C+includes+a+parameter+more+than+once%2C+or+is+otherwise+malformed.&error_hint=Make+sure+that+the+various+parameters+are+correct%2C+be+aware+of+case+sensitivity+and+trim+your+parameters.+Make+sure+that+the+client+you+are+using+has+exactly+whitelisted+the+redirect_uri+you+specified.&state=foostate")
				b, _ := url.Parse(header.Get(consts.HeaderLocation))
				assert.Equal(t, a, b, "\n\t%s\n\t%s", header.Get(consts.HeaderLocation), a.String())
				assert.Equal(t, consts.CacheControlNoStore, header.Get(consts.HeaderCacheControl))
				assert.Equal(t, consts.PragmaNoCache, header.Get(consts.HeaderPragma))
			},
		},
		// 16
		{
			debug: true,
			err:   ErrInvalidRequest.WithDebug("with-debug"),
			mock: func(rw *MockResponseWriter, req *MockAuthorizeRequester) {
				req.EXPECT().IsRedirectURIValid().Return(true)
				req.EXPECT().GetRedirectURI().Return(copyUrl(purls[1]))
				req.EXPECT().GetState().Return("foostate")
				req.EXPECT().GetResponseTypes().AnyTimes().Return(Arguments([]string{consts.ResponseTypeImplicitFlowToken}))
				req.EXPECT().GetResponseMode().Return(ResponseModeFragment).AnyTimes()
				rw.EXPECT().Header().Times(3).Return(header)
				rw.EXPECT().WriteHeader(http.StatusSeeOther)
			},
			checkHeader: func(t *testing.T, k int) {
				a, _ := url.Parse("https://foobar.com/?foo=bar#error=invalid_request&error_debug=with-debug&error_description=The+request+is+missing+a+required+parameter%2C+includes+an+invalid+parameter+value%2C+includes+a+parameter+more+than+once%2C+or+is+otherwise+malformed.&error_hint=Make+sure+that+the+various+parameters+are+correct%2C+be+aware+of+case+sensitivity+and+trim+your+parameters.+Make+sure+that+the+client+you+are+using+has+exactly+whitelisted+the+redirect_uri+you+specified.&state=foostate")
				b, _ := url.Parse(header.Get(consts.HeaderLocation))
				assert.Equal(t, a, b, "\n\t%s\n\t%s", header.Get(consts.HeaderLocation), a.String())
				assert.Equal(t, consts.CacheControlNoStore, header.Get(consts.HeaderCacheControl))
				assert.Equal(t, consts.PragmaNoCache, header.Get(consts.HeaderPragma))
			},
		},
		// 17
		{
			debug: true,
			err:   ErrInvalidRequest.WithDebug("with-debug"),
			mock: func(rw *MockResponseWriter, req *MockAuthorizeRequester) {
				req.EXPECT().IsRedirectURIValid().Return(true)
				req.EXPECT().GetRedirectURI().Return(copyUrl(purls[1]))
				req.EXPECT().GetState().Return("foostate")
				req.EXPECT().GetResponseTypes().AnyTimes().Return(Arguments([]string{consts.ResponseTypeImplicitFlowToken}))
				req.EXPECT().GetResponseMode().Return(ResponseModeFormPost).Times(2)
				rw.EXPECT().Header().Times(3).Return(header)
				rw.EXPECT().Write(gomock.Any()).AnyTimes()
			},
			checkHeader: func(t *testing.T, k int) {
				assert.Equal(t, consts.CacheControlNoStore, header.Get(consts.HeaderCacheControl))
				assert.Equal(t, consts.PragmaNoCache, header.Get(consts.HeaderPragma))
				assert.Equal(t, consts.ContentTypeTextHTML, header.Get(consts.HeaderContentType))
			},
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			provider := &Fosite{
				Config: &Config{
					SendDebugMessagesToClients: c.debug,
					UseLegacyErrorFormat:       !c.doNotUseLegacyFormat,
				},
			}

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			rw := NewMockResponseWriter(ctrl)
			req := NewMockAuthorizeRequester(ctrl)

			c.mock(rw, req)
			provider.WriteAuthorizeError(context.Background(), rw, req, c.err)
			c.checkHeader(t, k)
			header = http.Header{}
		})
	}
}

func copyUrl(u *url.URL) *url.URL {
	u2, _ := url.Parse(u.String())
	return u2
}
