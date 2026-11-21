// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"net/http"

	"golang.org/x/text/language"
)

// UserinfoRequester is a request to the OpenID Connect UserInfo endpoint.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
type UserinfoRequester interface {
	// GetAccessRequester returns the request the Access Token presented was issued for, nil until the Access Token is
	// resolved.
	GetAccessRequester() (requester AccessRequester)

	// GetClient returns the current registration of the client the Access Token was issued to, nil until it is
	// resolved.
	GetClient() (client Client)

	// GetLang returns the language used to localize error descriptions.
	GetLang() (lang language.Tag)
}

// UserinfoRequest is the default implementation of UserinfoRequester.
type UserinfoRequest struct {
	AccessRequester AccessRequester
	Client          Client
	Lang            language.Tag

	request *http.Request
}

// GetAccessRequester implements UserinfoRequester.
func (r *UserinfoRequest) GetAccessRequester() (requester AccessRequester) {
	return r.AccessRequester
}

// GetClient implements UserinfoRequester.
func (r *UserinfoRequest) GetClient() (client Client) {
	return r.Client
}

// GetLang implements UserinfoRequester.
func (r *UserinfoRequest) GetLang() (lang language.Tag) {
	return r.Lang
}

var (
	_ UserinfoRequester = (*UserinfoRequest)(nil)
)
