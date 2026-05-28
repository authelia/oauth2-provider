// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"strings"
	"time"

	"authelia.com/provider/oauth2/internal/consts"
)

// NewAccessResponse returns an empty AccessResponse with its extra parameters map initialized.
func NewAccessResponse() *AccessResponse {
	return &AccessResponse{
		Extra: map[string]any{},
	}
}

type AccessResponse struct {
	Extra       map[string]any
	AccessToken string
	TokenType   string
}

// SetScopes records the granted scopes as a space-separated 'scope' parameter on the response.
func (a *AccessResponse) SetScopes(scopes Arguments) {
	a.SetExtra(consts.AccessResponseScope, strings.Join(scopes, " "))
}

// SetExpiresIn records the access token lifetime in seconds as the 'expires_in' response parameter.
func (a *AccessResponse) SetExpiresIn(expiresIn time.Duration) {
	a.SetExtra(consts.AccessResponseExpiresIn, int64(expiresIn/time.Second))
}

// SetExtra sets an arbitrary key/value pair in the response. Use this to add extension parameters such as 'id_token' or
// 'refresh_token' to the JSON response body.
func (a *AccessResponse) SetExtra(key string, value any) {
	a.Extra[key] = value
}

// GetExtra returns the value previously stored under key, or nil if no such value has been set.
func (a *AccessResponse) GetExtra(key string) any {
	return a.Extra[key]
}

// SetAccessToken sets the 'access_token' value returned to the client.
func (a *AccessResponse) SetAccessToken(token string) {
	a.AccessToken = token
}

// SetTokenType sets the 'token_type' value returned to the client (commonly 'Bearer').
func (a *AccessResponse) SetTokenType(name string) {
	a.TokenType = name
}

// GetAccessToken returns the access token value that will be returned to the client.
func (a *AccessResponse) GetAccessToken() string {
	return a.AccessToken
}

// GetTokenType returns the token type that will be returned to the client.
func (a *AccessResponse) GetTokenType() string {
	return a.TokenType
}

// ToMap returns the complete response payload as a map, including the access token, token type and all extra
// parameters. It mutates the underlying Extra map to include the access_token and token_type entries.
func (a *AccessResponse) ToMap() map[string]any {
	a.Extra[consts.AccessResponseAccessToken] = a.GetAccessToken()
	a.Extra[consts.AccessResponseTokenType] = a.GetTokenType()
	return a.Extra
}
