// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"strings"
	"time"

	"authelia.com/provider/oauth2/internal/consts"
)

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

func (a *AccessResponse) SetScopes(scopes Arguments) {
	a.SetExtra(consts.AccessResponseScope, strings.Join(scopes, " "))
}

func (a *AccessResponse) SetExpiresIn(expiresIn time.Duration) {
	a.SetExtra(consts.AccessResponseExpiresIn, int64(expiresIn/time.Second))
}

func (a *AccessResponse) SetExtra(key string, value any) {
	a.Extra[key] = value
}

func (a *AccessResponse) GetExtra(key string) any {
	return a.Extra[key]
}

func (a *AccessResponse) SetAccessToken(token string) {
	a.AccessToken = token
}

func (a *AccessResponse) SetTokenType(name string) {
	a.TokenType = name
}

func (a *AccessResponse) GetAccessToken() string {
	return a.AccessToken
}

func (a *AccessResponse) GetTokenType() string {
	return a.TokenType
}

func (a *AccessResponse) ToMap() map[string]any {
	a.Extra[consts.AccessResponseAccessToken] = a.GetAccessToken()
	a.Extra[consts.AccessResponseTokenType] = a.GetTokenType()
	return a.Extra
}
