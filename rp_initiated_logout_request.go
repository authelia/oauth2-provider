// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"net/url"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
)

// RPInitiatedLogoutRequester is a request to the OpenID Connect end session endpoint.
//
// See: https://openid.net/specs/openid-connect-rpinitiated-1_0.html
type RPInitiatedLogoutRequester interface {
	// GetIDTokenHint returns the raw 'id_token_hint' parameter, empty if absent.
	GetIDTokenHint() (hint string)

	// GetIDTokenHintClaims returns the validated claims from the 'id_token_hint', nil if no hint was supplied.
	GetIDTokenHintClaims() (claims jwt.MapClaims)

	// GetSubject returns the 'sub' claim of the 'id_token_hint', empty if absent.
	GetSubject() (subject string)

	// GetSessionID returns the 'sid' claim of the 'id_token_hint', empty if absent.
	GetSessionID() (sid string)

	// GetLogoutHint returns the raw 'logout_hint' parameter, empty if absent. It is not interpreted.
	GetLogoutHint() (hint string)

	// GetClient returns the resolved client, nil when neither 'client_id' nor 'id_token_hint' was supplied.
	GetClient() (client Client)

	// GetPostLogoutRedirectURI returns the validated, registered redirect URI. It is nil when the parameter was
	// absent and nil on every error path, so an error can never be redirected to an unvalidated URI.
	GetPostLogoutRedirectURI() (uri *url.URL)

	// GetState returns the raw 'state' parameter, to be echoed back on the redirect.
	GetState() (state string)

	// GetUILocales returns the space-delimited 'ui_locales' parameter.
	GetUILocales() (locales Arguments)

	// GetRequestForm returns the raw request parameters.
	GetRequestForm() (form url.Values)
}

// NewRPInitiatedLogoutRequest returns an RPInitiatedLogoutRequest with its map fields initialized.
func NewRPInitiatedLogoutRequest() (request *RPInitiatedLogoutRequest) {
	return &RPInitiatedLogoutRequest{
		UILocales: Arguments{},
		Form:      url.Values{},
	}
}

// RPInitiatedLogoutRequest is an implementation of RPInitiatedLogoutRequester.
type RPInitiatedLogoutRequest struct {
	IDTokenHint           string
	IDTokenHintClaims     jwt.MapClaims
	LogoutHint            string
	Client                Client
	PostLogoutRedirectURI *url.URL
	State                 string
	UILocales             Arguments
	Form                  url.Values
}

// GetIDTokenHint returns the raw 'id_token_hint' parameter.
func (r *RPInitiatedLogoutRequest) GetIDTokenHint() (hint string) {
	return r.IDTokenHint
}

// GetIDTokenHintClaims returns the claims of the 'id_token_hint'.
func (r *RPInitiatedLogoutRequest) GetIDTokenHintClaims() (claims jwt.MapClaims) {
	return r.IDTokenHintClaims
}

// GetSubject returns the 'sub' claim of the 'id_token_hint', or an empty string when the hint is absent or the claim is
// not a string.
func (r *RPInitiatedLogoutRequest) GetSubject() (subject string) {
	return r.claimString(consts.ClaimSubject)
}

// GetSessionID returns the 'sid' claim of the 'id_token_hint', or an empty string when the hint is absent or the claim
// is not a string.
func (r *RPInitiatedLogoutRequest) GetSessionID() (sid string) {
	return r.claimString(consts.ClaimSessionID)
}

// GetLogoutHint returns the raw 'logout_hint' parameter.
func (r *RPInitiatedLogoutRequest) GetLogoutHint() (hint string) {
	return r.LogoutHint
}

// GetClient returns the client of the request.
func (r *RPInitiatedLogoutRequest) GetClient() (client Client) {
	return r.Client
}

// GetPostLogoutRedirectURI returns the 'post_logout_redirect_uri' of the request.
func (r *RPInitiatedLogoutRequest) GetPostLogoutRedirectURI() (uri *url.URL) {
	return r.PostLogoutRedirectURI
}

// GetState returns the raw 'state' parameter, to be echoed back on the redirect.
func (r *RPInitiatedLogoutRequest) GetState() (state string) {
	return r.State
}

// GetUILocales returns the space-delimited 'ui_locales' parameter.
func (r *RPInitiatedLogoutRequest) GetUILocales() (locales Arguments) {
	return r.UILocales
}

// GetRequestForm returns the raw request parameters.
func (r *RPInitiatedLogoutRequest) GetRequestForm() (form url.Values) {
	return r.Form
}

func (r *RPInitiatedLogoutRequest) claimString(claim string) (value string) {
	if r.IDTokenHintClaims == nil {
		return ""
	}

	value, _ = r.IDTokenHintClaims[claim].(string)

	return value
}

var (
	_ RPInitiatedLogoutRequester = (*RPInitiatedLogoutRequest)(nil)
)
