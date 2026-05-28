// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"net/url"

	"authelia.com/provider/oauth2/internal/consts"
)

type ResponseModeType string

const (
	ResponseModeDefault     = ResponseModeType("")
	ResponseModeFormPost    = ResponseModeType(consts.ResponseModeFormPost)
	ResponseModeQuery       = ResponseModeType(consts.ResponseModeQuery)
	ResponseModeFragment    = ResponseModeType(consts.ResponseModeFragment)
	ResponseModeFormPostJWT = ResponseModeType(consts.ResponseModeFormPostJWT)
	ResponseModeQueryJWT    = ResponseModeType(consts.ResponseModeQueryJWT)
	ResponseModeFragmentJWT = ResponseModeType(consts.ResponseModeFragmentJWT)
	ResponseModeJWT         = ResponseModeType(consts.ResponseModeJWT)
)

// AuthorizeRequest is an implementation of AuthorizeRequester
type AuthorizeRequest struct {
	ResponseTypes        Arguments        `json:"responseTypes" gorethink:"responseTypes"`
	RedirectURI          *url.URL         `json:"redirectUri" gorethink:"redirectUri"`
	State                string           `json:"state" gorethink:"state"`
	HandledResponseTypes Arguments        `json:"handledResponseTypes" gorethink:"handledResponseTypes"`
	ResponseMode         ResponseModeType `json:"ResponseModes" gorethink:"ResponseModes"`
	DefaultResponseMode  ResponseModeType `json:"DefaultResponseMode" gorethink:"DefaultResponseMode"`

	Request
}

// NewAuthorizeRequest returns an empty AuthorizeRequest with its response type slices initialized and the response mode
// set to ResponseModeDefault. The RedirectURI is intentionally left nil so callers can detect whether a redirect URI
// has actually been parsed from the request.
func NewAuthorizeRequest() *AuthorizeRequest {
	return &AuthorizeRequest{
		ResponseTypes:        Arguments{},
		HandledResponseTypes: Arguments{},
		Request:              *NewRequest(),
		ResponseMode:         ResponseModeDefault,
		// The redirect URL must be unset / nil for redirect detection to work properly:
		// RedirectURI:          &url.URL{},
	}
}

// IsRedirectURIValid reports whether the request's redirect_uri matches one of the registered redirect URIs of the
// associated client and conforms to the redirect URI rules in RFC 6749 section 3.1.2. Returns false when either the
// redirect URI or client is unset.
func (d *AuthorizeRequest) IsRedirectURIValid() bool {
	if d.GetRedirectURI() == nil {
		return false
	}

	raw := d.GetRedirectURI().String()
	if d.GetClient() == nil {
		return false
	}

	redirectURI, err := MatchRedirectURIWithClientRedirectURIs(raw, d.GetClient())
	if err != nil {
		return false
	}
	return IsValidRedirectURI(redirectURI)
}

// GetResponseTypes returns the response_type values requested by the client.
func (d *AuthorizeRequest) GetResponseTypes() Arguments {
	return d.ResponseTypes
}

// GetState returns the 'state' parameter supplied by the client, used to prevent CSRF and round-trip per-client data.
func (d *AuthorizeRequest) GetState() string {
	return d.State
}

// GetRedirectURI returns the parsed redirect URI for the request, or nil when the request did not include one or it has
// not yet been parsed.
func (d *AuthorizeRequest) GetRedirectURI() *url.URL {
	return d.RedirectURI
}

// SetResponseTypeHandled marks the given response type as handled by an authorize endpoint handler. Handlers must call
// this for every response_type value they fulfill so DidHandleAllResponseTypes can correctly detect a complete response.
func (d *AuthorizeRequest) SetResponseTypeHandled(name string) {
	d.HandledResponseTypes = append(d.HandledResponseTypes, name)
}

// DidHandleAllResponseTypes reports whether every requested response_type has been marked handled via
// SetResponseTypeHandled. It returns false when no response types were requested.
func (d *AuthorizeRequest) DidHandleAllResponseTypes() bool {
	for _, rt := range d.ResponseTypes {
		if !d.HandledResponseTypes.Has(rt) {
			return false
		}
	}

	return len(d.ResponseTypes) > 0
}

// GetResponseMode returns the response_mode requested by the client, or ResponseModeDefault when none was specified.
func (d *AuthorizeRequest) GetResponseMode() ResponseModeType {
	return d.ResponseMode
}

// SetDefaultResponseMode records the default response mode for the given response_type. If the client did not request
// an explicit response_mode, the request's effective ResponseMode is also updated to the default.
func (d *AuthorizeRequest) SetDefaultResponseMode(defaultResponseMode ResponseModeType) {
	if d.ResponseMode == ResponseModeDefault {
		d.ResponseMode = defaultResponseMode
	}
	d.DefaultResponseMode = defaultResponseMode
}

// GetDefaultResponseMode returns the default response_mode derived from the response_type, used as a fallback when the
// client did not include an explicit response_mode parameter.
func (d *AuthorizeRequest) GetDefaultResponseMode() ResponseModeType {
	return d.DefaultResponseMode
}
