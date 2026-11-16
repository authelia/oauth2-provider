// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"time"
)

// AccessRequest is the default implementation of AccessRequester.
type AccessRequest struct {
	GrantTypes       Arguments `json:"grantTypes" gorethink:"grantTypes"`
	HandledGrantType Arguments `json:"handledGrantType" gorethink:"handledGrantType"`

	Request

	refreshTokenRotationDisabled *bool
	refreshTokenGraceDeadline    *time.Time

	clientAuthenticationMethod string
}

// ClientAuthenticationMethodRequester is an AccessRequester that records the method the client authenticated with.
type ClientAuthenticationMethodRequester interface {
	// GetClientAuthenticationMethod returns the method the client authenticated with, such as 'private_key_jwt', or an
	// empty string when it did not authenticate.
	GetClientAuthenticationMethod() (method string)

	// SetClientAuthenticationMethod records the method the client authenticated with.
	SetClientAuthenticationMethod(method string)
}

// GetClientAuthenticationMethod returns the method the client of the request authenticated with at the token endpoint,
// or an empty string when it did not authenticate or the request does not implement ClientAuthenticationMethodRequester.
//
// See: https://datatracker.ietf.org/doc/html/rfc7591#section-2
func GetClientAuthenticationMethod(request Requester) (method string) {
	if r, ok := request.(ClientAuthenticationMethodRequester); ok {
		return r.GetClientAuthenticationMethod()
	}

	return ""
}

// GetClientAuthenticationMethod returns the method the client authenticated with.
func (a *AccessRequest) GetClientAuthenticationMethod() (method string) {
	return a.clientAuthenticationMethod
}

// SetClientAuthenticationMethod records the method the client authenticated with.
func (a *AccessRequest) SetClientAuthenticationMethod(method string) {
	a.clientAuthenticationMethod = method
}

// GetRefreshTokenRotationDisabled implements AccessRequester.
func (a *AccessRequest) GetRefreshTokenRotationDisabled() (disable, ok bool) {
	if a.refreshTokenRotationDisabled == nil {
		return false, false
	}

	return *a.refreshTokenRotationDisabled, true
}

// SetRefreshTokenRotationDisabled implements AccessRequester.
func (a *AccessRequest) SetRefreshTokenRotationDisabled(disable bool) {
	a.refreshTokenRotationDisabled = &disable
}

func (a *AccessRequest) getRefreshTokenGraceDeadline() (deadline time.Time, ok bool) {
	if a.refreshTokenGraceDeadline == nil {
		return time.Time{}, false
	}

	return *a.refreshTokenGraceDeadline, true
}

func (a *AccessRequest) setRefreshTokenGraceDeadline(deadline time.Time) {
	a.refreshTokenGraceDeadline = &deadline
}

// NewAccessRequest returns an empty AccessRequest seeded with the given session.
func NewAccessRequest(session Session) *AccessRequest {
	r := &AccessRequest{
		GrantTypes:       Arguments{},
		HandledGrantType: Arguments{},
		Request:          *NewRequest(),
	}
	r.Session = session

	return r
}

// GetGrantTypes returns the grant types of the access request.
func (a *AccessRequest) GetGrantTypes() Arguments {
	return a.GrantTypes
}

// SetGrantedScopes replaces the granted scopes of the access request with the given scopes.
func (a *AccessRequest) SetGrantedScopes(scopes Arguments) {
	a.GrantedScope = scopes
}

// SanitizeRestoreRefreshTokenOriginalRequester returns a sanitized Requester carrying the original refresh token
// session's requested and granted scopes, audiences, resources, and authorization details alongside the supplied
// requester's ID. It is used by refresh token handlers to preserve the lineage between an issued refresh token and its
// preceding access request.
func (a *AccessRequest) SanitizeRestoreRefreshTokenOriginalRequester(requester Requester) Requester {
	r := a.Sanitize(nil).(*Request)

	ar := &AccessRequest{
		Request: *r,
	}

	ar.SetID(requester.GetID())

	ar.SetRequestedScopes(requester.GetRequestedScopes())
	ar.SetGrantedScopes(requester.GetGrantedScopes())

	ar.SetRequestedAudience(requester.GetRequestedAudience())
	ar.GrantedAudience = nil

	for _, audience := range requester.GetGrantedAudience() {
		ar.GrantAudience(audience)
	}

	ar.SetRequestedResource(requester.GetRequestedResource())
	ar.GrantedResource = nil

	for _, resource := range requester.GetGrantedResource() {
		ar.GrantResource(resource)
	}

	ar.SetRequestedAuthorizationDetails(requester.GetRequestedAuthorizationDetails())
	ar.SetGrantedAuthorizationDetails(requester.GetGrantedAuthorizationDetails())

	return ar
}
