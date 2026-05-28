// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"net/url"
	"time"

	"github.com/google/uuid"
	"golang.org/x/text/language"

	"authelia.com/provider/oauth2/internal/consts"
)

// Request is an implementation of Requester
type Request struct {
	ID                string       `json:"id" gorethink:"id"`
	RequestedAt       time.Time    `json:"requestedAt" gorethink:"requestedAt"`
	Client            Client       `json:"-" gorethink:"client"`
	RequestedScope    Arguments    `json:"scopes" gorethink:"scopes"`
	GrantedScope      Arguments    `json:"grantedScopes" gorethink:"grantedScopes"`
	Form              url.Values   `json:"form" gorethink:"form"`
	Session           Session      `json:"session" gorethink:"session"`
	RequestedAudience Arguments    `json:"requestedAudience"`
	GrantedAudience   Arguments    `json:"grantedAudience"`
	RequestedResource Arguments    `json:"requestedResource"`
	GrantedResource   Arguments    `json:"grantedResource"`
	Lang              language.Tag `json:"-"`
}

// NewRequest returns a Request with its slice and map fields initialized, a default empty client, and RequestedAt set
// to the current time in UTC.
func NewRequest() *Request {
	return &Request{
		Client:            &DefaultClient{},
		RequestedScope:    Arguments{},
		RequestedAudience: Arguments{},
		GrantedAudience:   Arguments{},
		RequestedResource: Arguments{},
		GrantedResource:   Arguments{},
		GrantedScope:      Arguments{},
		Form:              url.Values{},
		RequestedAt:       time.Now().UTC(),
	}
}

// GetID returns the request identifier, generating a new UUID on first access if one has not been assigned.
func (a *Request) GetID() string {
	if a.ID == "" {
		a.ID = uuid.New().String()
	}

	return a.ID
}

// SetID assigns the request identifier. Callers should ensure the value is unique across requests for storage lookups.
func (a *Request) SetID(id string) {
	a.ID = id
}

// GetRequestForm returns the original HTTP form values associated with the request.
func (a *Request) GetRequestForm() url.Values {
	return a.Form
}

// GetRequestedAt returns the time at which the request was received.
func (a *Request) GetRequestedAt() time.Time {
	return a.RequestedAt
}

// SetRequestedAt overrides the time at which the request was received, typically used when restoring requests from
// persistent storage.
func (a *Request) SetRequestedAt(rat time.Time) {
	a.RequestedAt = rat
}

// GetClient returns the OAuth 2.0 client associated with the request.
func (a *Request) GetClient() Client {
	return a.Client
}

// GetRequestedScopes returns the scopes asked for by the client.
func (a *Request) GetRequestedScopes() Arguments {
	return a.RequestedScope
}

// SetRequestedScopes replaces the requested scopes, de-duplicating entries.
func (a *Request) SetRequestedScopes(s Arguments) {
	a.RequestedScope = nil

	for _, scope := range s {
		a.AppendRequestedScope(scope)
	}
}

// SetRequestedAudience replaces the requested audience, de-duplicating entries.
func (a *Request) SetRequestedAudience(s Arguments) {
	a.RequestedAudience = nil

	for _, scope := range s {
		a.AppendRequestedAudience(scope)
	}
}

// AppendRequestedScope adds the given scope to the requested scopes if it is not already present.
func (a *Request) AppendRequestedScope(scope string) {
	for _, has := range a.RequestedScope {
		if scope == has {
			return
		}
	}

	a.RequestedScope = append(a.RequestedScope, scope)
}

// AppendRequestedAudience adds the given audience value to the requested audiences if it is not already present.
func (a *Request) AppendRequestedAudience(audience string) {
	for _, has := range a.RequestedAudience {
		if audience == has {
			return
		}
	}

	a.RequestedAudience = append(a.RequestedAudience, audience)
}

// GetRequestedAudience returns the audience values asked for by the client.
func (a *Request) GetRequestedAudience() (audience Arguments) {
	return a.RequestedAudience
}

// GrantAudience marks the given audience as granted to the client if it is not already present.
func (a *Request) GrantAudience(audience string) {
	for _, has := range a.GrantedAudience {
		if audience == has {
			return
		}
	}

	a.GrantedAudience = append(a.GrantedAudience, audience)
}

// SetRequestedResource replaces the requested RFC 8707 resource indicators, de-duplicating entries.
func (a *Request) SetRequestedResource(s Arguments) {
	a.RequestedResource = nil

	for _, resource := range s {
		a.AppendRequestedResource(resource)
	}
}

// AppendRequestedResource adds the given resource indicator if it is not already present.
func (a *Request) AppendRequestedResource(resource string) {
	for _, has := range a.RequestedResource {
		if resource == has {
			return
		}
	}

	a.RequestedResource = append(a.RequestedResource, resource)
}

// GetRequestedResource returns the RFC 8707 resource indicators asked for by the client.
func (a *Request) GetRequestedResource() Arguments {
	return a.RequestedResource
}

// GrantResource marks the given RFC 8707 resource indicator as granted if it is not already present.
func (a *Request) GrantResource(resource string) {
	for _, has := range a.GrantedResource {
		if resource == has {
			return
		}
	}

	a.GrantedResource = append(a.GrantedResource, resource)
}

// GetGrantedResource returns the RFC 8707 resource indicators that have been granted to the client.
func (a *Request) GetGrantedResource() Arguments {
	return a.GrantedResource
}

// GetGrantedScopes returns the scopes that have been granted to the client.
func (a *Request) GetGrantedScopes() Arguments {
	return a.GrantedScope
}

// GetGrantedAudience returns the audience values that have been granted to the client.
func (a *Request) GetGrantedAudience() Arguments {
	return a.GrantedAudience
}

// GrantScope marks the given scope as granted to the client if it is not already present.
func (a *Request) GrantScope(scope string) {
	for _, has := range a.GrantedScope {
		if scope == has {
			return
		}
	}
	a.GrantedScope = append(a.GrantedScope, scope)
}

// SetSession sets the session associated with the request.
func (a *Request) SetSession(session Session) {
	a.Session = session
}

// GetSession returns the session associated with the request, or nil if none has been set.
func (a *Request) GetSession() Session {
	return a.Session
}

// Merge copies the requested and granted scopes, audiences and resource indicators from the given Requester into this
// request alongside its ID, RequestedAt timestamp, client, session, and form values.
func (a *Request) Merge(request Requester) {
	for _, scope := range request.GetRequestedScopes() {
		a.AppendRequestedScope(scope)
	}

	for _, scope := range request.GetGrantedScopes() {
		a.GrantScope(scope)
	}

	for _, aud := range request.GetRequestedAudience() {
		a.AppendRequestedAudience(aud)
	}

	for _, aud := range request.GetGrantedAudience() {
		a.GrantAudience(aud)
	}

	for _, resource := range request.GetRequestedResource() {
		a.AppendRequestedResource(resource)
	}

	for _, resource := range request.GetGrantedResource() {
		a.GrantResource(resource)
	}

	a.ID = request.GetID()
	a.RequestedAt = request.GetRequestedAt()
	a.Client = request.GetClient()
	a.Session = request.GetSession()

	for k, v := range request.GetRequestForm() {
		a.Form[k] = v
	}
}

var alwaysAllowedParameters = []string{
	consts.FormParameterGrantType,
	consts.FormParameterResponseType,
	consts.FormParameterScope,
	consts.FormParameterClientID,
}

// Sanitize returns a shallow copy of the request with its form values restricted to allowedParameters and a small set
// of always-allowed parameters (grant_type, response_type, scope, client_id). It is used by handlers to scrub
// credentials and other sensitive form fields before persisting the request to storage.
func (a *Request) Sanitize(allowedParameters []string) Requester {
	b := new(Request)
	allowed := map[string]bool{}
	for _, v := range allowedParameters {
		allowed[v] = true
	}

	for _, v := range alwaysAllowedParameters {
		if _, ok := allowed[v]; !ok {
			allowed[v] = true
		}
	}

	*b = *a
	b.ID = a.GetID()
	b.Form = url.Values{}
	for k := range a.Form {
		if allowed[k] {
			b.Form[k] = a.Form[k]
		}
	}

	return b
}

// GetLang returns the language tag negotiated for the request, used to localize error descriptions.
func (a *Request) GetLang() language.Tag {
	return a.Lang
}
