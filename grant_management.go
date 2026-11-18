// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"authelia.com/provider/oauth2/internal/consts"
)

// GrantManagementAction is a 'grant_management_action' authorization request parameter value or a Grant Management
// API action.
//
// See: https://openid.net/specs/oauth-v2-grant-management.html#section-5.2
type GrantManagementAction string

const (
	// GrantManagementActionCreate requests a new grant.
	//
	// See: https://openid.net/specs/oauth-v2-grant-management.html#section-5.2
	GrantManagementActionCreate GrantManagementAction = consts.GrantManagementActionCreate

	// GrantManagementActionMerge requests the consented permissions be added to an existing grant.
	//
	// See: https://openid.net/specs/oauth-v2-grant-management.html#section-5.2
	GrantManagementActionMerge GrantManagementAction = consts.GrantManagementActionMerge

	// GrantManagementActionReplace requests the consented permissions replace those of an existing grant.
	//
	// See: https://openid.net/specs/oauth-v2-grant-management.html#section-5.2
	GrantManagementActionReplace GrantManagementAction = consts.GrantManagementActionReplace

	// GrantManagementActionQuery is the Grant Management API action which queries the status of a grant.
	//
	// See: https://openid.net/specs/oauth-v2-grant-management.html#section-6.4
	GrantManagementActionQuery GrantManagementAction = consts.GrantManagementActionQuery

	// GrantManagementActionRevoke is the Grant Management API action which revokes a grant.
	//
	// See: https://openid.net/specs/oauth-v2-grant-management.html#section-6.5
	GrantManagementActionRevoke GrantManagementAction = consts.GrantManagementActionRevoke
)

const (
	// GrantUpdatedByClient is the Grant UpdatedBy value of a grant last updated by a request of the client.
	//
	// See: https://openid.net/specs/oauth-v2-grant-management.html#section-5.6
	GrantUpdatedByClient = consts.GrantUpdatedByClient

	// GrantUpdatedByAuthorizationServer is the Grant UpdatedBy value of a grant last updated by the authorization
	// server.
	//
	// See: https://openid.net/specs/oauth-v2-grant-management.html#section-5.6
	GrantUpdatedByAuthorizationServer = consts.GrantUpdatedByAuthorizationServer
)

// GrantManagementConfig is the grant management configuration of the authorization server.
//
// See: https://openid.net/specs/oauth-v2-grant-management.html#section-7.1
type GrantManagementConfig struct {
	// Actions is the supported actions, advertised as 'grant_management_actions_supported'.
	Actions []GrantManagementAction

	// Endpoint is the URL of the Grant Management API, advertised as 'grant_management_endpoint'.
	Endpoint string

	// ActionRequired is true if every authorization request must carry a 'grant_management_action', advertised as
	// 'grant_management_action_required'.
	ActionRequired bool

	// Audience is the audience an access token must carry at the Grant Management API. Empty means the issuer.
	Audience string
}

// Supports returns true if the action is one of the supported actions.
//
// See: https://openid.net/specs/oauth-v2-grant-management.html#section-7.1
func (c *GrantManagementConfig) Supports(action GrantManagementAction) bool {
	return c != nil && slices.Contains(c.Actions, action)
}

// GrantScope is a scope value of a grant and the resources it applies to.
//
// See: https://openid.net/specs/oauth-v2-grant-management.html#section-6.4
type GrantScope struct {
	Scope    string   `json:"scope,omitempty"`
	Resource []string `json:"resource,omitempty"`
}

// GrantPermissions is the consented permission set of a grant.
//
// See: https://openid.net/specs/oauth-v2-grant-management.html#section-6.4
type GrantPermissions struct {
	Scopes               []GrantScope         `json:"scopes,omitempty"`
	Audience             []string             `json:"audience,omitempty"`
	Claims               []string             `json:"claims,omitempty"`
	AuthorizationDetails AuthorizationDetails `json:"authorization_details,omitempty"`
}

// ScopeValues returns every scope value of the permissions, deduplicated. A scope of the permissions is a space
// delimited list of scope values.
//
// See: https://openid.net/specs/oauth-v2-grant-management.html#section-6.4
func (p *GrantPermissions) ScopeValues() (scopes Arguments) {
	if p == nil {
		return nil
	}

	for _, scope := range p.Scopes {
		scopes = appendDistinct(scopes, strings.Fields(scope.Scope))
	}

	return scopes
}

// ResourceValues returns every resource the scopes of the permissions apply to, deduplicated.
func (p *GrantPermissions) ResourceValues() (resources Arguments) {
	if p == nil {
		return nil
	}

	for _, scope := range p.Scopes {
		resources = appendDistinct(resources, scope.Resource)
	}

	return resources
}

// Merge returns the union of the permissions and other as a new value which shares no memory with either. Scopes are
// united by scope value and their resources united; authorization details objects which are equal as JSON are kept
// once.
//
// See: https://openid.net/specs/oauth-v2-grant-management.html#section-5.2
func (p *GrantPermissions) Merge(other *GrantPermissions) (merged *GrantPermissions) {
	if merged = p.Clone(); merged == nil {
		merged = &GrantPermissions{}
	}

	if other == nil {
		return merged
	}

	for _, scope := range other.Scopes {
		if i := slices.IndexFunc(merged.Scopes, func(s GrantScope) bool { return s.Scope == scope.Scope }); i >= 0 {
			merged.Scopes[i].Resource = appendDistinct(merged.Scopes[i].Resource, scope.Resource)
		} else {
			merged.Scopes = append(merged.Scopes, GrantScope{Scope: scope.Scope, Resource: slices.Clone(scope.Resource)})
		}
	}

	merged.Audience = appendDistinct(merged.Audience, other.Audience)
	merged.Claims = appendDistinct(merged.Claims, other.Claims)

	for _, detail := range other.AuthorizationDetails {
		if !slices.ContainsFunc(merged.AuthorizationDetails, func(d AuthorizationDetail) bool { return equalAuthorizationDetail(d, detail) }) {
			merged.AuthorizationDetails = append(merged.AuthorizationDetails, detail.Clone())
		}
	}

	return merged
}

// Clone returns a deep copy of the permissions, or nil when the receiver is nil.
func (p *GrantPermissions) Clone() (cloned *GrantPermissions) {
	if p == nil {
		return nil
	}

	cloned = &GrantPermissions{
		Audience:             slices.Clone(p.Audience),
		Claims:               slices.Clone(p.Claims),
		AuthorizationDetails: p.AuthorizationDetails.Clone(),
	}

	if p.Scopes != nil {
		cloned.Scopes = make([]GrantScope, len(p.Scopes))

		for i, scope := range p.Scopes {
			cloned.Scopes[i] = GrantScope{Scope: scope.Scope, Resource: slices.Clone(scope.Resource)}
		}
	}

	return cloned
}

// Grant is the record of the permissions a resource owner consented to for a client, and of the requests which issued
// tokens under it.
//
// See: https://openid.net/specs/oauth-v2-grant-management.html#section-5.6
type Grant struct {
	// ID is the 'grant_id'.
	ID string

	// ClientID is the identifier of the client the grant was issued to.
	ClientID string

	// Subject is the resource owner who consented to the grant.
	Subject string

	// Permissions is the consented permission set.
	Permissions GrantPermissions

	// CreatedAt is when the grant was created.
	CreatedAt time.Time

	// UpdatedAt is when the grant was last updated.
	UpdatedAt time.Time

	// ExpiresAt is when the grant expires, or the zero time when it does not.
	ExpiresAt time.Time

	// UpdatedBy is the party which last updated the grant, either 'client' or 'authorization_server'.
	UpdatedBy string

	// RequestIDs identifies the requests which issued tokens under the grant.
	RequestIDs []string
}

// Clone returns a deep copy of the grant, or nil when the receiver is nil.
func (g *Grant) Clone() (cloned *Grant) {
	if g == nil {
		return nil
	}

	c := *g

	c.Permissions = *g.Permissions.Clone()
	c.RequestIDs = slices.Clone(g.RequestIDs)

	return &c
}

// GrantManagementStorage persists grants and revokes the tokens issued under them. The grant methods must not alias
// the caller's grant: CreateGrant and UpdateGrant store a copy, and GetGrant returns one.
// The RequestIDs of a stored grant change only through AppendGrantRequestID, ReplaceGrantRequestIDs and DeleteGrant,
// which a store must apply atomically: the tokens of a request ID which is lost survive the revocation of the grant.
//
// See: https://openid.net/specs/oauth-v2-grant-management.html#section-5.6
type GrantManagementStorage interface {
	// CreateGrant stores a new grant. It must fail when a grant with the same ID exists.
	CreateGrant(ctx context.Context, grant *Grant) (err error)

	// GetGrant returns the grant with the given ID, or ErrNotFound when there is none.
	GetGrant(ctx context.Context, id string) (grant *Grant, err error)

	// UpdateGrant replaces every field of the grant other than RequestIDs, which keep their stored value, or returns
	// ErrNotFound when there is none.
	UpdateGrant(ctx context.Context, grant *Grant) (err error)

	// AppendGrantRequestID atomically adds requestID to the grant's RequestIDs when absent. It returns ErrNotFound
	// when the grant does not exist.
	AppendGrantRequestID(ctx context.Context, id string, requestID string) (err error)

	// ReplaceGrantRequestIDs atomically replaces the grant's RequestIDs and returns the previous ones, which must not
	// alias the stored state. It returns ErrNotFound when the grant does not exist.
	ReplaceGrantRequestIDs(ctx context.Context, id string, requestIDs []string) (previous []string, err error)

	// DeleteGrant atomically deletes the grant with the given ID and returns the RequestIDs it had when deleted,
	// which must not alias the stored state. It returns ErrNotFound when the grant does not exist.
	DeleteGrant(ctx context.Context, id string) (requestIDs []string, err error)

	// RevokeRefreshToken revokes every refresh token issued for the request ID.
	RevokeRefreshToken(ctx context.Context, requestID string) (err error)

	// RevokeAccessToken revokes every access token issued for the request ID.
	RevokeAccessToken(ctx context.Context, requestID string) (err error)
}

// GrantManagementSession is implemented by a Session which records the grant its tokens are issued under.
//
// See: https://openid.net/specs/oauth-v2-grant-management.html#section-5.5
type GrantManagementSession interface {
	// GetGrantID returns the 'grant_id' of the grant, or an empty string when there is none.
	GetGrantID() (id string)

	// SetGrantID sets the 'grant_id' of the grant.
	SetGrantID(id string)

	// GetGrantManagementAction returns the 'grant_management_action' the grant was authorized with, or an empty
	// string when there is none.
	GetGrantManagementAction() (action GrantManagementAction)

	// SetGrantManagementAction sets the 'grant_management_action' the grant was authorized with.
	SetGrantManagementAction(action GrantManagementAction)

	// GetGrantPermissions returns the permission set of the grant resulting from the authorization, or nil when there
	// is none.
	GetGrantPermissions() (permissions *GrantPermissions)

	// SetGrantPermissions sets the permission set of the grant resulting from the authorization.
	SetGrantPermissions(permissions *GrantPermissions)
}

// GrantManagementHandler is implemented by the handler that implements OpenID Grant Management for OAuth 2.0.
//
// See: https://openid.net/specs/oauth-v2-grant-management.html#section-7.1
type GrantManagementHandler interface {
	// HandlesGrantManagement returns true if the handler is configured to process grant management requests.
	HandlesGrantManagement(ctx context.Context) (enabled bool)
}

// NewGrantID returns a new 'grant_id': 128 bits from the cryptographic random source, base64url encoded without
// padding.
//
// See: https://openid.net/specs/oauth-v2-grant-management.html#section-5.5
func NewGrantID() (id string, err error) {
	b := make([]byte, 16)

	if _, err = rand.Read(b); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}

func appendDistinct[S ~[]string](values S, add []string) S {
	for _, value := range add {
		if !slices.Contains(values, value) {
			values = append(values, value)
		}
	}

	return values
}

func equalAuthorizationDetail(a, b AuthorizationDetail) bool {
	x, err := json.Marshal(a)
	if err != nil {
		return false
	}

	y, err := json.Marshal(b)
	if err != nil {
		return false
	}

	return bytes.Equal(x, y)
}
