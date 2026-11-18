// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"net/http"
	"strings"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

// GrantManagementRequester is a validated and authorized request to the Grant Management API.
//
// See: https://openid.net/specs/oauth-v2-grant-management.html#section-6
type GrantManagementRequester interface {
	// GetMethod returns the HTTP method of the request.
	GetMethod() (method string)

	// GetClient returns the client the access token was issued to.
	GetClient() (client Client)

	// GetGrantID returns the 'grant_id' of the grant resource URL.
	GetGrantID() (id string)
}

// GrantManagementResponder is the response of the Grant Management API.
//
// See: https://openid.net/specs/oauth-v2-grant-management.html#section-6
type GrantManagementResponder interface {
	// GetStatusCode returns the HTTP status code.
	GetStatusCode() (code int)

	// GetBody returns the response body, or nil when the response has none.
	GetBody() (body *GrantManagementResponseBody)
}

// GrantManagementResponseBody is the status of a grant. The audience of the grant is not part of it.
//
// See: https://openid.net/specs/oauth-v2-grant-management.html#section-6.4
type GrantManagementResponseBody struct {
	Scopes               []GrantScope         `json:"scopes,omitempty"`
	Claims               []string             `json:"claims,omitempty"`
	AuthorizationDetails AuthorizationDetails `json:"authorization_details,omitempty"`
	CreatedAt            int64                `json:"created_at,omitempty"`
	LastUpdatedAt        int64                `json:"last_updated_at,omitempty"`
	ExpiresAt            int64                `json:"expires_at,omitempty"`
	UpdatedBy            string               `json:"updated_by,omitempty"`
}

// GrantManagementRequest is the default GrantManagementRequester.
type GrantManagementRequest struct {
	Method  string
	Client  Client
	GrantID string
}

// GetMethod returns the HTTP method of the request.
func (r *GrantManagementRequest) GetMethod() (method string) { return r.Method }

// GetClient returns the client the access token was issued to.
func (r *GrantManagementRequest) GetClient() (client Client) { return r.Client }

// GetGrantID returns the 'grant_id' of the grant resource URL.
func (r *GrantManagementRequest) GetGrantID() (id string) { return r.GrantID }

// GrantManagementResponse is the default GrantManagementResponder.
type GrantManagementResponse struct {
	StatusCode int
	Body       *GrantManagementResponseBody
}

// GetStatusCode returns the HTTP status code.
func (r *GrantManagementResponse) GetStatusCode() (code int) { return r.StatusCode }

// GetBody returns the response body, or nil when the response has none.
func (r *GrantManagementResponse) GetBody() (body *GrantManagementResponseBody) { return r.Body }

// NewGrantManagementRequest authorizes a request to the Grant Management API for the grant the caller routed it to.
// Only the supported methods of GET and DELETE are served. The access token is read from the Authorization header
// only, must carry the configured audience, and needs 'grant_management_query' for GET and 'grant_management_revoke'
// for DELETE.
//
// The session passed in must implement DPoPBoundSession and MTLSBoundSession, otherwise a bound token looks unbound and
// its binding is not enforced.
//
// See: https://openid.net/specs/oauth-v2-grant-management.html#section-6.2
// See: https://openid.net/specs/oauth-v2-grant-management.html#section-6.6
func (f *Fosite) NewGrantManagementRequest(ctx context.Context, r *http.Request, grantID string, session Session) (requester GrantManagementRequester, err error) {
	var config *GrantManagementConfig

	if config, _, err = f.grantManagement(ctx); err != nil {
		return nil, err
	}

	if !f.hasGrantManagementHandler(ctx) {
		return nil, errorsx.WithStack(ErrServerError.WithDebug("Grant management is not configured."))
	}

	var scope string

	if scope, err = grantManagementMethodScope(config, r.Method); err != nil {
		return nil, err
	}

	audience := config.Audience

	if audience == "" {
		audience = f.Config.GetIssuer(ctx)
	}

	if audience == "" {
		return nil, errorsx.WithStack(ErrServerError.WithDebug("Grant management is not configured with an audience."))
	}

	var (
		token string
		ar    AccessRequester
	)

	if token, ar, err = f.introspectBearerCredential(ctx, r, session); err != nil {
		return nil, err
	}

	if err = ValidateBearerAuthorization(ctx, f.Config, r, ar, token, BearerAuthorization{
		Audiences: []string{audience},
		Scopes:    []string{scope},
	}); err != nil {
		return nil, err
	}

	client := ar.GetClient()

	if client == nil || client.GetID() == "" {
		return nil, errorsx.WithStack(ErrInvalidToken.WithHint("The Access Token is missing, malformed, or invalid.").WithDebug("The credential does not identify a client."))
	}

	if grantID == "" {
		return nil, errorsx.WithStack(ErrNotFound.WithDebug("The request does not identify a grant."))
	}

	return &GrantManagementRequest{Method: r.Method, Client: client, GrantID: grantID}, nil
}

func (f *Fosite) grantManagement(ctx context.Context) (config *GrantManagementConfig, storage GrantManagementStorage, err error) {
	if provider, ok := f.Config.(GrantManagementConfigProvider); ok {
		config = provider.GetGrantManagementConfig(ctx)
	}

	if config == nil {
		return nil, nil, errorsx.WithStack(ErrServerError.WithDebug("Grant management is not configured."))
	}

	var ok bool

	if storage, ok = f.Store.(GrantManagementStorage); !ok {
		return nil, nil, errorsx.WithStack(ErrServerError.WithDebug("Grant management is not configured."))
	}

	return config, storage, nil
}

func grantManagementMethodScope(config *GrantManagementConfig, method string) (scope string, err error) {
	switch {
	case method == http.MethodGet && config.Supports(GrantManagementActionQuery):
		return consts.ScopeGrantManagementQuery, nil
	case method == http.MethodDelete && config.Supports(GrantManagementActionRevoke):
		return consts.ScopeGrantManagementRevoke, nil
	default:
		return "", errorsx.WithStack(ErrInvalidRequest.WithHintf("HTTP method is '%s', expected one of '%s'.", method, grantManagementAllowedMethods(config)).WithCode(http.StatusMethodNotAllowed))
	}
}

func grantManagementAllowedMethods(config *GrantManagementConfig) (allow string) {
	var methods []string

	if config.Supports(GrantManagementActionQuery) {
		methods = append(methods, http.MethodGet)
	}

	if config.Supports(GrantManagementActionRevoke) {
		methods = append(methods, http.MethodDelete)
	}

	return strings.Join(methods, ", ")
}
