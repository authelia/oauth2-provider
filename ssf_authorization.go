// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

// authorizeSSFRequest authenticates a request to an SSF management endpoint with an Access Token. Reads require
// 'ssf.read' or 'ssf.manage' and writes require 'ssf.manage'. The token audience must be the configured audience; the
// request URL is never a fallback.
//
// The token is read only from the Authorization header, using the Bearer or DPoP scheme. An 'access_token' parameter
// alongside it is 'invalid_request' (RFC 6750 Section 2).
//
// The session passed in must implement DPoPBoundSession and MTLSBoundSession, otherwise a bound token looks unbound and
// its binding is not enforced.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8
// See: https://openid.net/specs/openid-caep-interoperability-profile-1_0.html#section-2.7.2
// See: https://openid.net/specs/openid-caep-interoperability-profile-1_0.html#section-2.7.3
func (f *Fosite) authorizeSSFRequest(ctx context.Context, r *http.Request, session Session, write bool) (requester AccessRequester, storage SSFStreamStorage, err error) {
	var config *SSFConfig

	if config = f.getSSFConfig(ctx); config == nil || config.Audience == "" {
		return nil, nil, errorsx.WithStack(ErrServerError.WithDebug("The Shared Signals Framework transmitter is not configured with an audience."))
	}

	var token string

	if token, err = ssfCredentialFromRequest(r); err != nil {
		return nil, nil, err
	}

	if token == "" {
		return nil, nil, errorsx.WithStack(ErrInvalidToken.WithHint("The request did not include an Access Token."))
	}

	var (
		use TokenUse
		ar  AccessRequester
	)

	if use, ar, err = f.IntrospectToken(ctx, token, AccessToken, session); errors.Is(err, ErrServerError) {
		return nil, nil, err
	} else if err != nil {
		return nil, nil, errorsx.WithStack(ErrInvalidToken.WithHint("The Access Token is missing, malformed, or invalid.").WithWrap(err).WithDebugError(err))
	} else if use != "" && use != AccessToken {
		return nil, nil, errorsx.WithStack(ErrInvalidToken.WithHint("The Access Token is missing, malformed, or invalid.").WithDebugf("The credential was of type '%s' rather than 'access_token'.", use))
	}

	scopes := []string{consts.ScopeSSFManage}

	if !write {
		scopes = []string{consts.ScopeSSFRead, consts.ScopeSSFManage}
	}

	if err = ValidateBearerAuthorization(ctx, f.Config, r, ar, token, BearerAuthorization{
		Audiences: []string{config.Audience},
		Scopes:    scopes,
	}); err != nil {
		return nil, nil, err
	}

	// The client ID is the only stream ownership boundary (SSF Section 8), so a credential without a client is invalid.
	if client := ar.GetClient(); client == nil || client.GetID() == "" {
		return nil, nil, errorsx.WithStack(ErrInvalidToken.WithHint("The Access Token is missing, malformed, or invalid.").WithDebug("The credential does not identify a client."))
	}

	var ok bool

	if storage, ok = f.Store.(SSFStreamStorage); !ok {
		return nil, nil, errorsx.WithStack(ErrServerError.WithDebug("The storage does not implement SSFStreamStorage."))
	}

	return ar, storage, nil
}

// ssfCredentialFromRequest returns the token of the Authorization header, or empty when it has no Bearer or DPoP
// credential. An 'access_token' parameter is never used as the token (CAEP profile Section 2.7.3), and is rejected
// alongside a token in the header (RFC 6750 Section 2). A form body is not parsed here, as these endpoints reject one.
func ssfCredentialFromRequest(r *http.Request) (token string, err error) {
	var scheme, value string

	if scheme, value, err = AuthorizationCredentialFromRequest(r); err != nil {
		return "", err
	}

	if !strings.EqualFold(scheme, BearerAccessToken) && !strings.EqualFold(scheme, DPoPAccessToken) {
		return "", nil
	}

	if value != "" && (r.URL.Query().Get(consts.FormParameterAccessToken) != "" || r.Form.Get(consts.FormParameterAccessToken) != "") {
		return "", errorsx.WithStack(ErrInvalidRequest.WithHint("Multiple methods used to include access token."))
	}

	return value, nil
}
