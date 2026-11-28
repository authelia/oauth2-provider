// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"net/http"
	"strings"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

// authorizeSSFRequest authenticates a request to an SSF management endpoint with an Access Token. Reads require
// 'ssf.read' or 'ssf.manage' and writes require 'ssf.manage'. The token audience must be the configured audience; the
// request URL is never a fallback.
//
// The token is read only from the Authorization header, using the Bearer scheme, or the DPoP scheme when DPoP is
// enabled (RFC 9449 Section 7.1). An 'access_token' parameter alongside it is 'invalid_request' (RFC 6750 Section 2).
//
// The session passed in must implement DPoPBoundSession and MTLSBoundSession, otherwise a bound token looks unbound and
// its binding is not enforced.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8
// See: https://openid.net/specs/openid-caep-interoperability-profile-1_0.html#section-2.7.2
// See: https://openid.net/specs/openid-caep-interoperability-profile-1_0.html#section-2.7.3
// See: https://www.rfc-editor.org/rfc/rfc9449.html#section-7.1
func (f *Fosite) authorizeSSFRequest(ctx context.Context, r *http.Request, session Session, write bool) (requester AccessRequester, storage SSFStreamStorage, err error) {
	var (
		config   *SSFConfig
		audience string
	)

	if config = f.getSSFConfig(ctx); config == nil {
		return nil, nil, errorsx.WithStack(ErrServerError.WithDebug("The Shared Signals Framework transmitter is not configured."))
	}

	if audience = f.ssfAudience(ctx, config); audience == "" {
		return nil, nil, errorsx.WithStack(ErrServerError.WithDebug("The Shared Signals Framework transmitter is not configured with an audience."))
	}

	var token string

	if token, err = ssfCredentialFromRequest(r, f.Config.GetDPoPEnabled(ctx)); err != nil {
		return nil, nil, err
	}

	if token == "" {
		return nil, nil, errorsx.WithStack(ErrInvalidToken.WithHint("The request did not include an Access Token."))
	}

	var (
		use TokenUse
		ar  AccessRequester
	)

	use, ar, err = f.IntrospectToken(ctx, token, AccessToken, session)

	if failure, ok := IntrospectionServerFailure(err); ok {
		return nil, nil, failure
	} else if err != nil {
		return nil, nil, errorsx.WithStack(ErrInvalidToken.WithHint("The Access Token is missing, malformed, or invalid.").WithWrap(err).WithDebugError(err))
	} else if use != "" && use != AccessToken {
		return nil, nil, errorsx.WithStack(ErrInvalidToken.WithHint("The Access Token is missing, malformed, or invalid.").WithDebugf("The credential was of type '%s' rather than 'access_token'.", use))
	}

	scopes := []string{consts.ScopeSSFManage}

	if !write {
		scopes = []string{consts.ScopeSSFRead, consts.ScopeSSFManage}
	}

	var client Client

	if client, err = ValidateBearerAuthorization(ctx, f.Config, f.Store, r, ar, token, BearerAuthorization{
		Audiences: []string{audience},
		Scopes:    scopes,
	}); err != nil {
		return nil, nil, err
	}

	// The client ID is the only stream ownership boundary (SSF Section 8), so a credential without a client is invalid.
	if client == nil {
		return nil, nil, errorsx.WithStack(ErrInvalidToken.WithHint("The Access Token is missing, malformed, or invalid.").WithDebug("The credential does not identify a client."))
	}

	// A client resolved from a Client ID Metadata Document is not registered, so it never manages streams.
	//
	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03#section-9.1
	if jwt.IsClientIDMetadataDocumentClient(client) || jwt.IsClientIDMetadataDocumentClient(ar.GetClient()) {
		return nil, nil, errorsx.WithStack(ErrInvalidToken.WithHint("The Access Token is missing, malformed, or invalid.").WithDebug("The Access Token was issued to a client resolved from a Client ID Metadata Document."))
	}

	var ok bool

	if storage, ok = f.Store.(SSFStreamStorage); !ok {
		return nil, nil, errorsx.WithStack(ErrServerError.WithDebug("The storage does not implement SSFStreamStorage."))
	}

	return ar, storage, nil
}

// ssfCredentialFromRequest returns the token of the Authorization header, or empty when it has no Bearer credential
// and, where dpop permits the scheme, no DPoP credential. An 'access_token' parameter is never used as the token (CAEP profile Section 2.7.3), and is rejected
// alongside a token in the header (RFC 6750 Section 2). A form body is not parsed here, as these endpoints reject one.
func ssfCredentialFromRequest(r *http.Request, dpop bool) (token string, err error) {
	var scheme, value string

	if scheme, value, err = AuthorizationCredentialFromRequest(r); err != nil {
		return "", err
	}

	if !strings.EqualFold(scheme, BearerAccessToken) && (!dpop || !strings.EqualFold(scheme, DPoPAccessToken)) {
		return "", nil
	}

	if value != "" && (r.URL.Query().Get(consts.FormParameterAccessToken) != "" || r.Form.Get(consts.FormParameterAccessToken) != "") {
		return "", errorsx.WithStack(ErrInvalidRequest.WithHint("Multiple methods used to include access token."))
	}

	return value, nil
}
