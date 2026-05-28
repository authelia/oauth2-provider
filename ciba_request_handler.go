// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"errors"
	"net/http"

	"authelia.com/provider/oauth2/i18n"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

// NewOpenIDCIBARequest parses and validates an OpenID Connect Client Initiated Backchannel Authentication (CIBA)
// request at the backchannel authentication endpoint per Section 7.1 of the specification. The HTTP method must be
// POST. The client is authenticated using the token endpoint authentication method, and the requested scopes,
// audience, and RFC 8707 resource indicators are validated against the client's registration. Exactly one of
// 'login_hint', 'login_hint_token', or 'id_token_hint' must be present.
func (f *Fosite) NewOpenIDCIBARequest(ctx context.Context, r *http.Request) (requester CIBARequester, err error) {
	request := NewCIBARequest()
	request.Lang = i18n.GetLangFromRequest(f.Config.GetMessageCatalog(ctx), r)

	if r.Method != http.MethodPost {
		return request, errorsx.WithStack(ErrInvalidRequest.WithHintf("HTTP method is '%s', expected 'POST'.", r.Method))
	}

	if err = r.ParseMultipartForm(1 << 20); err != nil && err != http.ErrNotMultipart {
		return request, errorsx.WithStack(ErrInvalidRequest.WithHint("Unable to parse HTTP body, make sure to send a properly formatted form request body.").WithWrap(err).WithDebugError(err))
	}

	request.Form = r.PostForm

	// Authenticate the client in the same way as at the token endpoint (Section 7.1 of [OIDC-CIBA] requires this).
	client, _, err := f.AuthenticateClient(ctx, r, r.Form)
	if err != nil {
		var rfcerr *RFC6749Error
		if errors.As(err, &rfcerr) && rfcerr.ErrorField != ErrInvalidClient.ErrorField {
			return request, errorsx.WithStack(ErrInvalidClient.WithHint("The requested OAuth 2.0 Client could not be authenticated.").WithWrap(err).WithDebugError(err))
		}

		return request, err
	}

	request.Client = client

	if !client.GetGrantTypes().Has(string(GrantTypeOpenIDCIBA)) {
		return request, errorsx.WithStack(ErrInvalidGrant.WithHintf("The requested OAuth 2.0 Client does not have the '%s' grant.", consts.GrantTypeOpenIDCIBA))
	}

	if err = f.validateScope(ctx, r, request); err != nil {
		return request, err
	}

	if !request.GetRequestedScopes().Has(consts.ScopeOpenID) {
		return request, errorsx.WithStack(ErrInvalidRequest.WithHint("The 'scope' parameter is required for OpenID Connect CIBA and must contain the 'openid' scope value."))
	}

	if err = ValidateResourceIndicators(request.Form); err != nil {
		return request, err
	}

	if err = f.validateAudience(ctx, r, request); err != nil {
		return request, err
	}

	hints := 0
	for _, key := range []string{consts.FormParameterLoginHint, consts.FormParameterLoginHintToken, consts.FormParameterIDTokenHint} {
		if request.Form.Get(key) != "" {
			hints++
		}
	}

	switch hints {
	case 1:
		// continue
	case 0:
		return request, errorsx.WithStack(ErrInvalidRequest.WithHint("The CIBA request must include exactly one of 'login_hint', 'login_hint_token', or 'id_token_hint'."))
	default:
		return request, errorsx.WithStack(ErrInvalidRequest.WithHint("The CIBA request must include exactly one of 'login_hint', 'login_hint_token', or 'id_token_hint'."))
	}

	return request, nil
}
