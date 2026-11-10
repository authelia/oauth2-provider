// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"net/http"
	"strings"

	"github.com/pkg/errors"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

type TokenIntrospector interface {
	IntrospectToken(ctx context.Context, token string, tokenUseHint TokenUse, request AccessRequester, scopes []string) (tokenUse TokenUse, err error)
}

// AuthorizationCredentialFromRequest returns the scheme and token of the Authorization header, with both empty when the
// header is absent or has no separator. More than one header is 'invalid_request' (RFC 9449 Section 7.2), and one or more
// spaces separate the scheme from the token (RFC 9110 Section 11.4). The caller decides which schemes it permits.
func AuthorizationCredentialFromRequest(r *http.Request) (scheme, token string, err error) {
	if len(r.Header.Values(consts.HeaderAuthorization)) > 1 {
		return "", "", errorsx.WithStack(ErrInvalidRequest.WithHint("Multiple methods used to include access token."))
	}

	var found bool

	if scheme, token, found = strings.Cut(r.Header.Get(consts.HeaderAuthorization), " "); !found {
		return "", "", nil
	}

	return scheme, strings.TrimLeft(token, " "), nil
}

// AccessTokenFromRequest extracts a bearer access token from an HTTP request. Per RFC 6750 the token may be supplied in
// the Authorization header (Bearer scheme) or as the 'access_token' form parameter. Returns the empty string if no
// token can be located.
func AccessTokenFromRequest(r *http.Request) string {
	// RFC 6750: the Authorization header is tried first, then the 'access_token' parameter.

	auth := r.Header.Get(consts.HeaderAuthorization)
	split := strings.SplitN(auth, " ", 2)

	if len(split) != 2 || !strings.EqualFold(split[0], BearerAccessToken) {
		// Nothing in Authorization header, try access_token
		// Empty string returned if there's no such parameter
		if err := r.ParseForm(); err != nil {
			return ""
		}

		return r.Form.Get(consts.FormParameterAccessToken)
	}

	return split[1]
}

// IntrospectToken validates the provided opaque or structured token against each configured TokenIntrospector. It
// returns the detected token use (access, refresh, etc.), the populated AccessRequester for downstream callers, or
// ErrRequestUnauthorized if no introspector recognizes the token. The tokenUse argument is treated as a hint that
// introspectors may use to short-circuit when the token type is known in advance.
func (f *Fosite) IntrospectToken(ctx context.Context, token string, tokenUse TokenUse, session Session, scopes ...string) (TokenUse, AccessRequester, error) {
	var found = false
	var foundTokenUse TokenUse = ""

	ar := NewAccessRequest(session)
	for _, validator := range f.Config.GetTokenIntrospectionHandlers(ctx) {
		tu, err := validator.IntrospectToken(ctx, token, tokenUse, ar, scopes)

		switch {
		case err == nil:
			found = true
			foundTokenUse = tu
		case errors.Is(err, ErrUnknownRequest):
			break
		default:
			return "", nil, errorsx.WithStack(ErrorToRFC6749Error(err))
		}
	}

	if !found {
		return "", nil, errorsx.WithStack(ErrRequestUnauthorized.WithHint("Unable to find a suitable validation strategy for the token, thus it is invalid."))
	}

	return foundTokenUse, ar, nil
}
