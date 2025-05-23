// Copyright © 2023 Ory Corp
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
	IntrospectToken(ctx context.Context, token string, tokenUseHint TokenUse, requester AccessRequester, scopes []string) (tokenUse TokenUse, err error)
}

func AccessTokenFromRequest(req *http.Request) string {
	// According to https://datatracker.ietf.org/doc/html/rfc6750 you can pass tokens through:
	// - Form-Encoded Body Parameter. Recommended, more likely to appear. e.g.: Authorization: Bearer mytoken123
	// - URI Query Parameter e.g. access_token=mytoken123

	auth := req.Header.Get(consts.HeaderAuthorization)
	split := strings.SplitN(auth, " ", 2)
	if len(split) != 2 || !strings.EqualFold(split[0], BearerAccessToken) {
		// Nothing in Authorization header, try access_token
		// Empty string returned if there's no such parameter
		if err := req.ParseMultipartForm(1 << 20); err != nil && err != http.ErrNotMultipart {
			return ""
		}

		return req.Form.Get(consts.FormParameterAccessToken)
	}

	return split[1]
}

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
