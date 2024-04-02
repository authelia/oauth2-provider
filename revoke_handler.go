// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

// NewRevocationRequest handles incoming token revocation requests and
// validates various parameters as specified in:
// https://datatracker.ietf.org/doc/html/rfc7009#section-2.1
//
// The authorization server first validates the client credentials (in
// case of a confidential client) and then verifies whether the token
// was issued to the client making the revocation request.  If this
// validation fails, the request is refused and the client is informed
// of the error by the authorization server as described below.
//
// In the next step, the authorization server invalidates the token.
// The invalidation takes place immediately, and the token cannot be
// used again after the revocation.
//
// * https://datatracker.ietf.org/doc/html/rfc7009#section-2.2
// An invalid token type hint value is ignored by the authorization
// server and does not influence the revocation response.
func (f *Fosite) NewRevocationRequest(ctx context.Context, r *http.Request) error {
	ctx = context.WithValue(ctx, RequestContextKey, r)

	if r.Method != http.MethodPost {
		return errorsx.WithStack(ErrInvalidRequest.WithHintf("HTTP method is '%s' but expected 'POST'.", r.Method))
	} else if err := r.ParseMultipartForm(1 << 20); err != nil && err != http.ErrNotMultipart {
		return errorsx.WithStack(ErrInvalidRequest.WithHint("Unable to parse HTTP body, make sure to send a properly formatted form request body.").WithWrap(err).WithDebugError(err))
	} else if len(r.PostForm) == 0 {
		return errorsx.WithStack(ErrInvalidRequest.WithHint("The POST body can not be empty."))
	}

	client, _, err := f.AuthenticateClient(ctx, r, r.PostForm)
	if err != nil {
		return err
	}

	token := r.PostForm.Get(consts.FormParameterToken)
	tokenTypeHint := TokenType(r.PostForm.Get(consts.FormParameterTokenTypeHint))

	var found = false
	for _, loader := range f.Config.GetRevocationHandlers(ctx) {
		if err = loader.RevokeToken(ctx, token, tokenTypeHint, client); err == nil {
			found = true
		} else if errors.Is(err, ErrUnknownRequest) {
			// do nothing
		} else if err != nil {
			return err
		}
	}

	if !found {
		return errorsx.WithStack(ErrInvalidRequest)
	}

	return nil
}

// WriteRevocationResponse writes a token revocation response as specified in:
// https://datatracker.ietf.org/doc/html/rfc7009#section-2.2
//
// The authorization server responds with HTTP status code 200 if the
// token has been revoked successfully or if the client submitted an
// invalid token.
//
// Note: invalid tokens do not cause an error response since the client
// cannot handle such an error in a reasonable way.  Moreover, the
// purpose of the revocation request, invalidating the particular token,
// is already achieved.
func (f *Fosite) WriteRevocationResponse(ctx context.Context, rw http.ResponseWriter, err error) {
	rw.Header().Set(consts.HeaderCacheControl, consts.CacheControlNoStore)
	rw.Header().Set(consts.HeaderPragma, consts.PragmaNoCache)

	switch {
	case err == nil:
		rw.WriteHeader(http.StatusOK)
	case errors.Is(err, ErrInvalidRequest):
		f.writeRevocationResponseError(ctx, rw, ErrInvalidRequest)
	case errors.Is(err, ErrInvalidClient):
		f.writeRevocationResponseError(ctx, rw, ErrInvalidClient)
	case errors.Is(err, ErrInvalidGrant):
		f.writeRevocationResponseError(ctx, rw, ErrInvalidGrant)
	case errors.Is(err, ErrUnauthorizedClient):
		f.writeRevocationResponseError(ctx, rw, ErrUnauthorizedClient)
	case errors.Is(err, ErrUnsupportedGrantType):
		f.writeRevocationResponseError(ctx, rw, ErrUnsupportedGrantType)
	case errors.Is(err, ErrInvalidScope):
		f.writeRevocationResponseError(ctx, rw, ErrInvalidScope)
	default:
		rw.WriteHeader(http.StatusInternalServerError)
	}
}

//nolint:unparam
func (f *Fosite) writeRevocationResponseError(ctx context.Context, rw http.ResponseWriter, rfc *RFC6749Error) {
	rw.Header().Set(consts.HeaderContentType, consts.ContentTypeApplicationJSON)

	js, err := json.Marshal(rfc)
	if err != nil {
		http.Error(rw, fmt.Sprintf(`{"error": "%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	rw.WriteHeader(rfc.CodeField)

	_, _ = rw.Write(js)
}
