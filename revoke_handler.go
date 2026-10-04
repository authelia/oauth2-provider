// SPDX-FileCopyrightText: 2026 Authelia
//
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

// NewRevocationRequest handles incoming token revocation requests and validates various parameters.
//
// See: https://datatracker.ietf.org/doc/html/rfc7009#section-2.1
// See: https://datatracker.ietf.org/doc/html/rfc7009#section-2.2
func (f *Fosite) NewRevocationRequest(ctx context.Context, r *http.Request) error {
	ctx = context.WithValue(ctx, RequestContextKey, r)

	if r.Method != http.MethodPost {
		return errorsx.WithStack(ErrInvalidRequest.WithHintf("HTTP method is '%s' but expected 'POST'.", r.Method))
	} else if err := r.ParseMultipartForm(1 << 20); err != nil && err != http.ErrNotMultipart {
		return errorsx.WithStack(ErrInvalidRequest.WithHint("Unable to parse HTTP body, make sure to send a properly formatted form request body.").WithWrap(err).WithDebugError(err))
	} else if len(r.PostForm) == 0 {
		return errorsx.WithStack(ErrInvalidRequest.WithHint("The POST body can not be empty."))
	}

	client, _, err := f.AuthenticateClientWithAuthHandler(ctx, r, r.PostForm, f.Config.GetRevocationEndpointClientAuthStrategy(ctx))
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

// WriteRevocationResponse writes a token revocation response.
//
// See: https://datatracker.ietf.org/doc/html/rfc7009#section-2.2
func (f *Fosite) WriteRevocationResponse(ctx context.Context, rw http.ResponseWriter, err error) {
	rw.Header().Set(consts.HeaderCacheControl, consts.CacheControlNoStore)
	rw.Header().Set(consts.HeaderPragma, consts.PragmaNoCache)

	switch {
	case err == nil:
		rw.WriteHeader(http.StatusOK)
	case errors.Is(err, ErrInvalidRequest):
		f.writeRevocationResponseError(ctx, rw, ErrInvalidRequest)
	case errors.Is(err, ErrInvalidClient):
		setClientAuthenticationChallenge(rw, ErrorToRFC6749Error(err))
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
