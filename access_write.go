// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"encoding/json"
	"net/http"

	"authelia.com/provider/oauth2/internal/consts"
)

// WriteAccessResponse writes the successful token endpoint response per RFC 6749 section 5.1 as JSON with the required
// cache-control headers. Use WriteAccessError to send error responses.
func (f *Fosite) WriteAccessResponse(ctx context.Context, rw http.ResponseWriter, request AccessRequester, response AccessResponder) {
	rw.Header().Set(consts.HeaderCacheControl, consts.CacheControlNoStore)
	rw.Header().Set(consts.HeaderPragma, consts.PragmaNoCache)

	f.writeDPoPNonceOnSuccess(ctx, rw, request)

	var (
		data []byte
		err  error
	)

	if data, err = json.Marshal(response.ToMap()); err != nil {
		f.writeFallbackJSONError(ctx, rw, err)

		return
	}

	rw.Header().Set(consts.HeaderContentType, consts.ContentTypeApplicationJSON)

	rw.WriteHeader(http.StatusOK)
	_, _ = rw.Write(data)
}

// writeDPoPNonceOnSuccess supplies the client with a fresh nonce to carry into its next DPoP proof, sparing it the
// 'use_dpop_nonce' round trip it would otherwise need to obtain one.
//
// That is only of use when nonces are required. Issuing one otherwise persists a record per token issued, each held
// for the nonce lifespan, which no proof will ever be checked against because ValidateDPoPProof only inspects the
// 'nonce' claim when a nonce is required. It also keeps the server's behaviour aligned with RFC 9449 Section 4.3 step
// 10, which conditions validating the claim on the server having provided a nonce in the first place.
func (f *Fosite) writeDPoPNonceOnSuccess(ctx context.Context, rw http.ResponseWriter, request AccessRequester) {
	if !f.Config.GetDPoPEnabled(ctx) || !f.Config.GetDPoPNonceRequired(ctx) {
		return
	}

	strategy := f.Config.GetDPoPStrategy(ctx)
	if strategy == nil {
		return
	}

	dpop, ok := request.GetSession().(DPoPBoundSession)
	if !ok || dpop.GetDPoPJWKThumbprint() == "" {
		return
	}

	if nonce, nonceErr := strategy.NewDPoPNonce(ctx); nonceErr == nil {
		rw.Header().Set(consts.HeaderDPoPNonce, nonce)
	}
}
