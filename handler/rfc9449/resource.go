// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc9449

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"strings"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

// AccessTokenFromRequest extracts the access token from an HTTP request and reports whether it was presented under the
// RFC 9449 DPoP authentication scheme (Authorization: DPoP <token>). When the DPoP scheme is not used it falls back to
// oauth2.AccessTokenFromRequest (RFC 6750 Bearer header, access_token form/query parameter), returning dpop=false.
func AccessTokenFromRequest(r *http.Request) (token string, dpop bool) {
	if scheme, value, found := strings.Cut(r.Header.Get(consts.HeaderAuthorization), " "); found && strings.EqualFold(scheme, oauth2.DPoPAccessToken) {
		return value, true
	}

	return oauth2.AccessTokenFromRequest(r), false
}

// ValidateResourceAccess performs the RFC 9449 7.1/7.2 resource-server checks for a DPoP-bound access token. boundJKT is
// the confirmed cnf.jkt the caller obtained via token introspection; accessToken is the raw token value the proof's
// 'ath' claim is verified against. On success it returns the validated proof. It returns an error wrapping
// oauth2.ErrInvalidDPoPProof for any failed check, or oauth2.ErrUseDPoPNonce when a nonce is required but missing or
// invalid, so the caller can respond with a DPoP-Nonce challenge.
//
// The method is intended only for tokens already known to be DPoP-bound; an empty boundJKT is treated as caller misuse.
func (s *DefaultStrategy) ValidateResourceAccess(ctx context.Context, r *http.Request, accessToken, boundJKT string, requireNonce bool) (parsed *oauth2.DPoPProof, err error) {
	if boundJKT == "" {
		return nil, errorsx.WithStack(oauth2.ErrInvalidDPoPProof.WithHint("The access token is not bound to a DPoP key."))
	}

	// RFC 9449 7.2: a DPoP-bound access token MUST be presented under the DPoP authentication scheme; reject a bearer
	// (or any non-DPoP) presentation to prevent downgraded use of the token.
	token, dpop := AccessTokenFromRequest(r)
	if !dpop || token != accessToken {
		// The client-facing hint stays generic so it does not reveal which sub-condition failed; the debug field (only
		// surfaced to clients when the server opts in) records the distinction for operators.
		return nil, errorsx.WithStack(oauth2.ErrInvalidDPoPProof.
			WithHint("The DPoP-bound access token was not presented using the DPoP authentication scheme.").
			WithDebugf("The access token must be presented via the DPoP scheme and match the introspected token (dpop scheme used: %t, token matches: %t).", dpop, token == accessToken))
	}

	var header string

	if header, err = singleDPoPHeader(r); err != nil {
		return nil, err
	}

	if header == "" {
		return nil, errorsx.WithStack(oauth2.ErrInvalidDPoPProof.WithHint("The request to the protected resource requires a DPoP proof but none was provided."))
	}

	if parsed, err = s.ValidateDPoPProof(ctx, r.Method, requestURL(r), header, requireNonce); err != nil {
		return nil, err
	}

	// RFC 9449 4.3 step 12: the 'ath' claim MUST equal the base64url SHA-256 hash of the access token's value.
	if parsed.AccessTokenHash == "" {
		return nil, errorsx.WithStack(oauth2.ErrInvalidDPoPProof.WithHint("The DPoP proof is missing the required 'ath' claim."))
	}

	sum := sha256.Sum256([]byte(accessToken))

	if subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(sum[:])), []byte(parsed.AccessTokenHash)) != 1 {
		return nil, errorsx.WithStack(oauth2.ErrInvalidDPoPProof.WithHint("The DPoP proof 'ath' claim does not match the access token."))
	}

	// RFC 9449 4.3 step 12: the proof's public key MUST match the key the access token is bound to.
	if parsed.Thumbprint != boundJKT {
		return nil, errorsx.WithStack(oauth2.ErrInvalidDPoPProof.WithHint("The DPoP proof key does not match the key the access token is bound to."))
	}

	return parsed, nil
}
