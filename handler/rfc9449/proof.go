// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc9449

import (
	"encoding/json"
	"time"

	"github.com/go-jose/go-jose/v4"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

// ParseProof parses a compact DPoP proof JWT, validates its structural requirements (typ, alg, embedded public jwk,
// signature, and required claims), and returns the validated proof. Request-contextual checks (htm/htu/iat/nonce and
// replay) are performed by the strategy.
func ParseProof(proof string, algorithms []jose.SignatureAlgorithm) (parsed *oauth2.DPoPProof, err error) {
	if proof == "" {
		return nil, errorsx.WithStack(oauth2.ErrInvalidDPoPProof.WithHint("The DPoP proof is missing."))
	}

	var jws *jose.JSONWebSignature

	if jws, err = jose.ParseSignedCompact(proof, algorithms); err != nil {
		return nil, errorsx.WithStack(oauth2.ErrInvalidDPoPProof.WithHintf("The DPoP proof could not be parsed: %s.", err).WithWrap(err))
	}

	if len(jws.Signatures) != 1 {
		return nil, errorsx.WithStack(oauth2.ErrInvalidDPoPProof.WithHint("The DPoP proof must contain exactly one signature."))
	}

	header := jws.Signatures[0].Header

	typ, _ := header.ExtraHeaders[jose.HeaderType].(string)
	if typ != jwt.JSONWebTokenTypeDPoP {
		return nil, errorsx.WithStack(oauth2.ErrInvalidDPoPProof.WithHintf("The DPoP proof has an invalid 'typ' header value of '%s'.", typ))
	}

	jwk := header.JSONWebKey
	if jwk == nil || !jwk.Valid() || !jwk.IsPublic() {
		return nil, errorsx.WithStack(oauth2.ErrInvalidDPoPProof.WithHint("The DPoP proof must contain a valid public 'jwk' header."))
	}

	var payload []byte

	if payload, err = jws.Verify(jwk); err != nil {
		return nil, errorsx.WithStack(oauth2.ErrInvalidDPoPProof.WithHint("The DPoP proof signature is invalid.").WithWrap(err))
	}

	claims := map[string]any{}
	if err = json.Unmarshal(payload, &claims); err != nil {
		return nil, errorsx.WithStack(oauth2.ErrInvalidDPoPProof.WithHint("The DPoP proof claims could not be parsed.").WithWrap(err))
	}

	parsed = &oauth2.DPoPProof{}

	if parsed.ID, _ = claims[consts.ClaimJWTID].(string); parsed.ID == "" {
		return nil, errorsx.WithStack(oauth2.ErrInvalidDPoPProof.WithHint("The DPoP proof is missing the required 'jti' claim."))
	}

	if parsed.Method, _ = claims[consts.ClaimHTTPMethod].(string); parsed.Method == "" {
		return nil, errorsx.WithStack(oauth2.ErrInvalidDPoPProof.WithHint("The DPoP proof is missing the required 'htm' claim."))
	}

	if parsed.URL, _ = claims[consts.ClaimHTTPURI].(string); parsed.URL == "" {
		return nil, errorsx.WithStack(oauth2.ErrInvalidDPoPProof.WithHint("The DPoP proof is missing the required 'htu' claim."))
	}

	iat, ok := toFloat(claims[consts.ClaimIssuedAt])
	if !ok {
		return nil, errorsx.WithStack(oauth2.ErrInvalidDPoPProof.WithHint("The DPoP proof is missing or has an invalid 'iat' claim."))
	}

	parsed.IssuedAt = time.Unix(int64(iat), 0).UTC()
	parsed.Nonce, _ = claims[consts.ClaimNonce].(string)
	parsed.AccessTokenHash, _ = claims[consts.ClaimDPoPAccessTokenHash].(string)

	if parsed.Thumbprint, err = jwt.ThumbprintJWK(jwk); err != nil {
		return nil, errorsx.WithStack(oauth2.ErrInvalidDPoPProof.WithHint("The DPoP proof key thumbprint could not be computed.").WithWrap(err))
	}

	return parsed, nil
}

func toFloat(v any) (f float64, ok bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case json.Number:
		n, err := t.Float64()
		return n, err == nil
	default:
		return 0, false
	}
}
