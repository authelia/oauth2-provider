// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc9449

import (
	"crypto/rsa"
	"encoding/json"
	"time"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jose"
	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

// JTIMaxLength is the longest accepted 'jti' claim. RFC 9449 Section 11.1 recommends rejecting proofs carrying an
// unnecessarily large 'jti' (or storing only a hash of it) so that a client cannot exhaust the memory of the replay
// store, which retains every accepted value for the proof's 'iat' acceptance window. Section 4.2 only asks for at
// least 96 bits of pseudorandom data or a version 4 UUID, both of which are far shorter than this bound.
const JTIMaxLength = 255

// NonceMaxLength is the longest accepted 'nonce' claim, bounded for the same reason as JTIMaxLength: a DPoPReplayStorage
// that keys on the nonce retains it alongside the 'jti' for the proof's 'iat' acceptance window, so an unbounded value
// would let a client exhaust its memory. The bound cannot reject a legitimate value, as a nonce is minted by the server
// (DefaultStrategy.NewDPoPNonce issues 43 characters) and one that was not is rejected by the nonce check regardless.
const NonceMaxLength = 255

// RSAMinimumKeySize is the smallest accepted modulus for an RSA DPoP proof key. RFC 7518 Sections 3.3 and 3.5 require
// a key of at least 2048 bits for the RS* and PS* algorithms, and nothing in the JOSE layer enforces it: a signature
// from a weak key verifies perfectly well, so without this check a token could be bound to a key that offers no real
// proof of possession. The client chooses this key freely, so the check costs a conforming client nothing.
const RSAMinimumKeySize = 2048

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

	// Checked before the signature is verified, as there is no reason to do the work for a key that will be rejected.
	if err = validateProofKeyStrength(jwk); err != nil {
		return nil, err
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

	if len(parsed.ID) > JTIMaxLength {
		return nil, errorsx.WithStack(oauth2.ErrInvalidDPoPProof.WithHintf("The DPoP proof 'jti' claim must not be longer than %d characters.", JTIMaxLength))
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

	if parsed.Nonce, _ = claims[consts.ClaimNonce].(string); len(parsed.Nonce) > NonceMaxLength {
		return nil, errorsx.WithStack(oauth2.ErrInvalidDPoPProof.WithHintf("The DPoP proof 'nonce' claim must not be longer than %d characters.", NonceMaxLength))
	}

	parsed.AccessTokenHash, _ = claims[consts.ClaimDPoPAccessTokenHash].(string)

	if parsed.Thumbprint, err = jwt.ThumbprintJWK(jwk); err != nil {
		return nil, errorsx.WithStack(oauth2.ErrInvalidDPoPProof.WithHint("The DPoP proof key thumbprint could not be computed.").WithWrap(err))
	}

	return parsed, nil
}

// validateProofKeyStrength rejects a proof key too weak for the proof-of-possession binding to be meaningful.
//
// Only RSA needs checking. The elliptic curve and Ed25519 key types the JOSE layer will accept as a public key all
// carry a fixed, adequate strength: go-jose parses an 'EC' JWK only for P-256, P-384 and P-521, and its ECDSA verifier
// derives the expected signature size from the algorithm rather than the key, so a curve weaker than the declared
// algorithm cannot be smuggled in.
func validateProofKeyStrength(jwk *jose.JSONWebKey) (err error) {
	if key, ok := jwk.Key.(*rsa.PublicKey); ok {
		if bits := key.N.BitLen(); bits < RSAMinimumKeySize {
			return errorsx.WithStack(oauth2.ErrInvalidDPoPProof.WithHintf("The DPoP proof 'jwk' header contains a %d bit RSA key but keys of at least %d bits are required.", bits, RSAMinimumKeySize))
		}
	}

	return nil
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
