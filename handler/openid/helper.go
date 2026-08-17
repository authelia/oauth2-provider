// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"
	"net/url"
	"strconv"
	"time"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jose"
	"authelia.com/provider/oauth2/token/jwt"
)

type IDTokenHandleHelper struct {
	IDTokenStrategy OpenIDConnectTokenStrategy
}

func (i *IDTokenHandleHelper) GetAccessTokenHash(ctx context.Context, request oauth2.AccessRequester, response oauth2.AccessResponder) (sum string) {
	var err error

	if sum, err = i.ComputeHash(ctx, request.GetClient(), response.GetAccessToken()); err != nil {
		// The only error ComputeHash returns comes from hash.Hash.Write, which is documented never to return one.
		panic(err)
	}

	return sum
}

func (i *IDTokenHandleHelper) generateIDToken(ctx context.Context, lifespan time.Duration, request oauth2.Requester) (token string, err error) {
	if token, err = i.IDTokenStrategy.GenerateIDToken(ctx, lifespan, request); err != nil {
		return "", err
	}

	return token, nil
}

func (i *IDTokenHandleHelper) IssueImplicitIDToken(ctx context.Context, lifespan time.Duration, request oauth2.Requester, response oauth2.AuthorizeResponder) (err error) {
	var token string

	if token, err = i.generateIDToken(ctx, lifespan, request); err != nil {
		return err
	}

	response.AddParameter(consts.AccessResponseIDToken, token)

	return nil
}

func (i *IDTokenHandleHelper) IssueExplicitIDToken(ctx context.Context, lifespan time.Duration, request oauth2.Requester, response oauth2.AccessResponder) (err error) {
	var token string

	if token, err = i.generateIDToken(ctx, lifespan, request); err != nil {
		return err
	}

	response.SetExtra(consts.AccessResponseIDToken, token)

	return nil
}

// ComputeHash computes the 'at_hash', 'c_hash', or 's_hash' value for token.
//
// OpenID Connect Core 1.0 Section 3.3.2.11 defines the value as "the base64url encoding of the left-most half of the
// hash of the octets of the ASCII representation" of the token, "where the hash algorithm used is the hash algorithm
// used in the 'alg' Header Parameter of the ID Token's JOSE Header. For instance, if the alg is HS512, hash the code
// value with SHA-512".
//
// The algorithm is resolved from the client's registered 'id_token_signed_response_alg', which is what the encoder
// actually signs the ID Token with, rather than from the session's ID Token headers. The session cannot carry it:
// jwt.Headers.ToMap deliberately filters 'alg' out, so reading it there always missed and every hash was computed
// with SHA-256 no matter which algorithm the ID Token declared, which a conforming Relying Party must reject.
func (i *IDTokenHandleHelper) ComputeHash(_ context.Context, client oauth2.Client, token string) (sum string, err error) {
	h := hashFor(idTokenSigningAlg(client))

	if _, err = h.Write([]byte(token)); err != nil {
		return "", err
	}

	// The left-most half of the hash octets, not of their encoded representation.
	digest := h.Sum(nil)

	return base64.RawURLEncoding.EncodeToString(digest[:len(digest)/2]), nil
}

// idTokenSigningAlg returns the JWS algorithm the ID Token issued to this client is signed with, defaulting to RS256
// which OpenID Connect Dynamic Client Registration 1.0 Section 2 makes the default for 'id_token_signed_response_alg'
// and OpenID Connect Core 1.0 Section 15.1 requires an OpenID Provider support.
func idTokenSigningAlg(client oauth2.Client) (alg string) {
	if c := jwt.NewIDTokenClient(client); c != nil {
		if alg = c.GetSigningAlg(); len(alg) != 0 {
			return alg
		}
	}

	return string(jose.RS256)
}

// hashFor returns the hash paired with a JWS signing algorithm by OpenID Connect Core 1.0 Section 3.3.2.11.
//
// The pairing is expressed as an explicit table rather than derived from the digits in the algorithm name: that
// derivation silently mis-handles every algorithm not ending in its digest size, of which EdDSA is one.
func hashFor(alg string) (h hash.Hash) {
	switch jose.SignatureAlgorithm(alg) {
	case jose.RS256, jose.PS256, jose.ES256, jose.HS256:
		return sha256.New()
	case jose.RS384, jose.PS384, jose.ES384, jose.HS384:
		return sha512.New384()
	case jose.RS512, jose.PS512, jose.ES512, jose.HS512:
		return sha512.New()
	case jose.EdDSA:
		// RFC8037 Section 3.1 defines EdDSA for JOSE in terms of Ed25519, which uses SHA-512 internally.
		return sha512.New()
	default:
		// SHA-256 is the correct fallback for an unrecognised algorithm: RS256 is both the
		// 'id_token_signed_response_alg' default and the algorithm Section 15.1 requires be supported, and
		// ES256K pairs with SHA-256 as well. Reporting an error here is not an option, because GetAccessTokenHash
		// panics on one and cannot return it without a breaking signature change.
		return sha256.New()
	}
}

// requestedMaxAge returns the 'max_age' authorization request parameter and whether it was present.
//
// A 'max_age' of 0 is not the same as an absent 'max_age': OpenID Connect Core 1.0 Section 3.1.2.1 states that
// "max_age=0 is equivalent to prompt=login", so it demands re-authentication rather than imposing no constraint at
// all. Parsing it with the error discarded and then gating enforcement on 'max_age > 0' collapsed the two, so the
// client that asked most explicitly for a fresh authentication silently received the existing session.
//
// Presence is decided by the key itself rather than by url.Values.Get, which returns an empty string for an absent
// key, for an explicitly empty 'max_age=', and for a repeated parameter alike. The latter two are malformed rather
// than absent: RFC6749 Section 3.1 requires that request parameters are not included more than once, and an empty
// value is not a non-negative integer, so both are rejected instead of being silently read as no constraint.
func requestedMaxAge(form url.Values) (maxAge int64, ok bool, err error) {
	values, present := form[consts.FormParameterMaximumAge]

	switch {
	case !present, len(values) == 0:
		return 0, false, nil
	case len(values) != 1:
		return 0, false, fmt.Errorf("the parameter was provided %d times but must be provided exactly once", len(values))
	}

	raw := values[0]

	if maxAge, err = strconv.ParseInt(raw, 10, 64); err != nil || maxAge < 0 {
		return 0, false, fmt.Errorf("the value '%s' could not be parsed as a non-negative integer", raw)
	}

	return maxAge, true, nil
}
