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

	"github.com/pkg/errors"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/reflection"
	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

type IDTokenHandleHelper struct {
	IDTokenStrategy OpenIDConnectTokenStrategy
}

// IDTokenSigningAlgValuesSupported returns the JWS algorithms the ID Token strategy can sign with, or nil when the
// strategy does not report them.
//
// See: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
func (i *IDTokenHandleHelper) IDTokenSigningAlgValuesSupported(ctx context.Context) (algs []string) {
	if i == nil || i.IDTokenStrategy == nil {
		return nil
	}

	if s, ok := i.IDTokenStrategy.(interface {
		SigningAlgValues(ctx context.Context) (algs []string)
	}); ok {
		return s.SigningAlgValues(ctx)
	}

	return nil
}

// GetAccessTokenHash returns the 'at_hash' claim value for the access token in the response. See ComputeHash.
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

// IssueImplicitIDToken generates an ID Token for the request and adds it to the authorize response as the 'id_token'
// parameter.
func (i *IDTokenHandleHelper) IssueImplicitIDToken(ctx context.Context, lifespan time.Duration, request oauth2.Requester, response oauth2.AuthorizeResponder) (err error) {
	var token string

	if token, err = i.generateIDToken(ctx, lifespan, request); err != nil {
		return err
	}

	response.AddParameter(consts.AccessResponseIDToken, token)

	return nil
}

// IssueExplicitIDToken generates an ID Token for the request and adds it to the token response as the 'id_token' value.
func (i *IDTokenHandleHelper) IssueExplicitIDToken(ctx context.Context, lifespan time.Duration, request oauth2.Requester, response oauth2.AccessResponder) (err error) {
	var token string

	if token, err = i.generateIDToken(ctx, lifespan, request); err != nil {
		return err
	}

	response.SetExtra(consts.AccessResponseIDToken, token)

	return nil
}

// ComputeHash computes the 'at_hash', 'c_hash', or 's_hash' value for token. The hash algorithm is resolved from the
// client's registered 'id_token_signed_response_alg', as the session's ID Token headers never carry 'alg'.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken
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
func hashFor(alg string) (h hash.Hash) {
	switch jose.SignatureAlgorithm(alg) {
	case jose.RS256, jose.PS256, jose.ES256, jose.HS256:
		return sha256.New()
	case jose.RS384, jose.PS384, jose.ES384, jose.HS384:
		return sha512.New384()
	case jose.RS512, jose.PS512, jose.ES512, jose.HS512:
		return sha512.New()
	case jose.EdDSA, jose.Ed25519:
		// RFC8037 Section 3.1 defines EdDSA for JOSE in terms of Ed25519, which uses SHA-512 internally.
		return sha512.New()
	default:
		// SHA-256 is the fallback as it pairs with RS256, the 'id_token_signed_response_alg' default. An error cannot
		// be reported here as GetAccessTokenHash panics on one.
		return sha256.New()
	}
}

// requestedMaxAge returns the 'max_age' authorization request parameter and whether it was present. A 'max_age' of 0
// is distinct from an absent one as it is equivalent to 'prompt=login', and an empty or repeated parameter is rejected
// rather than read as absent.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
// See: https://datatracker.ietf.org/doc/html/rfc6749#section-3.1
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

// The authorization server makes a reasonable effort at detecting and preventing the use of a constant OpenID Connect
// nonce.
//
// See: https://www.rfc-editor.org/rfc/rfc9700#section-2.1.1
func getIDTokenExpiresAt(session any, lifespan time.Duration) (expiresAt time.Time) {
	if lifespan == 0 {
		lifespan = defaultExpiryTime
	}

	expiresAt = time.Now().UTC().Add(lifespan)

	if s, ok := session.(Session); ok {
		if claims := s.IDTokenClaims(); claims != nil && claims.ExpirationTime != nil && claims.ExpirationTime.After(expiresAt) {
			expiresAt = claims.ExpirationTime.UTC()
		}
	}

	return expiresAt
}

func setIDTokenExpiresAt(session any, expiresAt time.Time) {
	s, ok := session.(Session)
	if !ok {
		return
	}

	if claims := s.IDTokenClaims(); claims != nil && (claims.ExpirationTime == nil || claims.ExpirationTime.IsZero()) {
		claims.ExpirationTime = jwt.NewNumericDate(expiresAt)
	}
}

func setNonceUsed(ctx context.Context, storage OpenIDConnectRequestStorage, request oauth2.Requester, expiresAt time.Time) (err error) {
	nonce := request.GetRequestForm().Get(consts.FormParameterNonce)

	if len(nonce) == 0 {
		return nil
	}

	if reflection.IsNil(storage) {
		return errorsx.WithStack(oauth2.ErrMisconfiguration.WithDebug("The OpenID Connect request storage is not configured, so the nonce cannot be recorded."))
	}

	client := request.GetClient()

	if err = storage.SetOpenIDConnectNonceUsed(ctx, client.GetID(), nonce, expiresAt); err != nil {
		if errors.Is(err, oauth2.ErrOpenIDConnectNonceReused) {
			return errorsx.WithStack(oauth2.ErrInvalidRequest.
				WithHint("The 'nonce' was already used by this client, a new nonce must be generated for every authentication request.").
				WithDebugf("The client with id '%s' used a 'nonce' value which it used in an earlier authentication request.", client.GetID()))
		}

		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugf("Error occurred attempting to record the nonce: %s.", err.Error()))
	}

	return nil
}

func getSessionExpiresAt(request oauth2.Requester, key oauth2.TokenType, fallback time.Duration) (expiresAt time.Time) {
	if session := request.GetSession(); !reflection.IsNil(session) {
		if expiresAt = session.GetExpiresAt(key); !expiresAt.IsZero() {
			return expiresAt
		}
	}

	return time.Now().UTC().Add(fallback)
}
