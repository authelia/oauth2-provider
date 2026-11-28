// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc9449

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"time"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/x/errorsx"
)

// StrategyConfig is the configuration required by DefaultStrategy.
type StrategyConfig interface {
	// GetDPoPAllowedJWSAlgorithms returns the permitted asymmetric DPoP proof signing algorithms.
	GetDPoPAllowedJWSAlgorithms(ctx context.Context) (algs []string)
	// GetDPoPClockSkew returns the tolerance allowed when judging the 'iat' claim of a DPoP proof.
	GetDPoPClockSkew(ctx context.Context) (skew time.Duration)
	// GetDPoPProofLifespan returns how long a DPoP proof remains valid after its 'iat' claim.
	GetDPoPProofLifespan(ctx context.Context) (lifespan time.Duration)
	// GetDPoPNonceLifespan returns the lifespan of issued DPoP server nonces.
	GetDPoPNonceLifespan(ctx context.Context) (lifespan time.Duration)
	// GetDPoPNonceStateless returns true if DPoP server nonces are authenticated with a key derived from the global secret
	// rather than stored.
	GetDPoPNonceStateless(ctx context.Context) (stateless bool)
	// GetGlobalSecret returns the global secret.
	GetGlobalSecret(ctx context.Context) (secret []byte, err error)
	// GetRotatedGlobalSecrets returns the rotated global secrets.
	GetRotatedGlobalSecrets(ctx context.Context) (secrets [][]byte, err error)
}

// DefaultStrategy is the default oauth2.DPoPStrategy implementation.
type DefaultStrategy struct {
	Config StrategyConfig
	Store  Storage
}

// NewDefaultStrategy returns a DefaultStrategy using the given config and storage.
func NewDefaultStrategy(config StrategyConfig, store Storage) *DefaultStrategy {
	return &DefaultStrategy{Config: config, Store: store}
}

// ValidateDPoPProof parses the DPoP proof and validates it against the request method and URL. The 'htm' and normalized
// 'htu' claims must match the request, the 'iat' claim must be within the proof lifespan allowing for the clock skew,
// the 'nonce' claim must be valid when a nonce is required, and the proof must not have been used before. For a client
// held to the FAPI 2.0 Security Profile carried by oauth2.NewDPoPProofClientContext, only the algorithms the profile
// permits are accepted and the clock skew is held between 10 and 60 seconds.
//
// See: https://www.rfc-editor.org/rfc/rfc9449#section-4.3
// See: https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.4.1
func (s *DefaultStrategy) ValidateDPoPProof(ctx context.Context, method, requestURL, proof string, requireNonce bool, alternates ...string) (parsed *oauth2.DPoPProof, err error) {
	client := oauth2.DPoPProofClientFromContext(ctx)

	if parsed, err = ParseProof(proof, s.allowedAlgorithms(ctx, client)); err != nil {
		return nil, err
	}

	// RFC 9449 4.3 step 8: the 'htm' claim must match the request method. The comparison is exact because RFC 9110
	// Section 9.1 defines the method token as case-sensitive.
	if parsed.Method != method {
		return nil, errorsx.WithStack(oauth2.ErrInvalidDPoPProof.WithHintf("The DPoP proof 'htm' claim '%s' does not match the request method '%s'.", parsed.Method, method))
	}

	var expected, actual string

	if expected, err = normalizeHTU(parsed.URL); err != nil {
		return nil, errorsx.WithStack(oauth2.ErrInvalidDPoPProof.WithHint("The DPoP proof 'htu' claim is not a valid URI."))
	}

	if actual, err = normalizeHTU(requestURL); err != nil {
		return nil, errorsx.WithStack(oauth2.ErrInvalidDPoPProof.WithHint("The request URI could not be normalized.").WithWrap(err))
	}

	if expected != actual && !matchesAlternate(expected, alternates) {
		return nil, errorsx.WithStack(oauth2.ErrInvalidDPoPProof.WithHintf("The DPoP proof 'htu' claim '%s' does not match the request URI '%s'.", expected, actual))
	}

	// RFC 9449 4.3 step 7: the 'iat' claim must be within an acceptable timeframe. The proof is good from iat-skew
	// until iat+lifespan+skew: the lifespan is how long a proof is good for after it was minted, and the skew is how
	// far apart this server's clock and the client's are allowed to be.
	var (
		skew     = oauth2.GetDPoPClockSkew(ctx, s.Config, client)
		lifespan = s.Config.GetDPoPProofLifespan(ctx)
		now      = time.Now()
	)

	if parsed.IssuedAt.After(now.Add(skew)) {
		return nil, errorsx.WithStack(oauth2.ErrInvalidDPoPProof.
			WithHint("The DPoP proof 'iat' claim is outside of the acceptable time window.").
			WithDebugf("The proof was issued at '%s', which is further into the future than the permitted clock skew of %s allows.", parsed.IssuedAt.UTC().Format(time.RFC3339), skew))
	}

	// expires is the instant the proof stops being acceptable to this client. The replay marker is kept until the
	// latest instant the proof is acceptable to any client, as the replay check is not scoped to the client.
	var (
		expires = parsed.IssuedAt.Add(lifespan + skew)
		marked  = parsed.IssuedAt.Add(lifespan + max(s.Config.GetDPoPClockSkew(ctx), oauth2.FAPI2SecurityProfileMinimumClockSkew))
	)

	if now.After(expires) {
		return nil, errorsx.WithStack(oauth2.ErrInvalidDPoPProof.
			WithHint("The DPoP proof 'iat' claim is outside of the acceptable time window.").
			WithDebugf("The proof was issued at '%s' and expired at '%s', being its lifespan of %s plus the permitted clock skew of %s.", parsed.IssuedAt.UTC().Format(time.RFC3339), expires.UTC().Format(time.RFC3339), lifespan, skew))
	}

	if requireNonce {
		if parsed.Nonce == "" {
			return nil, errorsx.WithStack(oauth2.ErrUseDPoPNonce.WithHint("The DPoP proof is missing the required 'nonce' claim."))
		}

		if err = s.ValidateDPoPNonce(ctx, parsed.Nonce); err != nil {
			return nil, err
		}
	}

	// Check-and-mark the proof as used in a single atomic step so concurrent requests presenting the same proof cannot
	// both pass the replay check. The marker is kept until 'marked', the instant the longest acceptance window closes.
	// The normalized 'htu' is passed rather than the raw claim so two spellings of the same target URI share one
	// replay slot; see DPoPReplayStorage.
	var used bool

	if used, err = s.Store.CheckAndSetDPoPProofUsed(ctx, parsed.ID, parsed.Thumbprint, parsed.Nonce, parsed.Method, expected, marked); err != nil {
		return nil, errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	} else if used {
		return nil, errorsx.WithStack(oauth2.ErrInvalidDPoPProof.WithHint("The DPoP proof has already been used."))
	}

	return parsed, nil
}

func matchesAlternate(expected string, alternates []string) bool {
	for _, alternate := range alternates {
		if alternate == "" {
			continue
		}

		if normalized, err := normalizeHTU(alternate); err == nil && normalized == expected {
			return true
		}
	}

	return false
}

// NewDPoPNonce generates a DPoP nonce valid for the configured nonce lifespan. A stateless nonce carries the time at
// the server and is authenticated with a key derived from the global secret, otherwise a random nonce is stored.
//
// See: https://www.rfc-editor.org/rfc/rfc9449#section-8, https://www.rfc-editor.org/rfc/rfc9449#section-11.1
func (s *DefaultStrategy) NewDPoPNonce(ctx context.Context) (nonce string, err error) {
	if s.Config.GetDPoPNonceStateless(ctx) {
		return s.newStatelessNonce(ctx, time.Now())
	}

	b := make([]byte, 32)

	if _, err = rand.Read(b); err != nil {
		return "", errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	nonce = base64.RawURLEncoding.EncodeToString(b)

	if err = s.Store.CreateDPoPNonce(ctx, nonce, time.Now().Add(s.Config.GetDPoPNonceLifespan(ctx))); err != nil {
		return "", errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	return nonce, nil
}

// ValidateDPoPNonce returns oauth2.ErrUseDPoPNonce unless the nonce is valid. A stateless nonce must be authenticated
// by the global secret or a rotated global secret and be no older than the nonce lifespan, otherwise the storage must
// report the nonce as valid.
func (s *DefaultStrategy) ValidateDPoPNonce(ctx context.Context, nonce string) (err error) {
	if s.Config.GetDPoPNonceStateless(ctx) {
		return s.validateStatelessNonce(ctx, nonce, time.Now())
	}

	var valid bool

	if valid, err = s.Store.IsDPoPNonceValid(ctx, nonce); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	if !valid {
		return errorsx.WithStack(oauth2.ErrUseDPoPNonce.WithHint("The DPoP proof 'nonce' claim is invalid or expired."))
	}

	return nil
}

func (s *DefaultStrategy) allowedAlgorithms(ctx context.Context, client oauth2.Client) []jose.SignatureAlgorithm {
	raw := oauth2.FilterFAPI2SecurityProfileSigningAlgValues(ctx, s.Config, client, s.Config.GetDPoPAllowedJWSAlgorithms(ctx))
	algs := make([]jose.SignatureAlgorithm, 0, len(raw))

	for _, a := range raw {
		algs = append(algs, jose.SignatureAlgorithm(a))
	}

	return algs
}

var (
	_ oauth2.DPoPStrategy = (*DefaultStrategy)(nil)
)
