// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc9449

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"time"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/token/jose"
	"authelia.com/provider/oauth2/x/errorsx"
)

// StrategyConfig is the configuration required by DefaultStrategy.
type StrategyConfig interface {
	GetDPoPAllowedJWSAlgorithms(ctx context.Context) (algs []string)
	GetDPoPClockSkew(ctx context.Context) (skew time.Duration)
	GetDPoPProofLifespan(ctx context.Context) (lifespan time.Duration)
	GetDPoPNonceLifespan(ctx context.Context) (lifespan time.Duration)
}

// DefaultStrategy is the default oauth2.DPoPStrategy implementation.
type DefaultStrategy struct {
	Config StrategyConfig
	Store  Storage
}

func NewDefaultStrategy(config StrategyConfig, store Storage) *DefaultStrategy {
	return &DefaultStrategy{Config: config, Store: store}
}

func (s *DefaultStrategy) ValidateDPoPProof(ctx context.Context, method, requestURL, proof string, requireNonce bool) (parsed *oauth2.DPoPProof, err error) {
	if parsed, err = ParseProof(proof, s.allowedAlgorithms(ctx)); err != nil {
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

	if expected != actual {
		return nil, errorsx.WithStack(oauth2.ErrInvalidDPoPProof.WithHintf("The DPoP proof 'htu' claim '%s' does not match the request URI '%s'.", expected, actual))
	}

	// RFC 9449 4.3 step 7: the 'iat' claim must be within an acceptable timeframe. That timeframe is built from two
	// separate quantities, because they answer different questions and a deployment tunes them for different reasons:
	//
	//   - The lifespan is how long a proof is good for after it was minted. It is a policy about how stale a proof
	//     may be, and it is what bounds the interval in which a captured proof could be replayed were the replay
	//     record below lost.
	//   - The skew is how far apart this server's clock and the client's are allowed to be. It is not a policy about
	//     proofs at all, and it applies at both ends: a client running fast mints a proof whose 'iat' is ahead of
	//     this server's clock, and one running slow mints one that already looks old.
	//
	// So the proof is good from iat-skew until iat+lifespan+skew. Collapsing the two into a single symmetric leeway -
	// which this previously did - forces a deployment to buy tolerance for a badly synchronised clock by leaving
	// every proof valid for that same span, and the two have no reason to be equal.
	var (
		skew     = s.Config.GetDPoPClockSkew(ctx)
		lifespan = s.Config.GetDPoPProofLifespan(ctx)
		now      = time.Now()
	)

	if parsed.IssuedAt.After(now.Add(skew)) {
		return nil, errorsx.WithStack(oauth2.ErrInvalidDPoPProof.
			WithHint("The DPoP proof 'iat' claim is outside of the acceptable time window.").
			WithDebugf("The proof was issued at '%s', which is further into the future than the permitted clock skew of %s allows.", parsed.IssuedAt.UTC().Format(time.RFC3339), skew))
	}

	// expires is the instant the proof stops being acceptable, and is reused below as the replay marker's own
	// expiry so the two can never disagree.
	expires := parsed.IssuedAt.Add(lifespan + skew)

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
	// both pass the replay check. The marker is kept until 'expires' - the exact instant the acceptance window above
	// closes - rather than any interval measured from now: a proof presented early (client clock ahead, within skew)
	// stays acceptable until iat+lifespan+skew, so a marker expiring before that would reopen a replay window for the
	// remainder. Deriving both from the same value is what keeps them in step if either setting is retuned. It is
	// recorded against the proof key together with the method, normalized target URI and nonce the proof commits to
	// rather than the 'jti' alone, as that is the context a 'jti' is required to be unique in, see DPoPReplayStorage.
	// The normalized 'htu' is passed rather than the raw claim so two spellings of the same target URI cannot be made
	// to occupy separate replay slots.
	var used bool

	if used, err = s.Store.CheckAndSetDPoPProofUsed(ctx, parsed.ID, parsed.Thumbprint, parsed.Nonce, parsed.Method, expected, expires); err != nil {
		return nil, errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	} else if used {
		return nil, errorsx.WithStack(oauth2.ErrInvalidDPoPProof.WithHint("The DPoP proof has already been used."))
	}

	return parsed, nil
}

func (s *DefaultStrategy) NewDPoPNonce(ctx context.Context) (nonce string, err error) {
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

func (s *DefaultStrategy) ValidateDPoPNonce(ctx context.Context, nonce string) (err error) {
	var valid bool

	if valid, err = s.Store.IsDPoPNonceValid(ctx, nonce); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	if !valid {
		return errorsx.WithStack(oauth2.ErrUseDPoPNonce.WithHint("The DPoP proof 'nonce' claim is invalid or expired."))
	}

	return nil
}

func (s *DefaultStrategy) allowedAlgorithms(ctx context.Context) []jose.SignatureAlgorithm {
	raw := s.Config.GetDPoPAllowedJWSAlgorithms(ctx)
	algs := make([]jose.SignatureAlgorithm, 0, len(raw))

	for _, a := range raw {
		algs = append(algs, jose.SignatureAlgorithm(a))
	}

	return algs
}

var (
	_ oauth2.DPoPStrategy = (*DefaultStrategy)(nil)
)
