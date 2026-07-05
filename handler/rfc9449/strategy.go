// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc9449

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/x/errorsx"
)

// StrategyConfig is the configuration required by DefaultStrategy.
type StrategyConfig interface {
	GetDPoPAllowedJWSAlgorithms(ctx context.Context) (algs []string)
	GetDPoPClockSkew(ctx context.Context) (skew time.Duration)
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

	if !strings.EqualFold(parsed.Method, method) {
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

	skew := s.Config.GetDPoPClockSkew(ctx)
	now := time.Now()

	if parsed.IssuedAt.After(now.Add(skew)) || parsed.IssuedAt.Before(now.Add(-skew)) {
		return nil, errorsx.WithStack(oauth2.ErrInvalidDPoPProof.WithHint("The DPoP proof 'iat' claim is outside of the acceptable time window."))
	}

	if requireNonce {
		if parsed.Nonce == "" {
			return nil, errorsx.WithStack(oauth2.ErrUseDPoPNonce.WithHint("The DPoP proof is missing the required 'nonce' claim."))
		}

		if err = s.ValidateDPoPNonce(ctx, parsed.Nonce); err != nil {
			return nil, err
		}
	}

	// Check-and-mark the proof 'jti' as used in a single atomic step so concurrent requests presenting the same proof
	// cannot both pass the replay check. The marker is kept until the end of the proof's own 'iat' acceptance window
	// (iat+skew), not now+skew: a proof presented before its iat (client clock ahead, within skew) stays iat-acceptable
	// until iat+skew, so expiring the marker at now+skew < iat+skew would reopen a replay window for the remainder.
	var used bool

	if used, err = s.Store.CheckAndSetDPoPProofUsed(ctx, parsed.ID, parsed.IssuedAt.Add(skew)); err != nil {
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

var _ oauth2.DPoPStrategy = (*DefaultStrategy)(nil)
