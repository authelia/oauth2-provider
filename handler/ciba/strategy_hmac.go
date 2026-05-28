// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package ciba

import (
	"context"
	"fmt"
	"strings"
	"time"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/token/hmac"
	"authelia.com/provider/oauth2/x/errorsx"
)

// HMACAuthRequestIDStrategy is the default production AuthRequestIDStrategy implementation. The auth_req_id is an
// opaque value derived from a cryptographically random source via the embedded *hmac.HMACStrategy and is signed for
// storage so the persisted reference can never be reconstructed from the storage key alone.
//
// The optional prefix follows the same convention as the rest of the codebase (e.g. "authelia_%s_") and produces ids
// of the form "<expanded-prefix><opaque>". When the prefix is non-empty the strategy validates that supplied auth_req_id
// values begin with it; this protects the token endpoint from accidentally treating a token of another kind as an
// auth_req_id when the application multiplexes credentials.
type HMACAuthRequestIDStrategy struct {
	Enigma *hmac.HMACStrategy
	Config interface {
		oauth2.OpenIDCIBAConfigProvider
	}

	usePrefix bool
	prefix    string
}

// NewHMACAuthRequestIDStrategy builds an HMAC-backed AuthRequestIDStrategy. The prefix argument follows the
// "authelia_%s_" convention; pass an empty string (or any string missing exactly one '%s') to disable prefixing.
func NewHMACAuthRequestIDStrategy(config HMACAuthRequestIDStrategyConfigurator, prefix string) *HMACAuthRequestIDStrategy {
	enigma := &hmac.HMACStrategy{Config: config}

	if len(prefix) == 0 || strings.Count(prefix, "%s") != 1 {
		return &HMACAuthRequestIDStrategy{
			Enigma: enigma,
			Config: config,
		}
	}

	return &HMACAuthRequestIDStrategy{
		Enigma:    enigma,
		Config:    config,
		prefix:    prefix,
		usePrefix: true,
	}
}

// IsOpaqueAuthRequestID reports whether the supplied auth_req_id has the configured prefix. Always returns true when
// the strategy has no prefix configured.
func (s *HMACAuthRequestIDStrategy) IsOpaqueAuthRequestID(_ context.Context, id string) bool {
	if !s.usePrefix {
		return true
	}

	return strings.HasPrefix(id, s.expandPrefix())
}

// GenerateAuthRequestID returns a freshly generated opaque auth_req_id alongside its storage signature.
func (s *HMACAuthRequestIDStrategy) GenerateAuthRequestID(ctx context.Context) (id, signature string, err error) {
	if id, signature, err = s.Enigma.Generate(ctx); err != nil {
		return "", "", err
	}

	return s.prepend(id), signature, nil
}

// AuthRequestIDSignature returns the storage signature for the supplied auth_req_id. When prefixing is enabled the
// prefix must be present, otherwise ErrInvalidTokenFormat is returned so callers cannot use this strategy to compute a
// signature for an unrelated token kind.
func (s *HMACAuthRequestIDStrategy) AuthRequestIDSignature(ctx context.Context, id string) (signature string, err error) {
	if s.usePrefix && !s.IsOpaqueAuthRequestID(ctx, id) {
		return "", errorsx.WithStack(oauth2.ErrInvalidTokenFormat.WithHint("Provided token does not appear to be an auth_req_id."))
	}

	return s.Enigma.Signature(s.trim(id)), nil
}

// ValidateAuthRequestID verifies that the supplied auth_req_id is well-formed, has not expired, and matches the HMAC
// signature recorded for the request. The expiry is taken from the CIBAAuthRequestID token type on the request's
// session and falls back to the configured CIBA lifespan applied to the request's RequestedAt timestamp.
func (s *HMACAuthRequestIDStrategy) ValidateAuthRequestID(ctx context.Context, r oauth2.Requester, id string) (err error) {
	if s.usePrefix && !s.IsOpaqueAuthRequestID(ctx, id) {
		return errorsx.WithStack(oauth2.ErrInvalidTokenFormat.WithHint("Provided token does not appear to be an auth_req_id."))
	}

	if session := r.GetSession(); session != nil {
		exp := session.GetExpiresAt(oauth2.CIBAAuthRequestID)

		switch {
		case exp.IsZero() && r.GetRequestedAt().Add(s.Config.GetOpenIDCIBALifespan(ctx)).Before(time.Now().UTC()):
			return errorsx.WithStack(oauth2.ErrDeviceExpiredToken.WithHintf("The auth_req_id expired at '%s'.", r.GetRequestedAt().Add(s.Config.GetOpenIDCIBALifespan(ctx))))
		case !exp.IsZero() && exp.Before(time.Now().UTC()):
			return errorsx.WithStack(oauth2.ErrDeviceExpiredToken.WithHintf("The auth_req_id expired at '%s'.", exp))
		}
	}

	return s.Enigma.Validate(ctx, s.trim(id))
}

func (s *HMACAuthRequestIDStrategy) prepend(id string) string {
	if !s.usePrefix {
		return id
	}

	return s.expandPrefix() + id
}

func (s *HMACAuthRequestIDStrategy) trim(id string) string {
	if !s.usePrefix {
		return id
	}

	return strings.TrimPrefix(id, s.expandPrefix())
}

func (s *HMACAuthRequestIDStrategy) expandPrefix() string {
	return fmt.Sprintf(s.prefix, authRequestIDPrefixPart)
}

// authRequestIDPrefixPart is the token-kind segment inserted into the configurable prefix template (e.g.
// "authelia_%s_" produces "authelia_arid_").
const authRequestIDPrefixPart = "bc"

// HMACAuthRequestIDStrategyConfigurator is the configuration surface required to construct an
// HMACAuthRequestIDStrategy.
type HMACAuthRequestIDStrategyConfigurator interface {
	oauth2.TokenEntropyProvider
	oauth2.GlobalSecretProvider
	oauth2.RotatedGlobalSecretsProvider
	oauth2.HMACHashingProvider
	oauth2.OpenIDCIBAConfigProvider
}

var (
	_ AuthRequestIDStrategy = (*HMACAuthRequestIDStrategy)(nil)
)
