// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"fmt"
	"strings"
	"time"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/errorsx"
	"authelia.com/provider/oauth2/token/hmac"
)

// NewHMACSHAStrategy creates a new HMACSHAStrategy with the potential to include the prefix format. The prefix must
// include a single '%s' for the purpose of adding the token part (ac, at, and rt; for the Authorize Code, Access
// Token, and Refresh Token; respectively.
func NewHMACSHAStrategy(config HMACSHAStrategyConfigurator, prefix string) (strategy *HMACSHAStrategy, err error) {
	if len(prefix) == 0 {
		return &HMACSHAStrategy{
			Enigma: &hmac.HMACStrategy{Config: config},
			Config: config,
		}, nil
	}

	if n := strings.Count(prefix, "%s"); n != 1 {
		return nil, fmt.Errorf("the prefix must contain a single '%%s' but contains %d", n)
	}

	return &HMACSHAStrategy{
		Enigma: &hmac.HMACStrategy{Config: config},
		Config: config,
		prefix: prefix,
	}, nil
}

type HMACSHAStrategy struct {
	Enigma *hmac.HMACStrategy
	Config interface {
		oauth2.AccessTokenLifespanProvider
		oauth2.RefreshTokenLifespanProvider
		oauth2.AuthorizeCodeLifespanProvider
	}

	prefix string
}

func (h *HMACSHAStrategy) AccessTokenSignature(ctx context.Context, token string) string {
	return h.Enigma.Signature(token)
}

func (h *HMACSHAStrategy) RefreshTokenSignature(ctx context.Context, token string) string {
	return h.Enigma.Signature(token)
}

func (h *HMACSHAStrategy) AuthorizeCodeSignature(ctx context.Context, token string) string {
	return h.Enigma.Signature(token)
}

func (h *HMACSHAStrategy) getPrefix(part string) string {
	if len(h.prefix) == 0 {
		return ""
	}

	return fmt.Sprintf(h.prefix, part)
}

func (h *HMACSHAStrategy) trimPrefix(token, part string) string {
	return strings.TrimPrefix(token, h.getPrefix(part))
}

func (h *HMACSHAStrategy) setPrefix(token, part string) string {
	return h.getPrefix(part) + token
}

func (h *HMACSHAStrategy) GenerateAccessToken(ctx context.Context, _ oauth2.Requester) (token string, signature string, err error) {
	token, sig, err := h.Enigma.Generate(ctx)
	if err != nil {
		return "", "", err
	}

	return h.setPrefix(token, tokenPartAccessToken), sig, nil
}

func (h *HMACSHAStrategy) ValidateAccessToken(ctx context.Context, r oauth2.Requester, token string) (err error) {
	var exp = r.GetSession().GetExpiresAt(oauth2.AccessToken)
	if exp.IsZero() && r.GetRequestedAt().Add(h.Config.GetAccessTokenLifespan(ctx)).Before(time.Now().UTC()) {
		return errorsx.WithStack(oauth2.ErrTokenExpired.WithHintf("Access token expired at '%s'.", r.GetRequestedAt().Add(h.Config.GetAccessTokenLifespan(ctx))))
	}

	if !exp.IsZero() && exp.Before(time.Now().UTC()) {
		return errorsx.WithStack(oauth2.ErrTokenExpired.WithHintf("Access token expired at '%s'.", exp))
	}

	return h.Enigma.Validate(ctx, h.trimPrefix(token, tokenPartAccessToken))
}

func (h *HMACSHAStrategy) GenerateRefreshToken(ctx context.Context, _ oauth2.Requester) (token string, signature string, err error) {
	token, sig, err := h.Enigma.Generate(ctx)
	if err != nil {
		return "", "", err
	}

	return h.setPrefix(token, tokenPartRefreshToken), sig, nil
}

func (h *HMACSHAStrategy) ValidateRefreshToken(ctx context.Context, r oauth2.Requester, token string) (err error) {
	var exp = r.GetSession().GetExpiresAt(oauth2.RefreshToken)
	if exp.IsZero() {
		// Unlimited lifetime
		return h.Enigma.Validate(ctx, h.trimPrefix(token, tokenPartRefreshToken))
	}

	if !exp.IsZero() && exp.Before(time.Now().UTC()) {
		return errorsx.WithStack(oauth2.ErrTokenExpired.WithHintf("Refresh token expired at '%s'.", exp))
	}

	return h.Enigma.Validate(ctx, h.trimPrefix(token, tokenPartRefreshToken))
}

func (h *HMACSHAStrategy) GenerateAuthorizeCode(ctx context.Context, _ oauth2.Requester) (token string, signature string, err error) {
	token, sig, err := h.Enigma.Generate(ctx)
	if err != nil {
		return "", "", err
	}

	return h.setPrefix(token, tokenPartAuthorizeCode), sig, nil
}

func (h *HMACSHAStrategy) ValidateAuthorizeCode(ctx context.Context, r oauth2.Requester, token string) (err error) {
	var exp = r.GetSession().GetExpiresAt(oauth2.AuthorizeCode)
	if exp.IsZero() && r.GetRequestedAt().Add(h.Config.GetAuthorizeCodeLifespan(ctx)).Before(time.Now().UTC()) {
		return errorsx.WithStack(oauth2.ErrTokenExpired.WithHintf("Authorize code expired at '%s'.", r.GetRequestedAt().Add(h.Config.GetAuthorizeCodeLifespan(ctx))))
	}

	if !exp.IsZero() && exp.Before(time.Now().UTC()) {
		return errorsx.WithStack(oauth2.ErrTokenExpired.WithHintf("Authorize code expired at '%s'.", exp))
	}

	return h.Enigma.Validate(ctx, h.trimPrefix(token, tokenPartAuthorizeCode))
}

const (
	tokenPartAuthorizeCode = "ac"
	tokenPartAccessToken   = "at"
	tokenPartRefreshToken  = "rt"
)

type HMACSHAStrategyConfigurator interface {
	oauth2.AccessTokenLifespanProvider
	oauth2.RefreshTokenLifespanProvider
	oauth2.AuthorizeCodeLifespanProvider
	oauth2.TokenEntropyProvider
	oauth2.GlobalSecretProvider
	oauth2.RotatedGlobalSecretsProvider
	oauth2.HMACHashingProvider
}
