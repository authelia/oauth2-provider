// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ory/x/errorsx"

	"github.com/authelia/goauth2"
	"github.com/authelia/goauth2/token/hmac"
)

type HMACSHAStrategy struct {
	Enigma *hmac.HMACStrategy
	Config interface {
		goauth2.AccessTokenLifespanProvider
		goauth2.RefreshTokenLifespanProvider
		goauth2.AuthorizeCodeLifespanProvider
	}
	prefix *string
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
	if h.prefix == nil {
		prefix := "ory_%s_"
		h.prefix = &prefix
	} else if len(*h.prefix) == 0 {
		return ""
	}

	return fmt.Sprintf(*h.prefix, part)
}

func (h *HMACSHAStrategy) trimPrefix(token, part string) string {
	return strings.TrimPrefix(token, h.getPrefix(part))
}

func (h *HMACSHAStrategy) setPrefix(token, part string) string {
	return h.getPrefix(part) + token
}

func (h *HMACSHAStrategy) GenerateAccessToken(ctx context.Context, _ goauth2.Requester) (token string, signature string, err error) {
	token, sig, err := h.Enigma.Generate(ctx)
	if err != nil {
		return "", "", err
	}

	return h.setPrefix(token, "at"), sig, nil
}

func (h *HMACSHAStrategy) ValidateAccessToken(ctx context.Context, r goauth2.Requester, token string) (err error) {
	var exp = r.GetSession().GetExpiresAt(goauth2.AccessToken)
	if exp.IsZero() && r.GetRequestedAt().Add(h.Config.GetAccessTokenLifespan(ctx)).Before(time.Now().UTC()) {
		return errorsx.WithStack(goauth2.ErrTokenExpired.WithHintf("Access token expired at '%s'.", r.GetRequestedAt().Add(h.Config.GetAccessTokenLifespan(ctx))))
	}

	if !exp.IsZero() && exp.Before(time.Now().UTC()) {
		return errorsx.WithStack(goauth2.ErrTokenExpired.WithHintf("Access token expired at '%s'.", exp))
	}

	return h.Enigma.Validate(ctx, h.trimPrefix(token, "at"))
}

func (h *HMACSHAStrategy) GenerateRefreshToken(ctx context.Context, _ goauth2.Requester) (token string, signature string, err error) {
	token, sig, err := h.Enigma.Generate(ctx)
	if err != nil {
		return "", "", err
	}

	return h.setPrefix(token, "rt"), sig, nil
}

func (h *HMACSHAStrategy) ValidateRefreshToken(ctx context.Context, r goauth2.Requester, token string) (err error) {
	var exp = r.GetSession().GetExpiresAt(goauth2.RefreshToken)
	if exp.IsZero() {
		// Unlimited lifetime
		return h.Enigma.Validate(ctx, h.trimPrefix(token, "rt"))
	}

	if !exp.IsZero() && exp.Before(time.Now().UTC()) {
		return errorsx.WithStack(goauth2.ErrTokenExpired.WithHintf("Refresh token expired at '%s'.", exp))
	}

	return h.Enigma.Validate(ctx, h.trimPrefix(token, "rt"))
}

func (h *HMACSHAStrategy) GenerateAuthorizeCode(ctx context.Context, _ goauth2.Requester) (token string, signature string, err error) {
	token, sig, err := h.Enigma.Generate(ctx)
	if err != nil {
		return "", "", err
	}

	return h.setPrefix(token, "ac"), sig, nil
}

func (h *HMACSHAStrategy) ValidateAuthorizeCode(ctx context.Context, r goauth2.Requester, token string) (err error) {
	var exp = r.GetSession().GetExpiresAt(goauth2.AuthorizeCode)
	if exp.IsZero() && r.GetRequestedAt().Add(h.Config.GetAuthorizeCodeLifespan(ctx)).Before(time.Now().UTC()) {
		return errorsx.WithStack(goauth2.ErrTokenExpired.WithHintf("Authorize code expired at '%s'.", r.GetRequestedAt().Add(h.Config.GetAuthorizeCodeLifespan(ctx))))
	}

	if !exp.IsZero() && exp.Before(time.Now().UTC()) {
		return errorsx.WithStack(goauth2.ErrTokenExpired.WithHintf("Authorize code expired at '%s'.", exp))
	}

	return h.Enigma.Validate(ctx, h.trimPrefix(token, "ac"))
}
