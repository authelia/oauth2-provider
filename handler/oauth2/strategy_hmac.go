package oauth2

import (
	"context"
	"fmt"
	"strings"
	"time"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/errorsx"
	"authelia.com/provider/oauth2/internal/randx"
	"authelia.com/provider/oauth2/token/hmac"
)

// NewHMACCoreStrategy creates a new HMACCoreStrategy with the potential to include the prefix format. The prefix must
// include a single '%s' for the purpose of adding the token part (ac, at, and rt; for the Authorize Code, Access
// Token, and Refresh Token; respectively.
func NewHMACCoreStrategy(config HMACCoreStrategyConfigurator, prefix string) (strategy *HMACCoreStrategy) {
	if len(prefix) == 0 || strings.Count(prefix, "%s") != 1 {
		return &HMACCoreStrategy{
			Enigma:    &hmac.HMACStrategy{Config: config},
			Config:    config,
			usePrefix: false,
		}
	}

	return &HMACCoreStrategy{
		Enigma:    &hmac.HMACStrategy{Config: config},
		Config:    config,
		prefix:    prefix,
		usePrefix: true,
	}
}

type HMACCoreStrategy struct {
	Enigma *hmac.HMACStrategy
	Config interface {
		oauth2.AccessTokenLifespanProvider
		oauth2.RefreshTokenLifespanProvider
		oauth2.AuthorizeCodeLifespanProvider
		oauth2.RFC9628DeviceAuthorizeConfigProvider
	}

	usePrefix bool
	prefix    string
}

// AccessTokenSignature implements oauth2.AccessTokenStrategy.
func (h *HMACCoreStrategy) AccessTokenSignature(ctx context.Context, tokenString string) (signature string) {
	return h.Enigma.Signature(tokenString)
}

// GenerateAccessToken implements oauth2.AccessTokenStrategy.
func (h *HMACCoreStrategy) GenerateAccessToken(ctx context.Context, _ oauth2.Requester) (tokenString string, signature string, err error) {
	if tokenString, signature, err = h.Enigma.Generate(ctx); err != nil {
		return "", "", err
	}

	return h.prependPrefix(tokenString, tokenPrefixPartAccessToken), signature, nil
}

// ValidateAccessToken implements oauth2.AccessTokenStrategy.
func (h *HMACCoreStrategy) ValidateAccessToken(ctx context.Context, r oauth2.Requester, tokenString string) (err error) {
	var exp = r.GetSession().GetExpiresAt(oauth2.AccessToken)
	if exp.IsZero() && r.GetRequestedAt().Add(h.Config.GetAccessTokenLifespan(ctx)).Before(time.Now().UTC()) {
		return errorsx.WithStack(oauth2.ErrTokenExpired.WithHintf("Access token expired at '%s'.", r.GetRequestedAt().Add(h.Config.GetAccessTokenLifespan(ctx))))
	}

	if !exp.IsZero() && exp.Before(time.Now().UTC()) {
		return errorsx.WithStack(oauth2.ErrTokenExpired.WithHintf("Access token expired at '%s'.", exp))
	}

	return h.Enigma.Validate(ctx, h.trimPrefix(tokenString, tokenPrefixPartAccessToken))
}

// RefreshTokenSignature implements oauth2.RefreshTokenStrategy.
func (h *HMACCoreStrategy) RefreshTokenSignature(ctx context.Context, tokenString string) string {
	return h.Enigma.Signature(tokenString)
}

// GenerateRefreshToken implements oauth2.RefreshTokenStrategy.
func (h *HMACCoreStrategy) GenerateRefreshToken(ctx context.Context, _ oauth2.Requester) (tokenString string, signature string, err error) {
	if tokenString, signature, err = h.Enigma.Generate(ctx); err != nil {
		return "", "", err
	}

	return h.prependPrefix(tokenString, tokenPrefixPartRefreshToken), signature, nil
}

// ValidateRefreshToken implements oauth2.RefreshTokenStrategy.
func (h *HMACCoreStrategy) ValidateRefreshToken(ctx context.Context, r oauth2.Requester, tokenString string) (err error) {
	var exp = r.GetSession().GetExpiresAt(oauth2.RefreshToken)

	if exp.IsZero() {
		return h.Enigma.Validate(ctx, h.trimPrefix(tokenString, tokenPrefixPartRefreshToken))
	}

	if exp.Before(time.Now().UTC()) {
		return errorsx.WithStack(oauth2.ErrTokenExpired.WithHintf("Refresh token expired at '%s'.", exp))
	}

	return h.Enigma.Validate(ctx, h.trimPrefix(tokenString, tokenPrefixPartRefreshToken))
}

// AuthorizeCodeSignature implements oauth2.AuthorizeCodeStrategy.
func (h *HMACCoreStrategy) AuthorizeCodeSignature(ctx context.Context, token string) string {
	return h.Enigma.Signature(token)
}

// GenerateAuthorizeCode implements oauth2.AuthorizeCodeStrategy.
func (h *HMACCoreStrategy) GenerateAuthorizeCode(ctx context.Context, _ oauth2.Requester) (tokenString string, signature string, err error) {
	if tokenString, signature, err = h.Enigma.Generate(ctx); err != nil {
		return "", "", err
	}

	return h.prependPrefix(tokenString, tokenPrefixPartAuthorizeCode), signature, nil
}

// ValidateAuthorizeCode implements oauth2.AuthorizeCodeStrategy.
func (h *HMACCoreStrategy) ValidateAuthorizeCode(ctx context.Context, r oauth2.Requester, tokenString string) (err error) {
	var exp = r.GetSession().GetExpiresAt(oauth2.AuthorizeCode)

	if exp.IsZero() && r.GetRequestedAt().Add(h.Config.GetAuthorizeCodeLifespan(ctx)).Before(time.Now().UTC()) {
		return errorsx.WithStack(oauth2.ErrTokenExpired.WithHintf("Authorize code expired at '%s'.", r.GetRequestedAt().Add(h.Config.GetAuthorizeCodeLifespan(ctx))))
	}

	if !exp.IsZero() && exp.Before(time.Now().UTC()) {
		return errorsx.WithStack(oauth2.ErrTokenExpired.WithHintf("Authorize code expired at '%s'.", exp))
	}

	return h.Enigma.Validate(ctx, h.trimPrefix(tokenString, tokenPrefixPartAuthorizeCode))
}

func (h *HMACCoreStrategy) RFC8628UserCodeSignature(ctx context.Context, tokenString string) (signature string, err error) {
	return h.Enigma.GenerateHMACForString(ctx, tokenString)
}

// GenerateRFC8628UserCode implements rfc8628.UserCodeStrategy.
func (h *HMACCoreStrategy) GenerateRFC8628UserCode(ctx context.Context) (tokenString string, signature string, err error) {
	seq, err := randx.RuneSequence(8, []rune("BCDFGHJKLMNPQRSTVWXZ"))
	if err != nil {
		return "", "", err
	}

	userCode := string(seq)

	signUserCode, err := h.RFC8628UserCodeSignature(ctx, userCode)
	if err != nil {
		return "", "", err
	}

	return userCode, signUserCode, nil
}

// ValidateRFC8628UserCode implements rfc8628.UserCodeStrategy.
func (h *HMACCoreStrategy) ValidateRFC8628UserCode(ctx context.Context, r oauth2.Requester, code string) (err error) {
	var exp = r.GetSession().GetExpiresAt(oauth2.UserCode)

	if exp.IsZero() && r.GetRequestedAt().Add(h.Config.GetRFC8628CodeLifespan(ctx)).Before(time.Now().UTC()) {
		return errorsx.WithStack(oauth2.ErrDeviceExpiredToken.WithHintf("User code expired at '%s'.", r.GetRequestedAt().Add(h.Config.GetRFC8628CodeLifespan(ctx))))
	}

	if !exp.IsZero() && exp.Before(time.Now().UTC()) {
		return errorsx.WithStack(oauth2.ErrDeviceExpiredToken.WithHintf("User code expired at '%s'.", exp))
	}

	return nil
}

// RFC8628DeviceCodeSignature implements rfc8628.DeviceCodeStrategy.
func (h *HMACCoreStrategy) RFC8628DeviceCodeSignature(ctx context.Context, tokenString string) (signature string, err error) {
	return h.Enigma.Signature(tokenString), nil
}

// GenerateRFC8628DeviceCode implements rfc8628.DeviceCodeStrategy.
func (h *HMACCoreStrategy) GenerateRFC8628DeviceCode(ctx context.Context) (tokenString string, signature string, err error) {
	tokenString, sig, err := h.Enigma.Generate(ctx)
	if err != nil {
		return "", "", err
	}

	return h.getPrefix(tokenPrefixPartDeviceCode) + tokenString, sig, nil
}

// ValidateRFC8628DeviceCode implements rfc8628.DeviceCodeStrategy.
func (h *HMACCoreStrategy) ValidateRFC8628DeviceCode(ctx context.Context, r oauth2.Requester, code string) (err error) {
	var exp = r.GetSession().GetExpiresAt(oauth2.DeviceCode)

	if exp.IsZero() && r.GetRequestedAt().Add(h.Config.GetRFC8628CodeLifespan(ctx)).Before(time.Now().UTC()) {
		return errorsx.WithStack(oauth2.ErrDeviceExpiredToken.WithHintf("Device code expired at '%s'.", r.GetRequestedAt().Add(h.Config.GetRFC8628CodeLifespan(ctx))))
	}

	if !exp.IsZero() && exp.Before(time.Now().UTC()) {
		return errorsx.WithStack(oauth2.ErrDeviceExpiredToken.WithHintf("Device code expired at '%s'.", exp))
	}

	return h.Enigma.Validate(ctx, h.trimPrefix(code, tokenPrefixPartDeviceCode))
}

func (h *HMACCoreStrategy) trimPrefix(tokenString, part string) string {
	if !h.usePrefix {
		return tokenString
	}

	return strings.TrimPrefix(tokenString, h.getPrefix(part))
}

func (h *HMACCoreStrategy) prependPrefix(tokenString, part string) string {
	if !h.usePrefix {
		return tokenString
	}

	return h.getPrefix(part) + tokenString
}

func (h *HMACCoreStrategy) getPrefix(part string) string {
	if !h.usePrefix {
		return ""
	}

	return fmt.Sprintf(h.prefix, part)
}

const (
	tokenPrefixPartAuthorizeCode = "ac"
	tokenPrefixPartAccessToken   = "at"
	tokenPrefixPartRefreshToken  = "rt"
	tokenPrefixPartDeviceCode    = "dc"
)

type CoreStrategyConfigurator interface {
	HMACCoreStrategyConfigurator

	oauth2.AccessTokenIssuerProvider
	oauth2.JWTScopeFieldProvider
}

type HMACCoreStrategyConfigurator interface {
	oauth2.AccessTokenLifespanProvider
	oauth2.RefreshTokenLifespanProvider
	oauth2.AuthorizeCodeLifespanProvider
	oauth2.TokenEntropyProvider
	oauth2.GlobalSecretProvider
	oauth2.RotatedGlobalSecretsProvider
	oauth2.HMACHashingProvider
	oauth2.RFC9628DeviceAuthorizeConfigProvider
}
