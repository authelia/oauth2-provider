package oauth2

import (
	"context"
	"fmt"
	"strings"
	"time"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/randx"
	"authelia.com/provider/oauth2/token/hmac"
	"authelia.com/provider/oauth2/x/errorsx"
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

// IsOpaqueAccessToken implements oauth2.AccessTokenStrategy.
func (s *HMACCoreStrategy) IsOpaqueAccessToken(ctx context.Context, tokenString string) bool {
	return s.usePrefix && s.hasPrefix(tokenString, tokenPrefixPartAccessToken)
}

// AccessTokenSignature implements oauth2.AccessTokenStrategy.
func (s *HMACCoreStrategy) AccessTokenSignature(ctx context.Context, tokenString string) (signature string) {
	if !s.usePrefix || s.IsOpaqueAccessToken(ctx, tokenString) {
		return s.Enigma.Signature(tokenString)
	}

	return
}

// GenerateAccessToken implements oauth2.AccessTokenStrategy.
func (s *HMACCoreStrategy) GenerateAccessToken(ctx context.Context, _ oauth2.Requester) (tokenString string, signature string, err error) {
	if tokenString, signature, err = s.Enigma.Generate(ctx); err != nil {
		return "", "", err
	}

	return s.prependPrefix(tokenString, tokenPrefixPartAccessToken), signature, nil
}

// ValidateAccessToken implements oauth2.AccessTokenStrategy.
func (s *HMACCoreStrategy) ValidateAccessToken(ctx context.Context, r oauth2.Requester, tokenString string) (err error) {
	if s.usePrefix && !s.IsOpaqueAccessToken(ctx, tokenString) {
		return errorsx.WithStack(oauth2.ErrInvalidTokenFormat.WithHint("Provided Token does not appear to be an Access Token."))
	}

	var exp = r.GetSession().GetExpiresAt(oauth2.AccessToken)

	if exp.IsZero() && r.GetRequestedAt().Add(s.Config.GetAccessTokenLifespan(ctx)).Before(time.Now().UTC()) {
		return errorsx.WithStack(oauth2.ErrTokenExpired.WithHintf("Access Token expired at '%s'.", r.GetRequestedAt().Add(s.Config.GetAccessTokenLifespan(ctx))))
	}

	if !exp.IsZero() && exp.Before(time.Now().UTC()) {
		return errorsx.WithStack(oauth2.ErrTokenExpired.WithHintf("Access Token expired at '%s'.", exp))
	}

	return s.Enigma.Validate(ctx, s.trimPrefix(tokenString, tokenPrefixPartAccessToken))
}

// IsOpaqueRefreshToken implements oauth2.RefreshTokenStrategy.
func (s *HMACCoreStrategy) IsOpaqueRefreshToken(ctx context.Context, tokenString string) bool {
	return s.usePrefix && s.hasPrefix(tokenString, tokenPrefixPartRefreshToken)
}

// RefreshTokenSignature implements oauth2.RefreshTokenStrategy.
func (s *HMACCoreStrategy) RefreshTokenSignature(ctx context.Context, tokenString string) (signature string) {
	if !s.usePrefix || s.IsOpaqueRefreshToken(ctx, tokenString) {
		return s.Enigma.Signature(tokenString)
	}

	return
}

// GenerateRefreshToken implements oauth2.RefreshTokenStrategy.
func (s *HMACCoreStrategy) GenerateRefreshToken(ctx context.Context, _ oauth2.Requester) (tokenString string, signature string, err error) {
	if tokenString, signature, err = s.Enigma.Generate(ctx); err != nil {
		return "", "", err
	}

	return s.prependPrefix(tokenString, tokenPrefixPartRefreshToken), signature, nil
}

// ValidateRefreshToken implements oauth2.RefreshTokenStrategy.
func (s *HMACCoreStrategy) ValidateRefreshToken(ctx context.Context, r oauth2.Requester, tokenString string) (err error) {
	if s.usePrefix && !s.IsOpaqueRefreshToken(ctx, tokenString) {
		return errorsx.WithStack(oauth2.ErrInvalidTokenFormat.WithHint("Provided Token does not appear to be a Refresh Token."))
	}

	var exp = r.GetSession().GetExpiresAt(oauth2.RefreshToken)

	if exp.IsZero() {
		return s.Enigma.Validate(ctx, s.trimPrefix(tokenString, tokenPrefixPartRefreshToken))
	}

	if exp.Before(time.Now().UTC()) {
		return errorsx.WithStack(oauth2.ErrTokenExpired.WithHintf("Refresh Token expired at '%s'.", exp))
	}

	return s.Enigma.Validate(ctx, s.trimPrefix(tokenString, tokenPrefixPartRefreshToken))
}

// IsOpaqueAuthorizeCode implements oauth2.AuthorizeCodeStrategy.
func (s *HMACCoreStrategy) IsOpaqueAuthorizeCode(ctx context.Context, tokenString string) bool {
	return s.usePrefix && s.hasPrefix(tokenString, tokenPrefixPartAuthorizeCode)
}

// AuthorizeCodeSignature implements oauth2.AuthorizeCodeStrategy.
func (s *HMACCoreStrategy) AuthorizeCodeSignature(ctx context.Context, tokenString string) (signature string) {
	if !s.usePrefix || s.IsOpaqueAuthorizeCode(ctx, tokenString) {
		return s.Enigma.Signature(tokenString)
	}

	return
}

// GenerateAuthorizeCode implements oauth2.AuthorizeCodeStrategy.
func (s *HMACCoreStrategy) GenerateAuthorizeCode(ctx context.Context, _ oauth2.Requester) (tokenString string, signature string, err error) {
	if tokenString, signature, err = s.Enigma.Generate(ctx); err != nil {
		return "", "", err
	}

	return s.prependPrefix(tokenString, tokenPrefixPartAuthorizeCode), signature, nil
}

// ValidateAuthorizeCode implements oauth2.AuthorizeCodeStrategy.
func (s *HMACCoreStrategy) ValidateAuthorizeCode(ctx context.Context, r oauth2.Requester, tokenString string) (err error) {
	if s.usePrefix && !s.IsOpaqueAuthorizeCode(ctx, tokenString) {
		return errorsx.WithStack(oauth2.ErrInvalidTokenFormat.WithHint("Provided Token does not appear to be an Authorization Code."))
	}

	var exp = r.GetSession().GetExpiresAt(oauth2.AuthorizeCode)

	if exp.IsZero() && r.GetRequestedAt().Add(s.Config.GetAuthorizeCodeLifespan(ctx)).Before(time.Now().UTC()) {
		return errorsx.WithStack(oauth2.ErrTokenExpired.WithHintf("Authorize Code expired at '%s'.", r.GetRequestedAt().Add(s.Config.GetAuthorizeCodeLifespan(ctx))))
	}

	if !exp.IsZero() && exp.Before(time.Now().UTC()) {
		return errorsx.WithStack(oauth2.ErrTokenExpired.WithHintf("Authorize Code expired at '%s'.", exp))
	}

	return s.Enigma.Validate(ctx, s.trimPrefix(tokenString, tokenPrefixPartAuthorizeCode))
}

func (s *HMACCoreStrategy) RFC8628UserCodeSignature(ctx context.Context, tokenString string) (signature string, err error) {
	return s.Enigma.GenerateHMACForString(ctx, tokenString)
}

// GenerateRFC8628UserCode implements rfc8628.UserCodeStrategy.
func (s *HMACCoreStrategy) GenerateRFC8628UserCode(ctx context.Context) (tokenString string, signature string, err error) {
	seq, err := randx.RuneSequence(8, []rune("BCDFGHJKLMNPQRSTVWXZ"))
	if err != nil {
		return "", "", err
	}

	userCode := string(seq)

	signUserCode, err := s.RFC8628UserCodeSignature(ctx, userCode)
	if err != nil {
		return "", "", err
	}

	return userCode, signUserCode, nil
}

// ValidateRFC8628UserCode implements rfc8628.UserCodeStrategy.
func (s *HMACCoreStrategy) ValidateRFC8628UserCode(ctx context.Context, r oauth2.Requester, code string) (err error) {
	var exp = r.GetSession().GetExpiresAt(oauth2.UserCode)

	if exp.IsZero() && r.GetRequestedAt().Add(s.Config.GetRFC8628CodeLifespan(ctx)).Before(time.Now().UTC()) {
		return errorsx.WithStack(oauth2.ErrDeviceExpiredToken.WithHintf("User Code expired at '%s'.", r.GetRequestedAt().Add(s.Config.GetRFC8628CodeLifespan(ctx))))
	}

	if !exp.IsZero() && exp.Before(time.Now().UTC()) {
		return errorsx.WithStack(oauth2.ErrDeviceExpiredToken.WithHintf("User Code expired at '%s'.", exp))
	}

	return nil
}

// IsOpaqueRFC8628DeviceCode implements rfc8628.DeviceCodeStrategy.
func (s *HMACCoreStrategy) IsOpaqueRFC8628DeviceCode(ctx context.Context, tokenString string) bool {
	return s.usePrefix && s.hasPrefix(tokenString, tokenPrefixPartDeviceCode)
}

// RFC8628DeviceCodeSignature implements rfc8628.DeviceCodeStrategy.
func (s *HMACCoreStrategy) RFC8628DeviceCodeSignature(ctx context.Context, tokenString string) (signature string, err error) {
	if !s.usePrefix || s.IsOpaqueRFC8628DeviceCode(ctx, tokenString) {
		return s.Enigma.Signature(tokenString), nil
	}

	return "", errorsx.WithStack(oauth2.ErrInvalidTokenFormat.WithHint("Provided Token does not appear to be a Device Code."))
}

// GenerateRFC8628DeviceCode implements rfc8628.DeviceCodeStrategy.
func (s *HMACCoreStrategy) GenerateRFC8628DeviceCode(ctx context.Context) (tokenString string, signature string, err error) {
	tokenString, sig, err := s.Enigma.Generate(ctx)
	if err != nil {
		return "", "", err
	}

	return s.getPrefix(tokenPrefixPartDeviceCode) + tokenString, sig, nil
}

// ValidateRFC8628DeviceCode implements rfc8628.DeviceCodeStrategy.
func (s *HMACCoreStrategy) ValidateRFC8628DeviceCode(ctx context.Context, r oauth2.Requester, code string) (err error) {
	if s.usePrefix && !s.IsOpaqueRFC8628DeviceCode(ctx, code) {
		return errorsx.WithStack(oauth2.ErrInvalidTokenFormat.WithHint("Provided Token does not appear to be a Device Code."))
	}

	var exp = r.GetSession().GetExpiresAt(oauth2.DeviceCode)

	if exp.IsZero() && r.GetRequestedAt().Add(s.Config.GetRFC8628CodeLifespan(ctx)).Before(time.Now().UTC()) {
		return errorsx.WithStack(oauth2.ErrDeviceExpiredToken.WithHintf("Device Code expired at '%s'.", r.GetRequestedAt().Add(s.Config.GetRFC8628CodeLifespan(ctx))))
	}

	if !exp.IsZero() && exp.Before(time.Now().UTC()) {
		return errorsx.WithStack(oauth2.ErrDeviceExpiredToken.WithHintf("Device Code expired at '%s'.", exp))
	}

	return s.Enigma.Validate(ctx, s.trimPrefix(code, tokenPrefixPartDeviceCode))
}

func (s *HMACCoreStrategy) hasPrefix(tokenString, part string) (has bool) {
	if !s.usePrefix {
		return false
	}

	return strings.HasPrefix(tokenString, s.getPrefix(part))
}

func (s *HMACCoreStrategy) trimPrefix(tokenString, part string) string {
	if !s.usePrefix {
		return tokenString
	}

	return strings.TrimPrefix(tokenString, s.getPrefix(part))
}

func (s *HMACCoreStrategy) prependPrefix(tokenString, part string) string {
	if !s.usePrefix {
		return tokenString
	}

	return s.getPrefix(part) + tokenString
}

func (s *HMACCoreStrategy) getPrefix(part string) string {
	if !s.usePrefix {
		return ""
	}

	return fmt.Sprintf(s.prefix, part)
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
	oauth2.JWTProfileAccessTokensProvider
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
