// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

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
// include a single '%s' for the purpose of adding the token part (ac, dc, at, rt, and cr; for the Authorize Code,
// Device Code, Access Token, Refresh Token, and Client Registration Token; respectively).
//
// This is the required way to construct a HMACCoreStrategy, not merely a convenience: it is the only place that
// initialises the unexported strategy client registration tokens are signed and verified with, kept on its own
// secret so that rotating the global secret never invalidates a client management token, which cannot be re-issued.
// A struct literal compiles - the other collaborators, Enigma and Config, are exported - but leaves that strategy
// nil, and GenerateClientRegistrationToken/ValidateClientRegistrationToken then return an error naming this
// constructor rather than panicking or silently falling back to Enigma's global secret.
func NewHMACCoreStrategy(config HMACCoreStrategyConfigurator, prefix string) (strategy *HMACCoreStrategy) {
	if len(prefix) == 0 || strings.Count(prefix, "%s") != 1 {
		return &HMACCoreStrategy{
			Enigma:                   &hmac.HMACStrategy{Config: config},
			enigmaClientRegistration: &hmac.HMACStrategy{Config: &clientRegistrationSecretConfig{HMACCoreStrategyConfigurator: config}},
			Config:                   config,
			usePrefix:                false,
		}
	}

	return &HMACCoreStrategy{
		Enigma:                   &hmac.HMACStrategy{Config: config},
		enigmaClientRegistration: &hmac.HMACStrategy{Config: &clientRegistrationSecretConfig{HMACCoreStrategyConfigurator: config}},
		Config:                   config,
		prefix:                   prefix,
		usePrefix:                true,
	}
}

// clientRegistrationSecretConfig adapts an HMACCoreStrategyConfigurator so the embedded hmac.HMACStrategy signs and
// verifies with the client registration token secrets instead of the global ones. Only the two secret getters are
// overridden, by shadowing the promoted methods of the same name; entropy and hashing continue to come from the
// embedded configuration unchanged. HMACCoreStrategyConfigurator is embedded directly, rather than alongside a
// second field of that same type, because it is already a superset of hmac.HMACStrategyConfigurator (the interface
// hmac.HMACStrategy.Config requires) - a second field would only duplicate the one embedded value and create two
// places that must always agree.
type clientRegistrationSecretConfig struct {
	HMACCoreStrategyConfigurator
}

func (c *clientRegistrationSecretConfig) GetGlobalSecret(ctx context.Context) (secret []byte, err error) {
	return c.GetRFC7591ClientRegistrationGlobalSecret(ctx)
}

func (c *clientRegistrationSecretConfig) GetRotatedGlobalSecrets(ctx context.Context) (secrets [][]byte, err error) {
	return c.GetRFC7591ClientRegistrationRotatedGlobalSecrets(ctx)
}

// errHMACCoreStrategyMissingClientRegistrationSecret is returned by GenerateClientRegistrationToken and
// ValidateClientRegistrationToken when enigmaClientRegistration is nil - i.e. this HMACCoreStrategy was assembled
// with a struct literal instead of NewHMACCoreStrategy, so the client registration secret strategy was never wired
// up. This deliberately does not fall back to Enigma's global secret: that fallback is exactly what enigmaClientRegistration
// exists to remove.
func errHMACCoreStrategyMissingClientRegistrationSecret() error {
	return errorsx.WithStack(fmt.Errorf("oauth2: HMACCoreStrategy has no client registration token secret strategy configured; construct it with NewHMACCoreStrategy, not a struct literal, so the client registration secret is wired up"))
}

// HMACCoreStrategy implements the OAuth 2.0 and RFC 7591/7592 opaque token strategies backed by HMAC-signed tokens.
//
// Construct it with NewHMACCoreStrategy, not a struct literal: NewHMACCoreStrategy is the only place that
// initialises enigmaClientRegistration, the unexported strategy client registration tokens are signed and verified
// with on their own secret, and a struct literal leaves it nil.
type HMACCoreStrategy struct {
	Enigma *hmac.HMACStrategy

	// enigmaClientRegistration signs client registration tokens with their own secret, so that rotating the global
	// secret does not invalidate tokens that never expire. It is nil unless this HMACCoreStrategy was built by
	// NewHMACCoreStrategy; GenerateClientRegistrationToken and ValidateClientRegistrationToken guard against that and
	// return a diagnosable error rather than panicking or falling back to Enigma.
	enigmaClientRegistration *hmac.HMACStrategy

	Config interface {
		oauth2.AccessTokenLifespanProvider
		oauth2.RefreshTokenLifespanProvider
		oauth2.AuthorizeCodeLifespanProvider
		oauth2.RFC8628DeviceAuthorizeConfigProvider
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

// IsOpaqueClientRegistrationToken returns true when the token carries this strategy's client registration token
// prefix. Client registration tokens are always opaque, so unlike access tokens there is no JWT alternative.
func (s *HMACCoreStrategy) IsOpaqueClientRegistrationToken(ctx context.Context, tokenString string) bool {
	return s.usePrefix && s.hasPrefix(tokenString, tokenPrefixPartClientRegistrationToken)
}

// ClientRegistrationTokenSignature returns the signature of an RFC 7591 / RFC 7592 client registration token, or an
// empty string when the token is not one. An empty signature can never be a legitimate storage key, so a caller may
// reject on it without a storage round trip.
//
// A nil enigmaClientRegistration - this HMACCoreStrategy was assembled with a struct literal instead of
// NewHMACCoreStrategy - is one such case, and is answered here rather than one layer down: no client registration
// token can have been minted without that strategy, so no signature it computed could resolve to anything, and the
// same condition already turns GenerateClientRegistrationToken and ValidateClientRegistrationToken into a
// diagnosable error.
func (s *HMACCoreStrategy) ClientRegistrationTokenSignature(ctx context.Context, tokenString string) (signature string) {
	if s.enigmaClientRegistration == nil {
		return ""
	}

	if !s.usePrefix || s.IsOpaqueClientRegistrationToken(ctx, tokenString) {
		return s.enigmaClientRegistration.Signature(tokenString)
	}

	return
}

// GenerateClientRegistrationToken mints an RFC 7591 / RFC 7592 client registration token.
func (s *HMACCoreStrategy) GenerateClientRegistrationToken(ctx context.Context, _ oauth2.Requester) (tokenString string, signature string, err error) {
	if s.enigmaClientRegistration == nil {
		return "", "", errHMACCoreStrategyMissingClientRegistrationSecret()
	}

	if tokenString, signature, err = s.enigmaClientRegistration.Generate(ctx); err != nil {
		return "", "", err
	}

	return s.prependPrefix(tokenString, tokenPrefixPartClientRegistrationToken), signature, nil
}

// ValidateClientRegistrationToken validates an RFC 7591 / RFC 7592 client registration token against its session.
//
// Unlike ValidateAccessToken there is no fallback to the configured access token lifespan when the session carries no
// expiry. newClientRegistrationToken always records one - substituting NonExpiringTokenLifespan for a lifespan of zero
// rather than leaving it unset - so a session reaching here without an expiry is malformed, and treating that as
// "never expires" is exactly the silent failure that fallback caused for these tokens before.
func (s *HMACCoreStrategy) ValidateClientRegistrationToken(ctx context.Context, r oauth2.Requester, tokenString string) (err error) {
	if s.enigmaClientRegistration == nil {
		return errHMACCoreStrategyMissingClientRegistrationSecret()
	}

	if s.usePrefix && !s.IsOpaqueClientRegistrationToken(ctx, tokenString) {
		return errorsx.WithStack(oauth2.ErrInvalidTokenFormat.WithHint("Provided Token does not appear to be a Client Registration Token."))
	}

	exp := r.GetSession().GetExpiresAt(oauth2.AccessToken)

	if exp.IsZero() {
		return errorsx.WithStack(oauth2.ErrInvalidTokenFormat.WithHint("Provided Token does not appear to be a Client Registration Token."))
	}

	if exp.Before(time.Now().UTC()) {
		return errorsx.WithStack(oauth2.ErrTokenExpired.WithHintf("Client Registration Token expired at '%s'.", exp))
	}

	return s.enigmaClientRegistration.Validate(ctx, s.trimPrefix(tokenString, tokenPrefixPartClientRegistrationToken))
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
	tokenPrefixPartAuthorizeCode           = "ac"
	tokenPrefixPartAccessToken             = "at"
	tokenPrefixPartRefreshToken            = "rt"
	tokenPrefixPartDeviceCode              = "dc"
	tokenPrefixPartClientRegistrationToken = "cr"
)

type CoreStrategyConfigurator interface {
	HMACCoreStrategyConfigurator

	oauth2.AccessTokenIssuerProvider
	oauth2.JWTScopeFieldProvider
	oauth2.JWTProfileAccessTokensProvider
	oauth2.ConfirmationConfigProvider
}

type HMACCoreStrategyConfigurator interface {
	oauth2.AccessTokenLifespanProvider
	oauth2.RefreshTokenLifespanProvider
	oauth2.AuthorizeCodeLifespanProvider
	oauth2.TokenEntropyProvider
	oauth2.GlobalSecretProvider
	oauth2.RotatedGlobalSecretsProvider
	oauth2.HMACHashingProvider
	oauth2.RFC8628DeviceAuthorizeConfigProvider
	oauth2.RFC7591ClientRegistrationTokenSecretProvider
}
