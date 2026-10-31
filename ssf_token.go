// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"

	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

// DefaultSecurityEventTokenStrategy signs a Security Event Token with the issuer key through a jwt.Strategy, setting
// the 'typ' header to 'secevent+jwt'.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-4.1.1
type DefaultSecurityEventTokenStrategy struct {
	// Strategy encodes the token. It must have an issuer that holds the signing key.
	Strategy jwt.Strategy

	// SigningAlg selects the issuer key. Empty means RS256.
	SigningAlg string
}

// GenerateSecurityEventToken implements SecurityEventTokenStrategy.
func (s *DefaultSecurityEventTokenStrategy) GenerateSecurityEventToken(ctx context.Context, claims *jwt.SecurityEventTokenClaims) (token string, err error) {
	if s.Strategy == nil {
		return "", errorsx.WithStack(ErrServerError.WithDebug("The Security Event Token strategy has no JWT strategy."))
	}

	if token, _, err = s.Strategy.Encode(ctx, claims,
		jwt.WithHeaders(&jwt.Headers{Extra: map[string]any{jwt.JSONWebTokenHeaderType: jwt.JSONWebTokenTypeSecurityEventToken}}),
		jwt.WithIssuerSigningAlg(s.SigningAlg),
	); err != nil {
		return "", errorsx.WithStack(err)
	}

	return token, nil
}

// GenerateSecurityEventToken returns a signed Security Event Token carrying the event for the subject, using the issuer
// and audience of the stream, and the 'jti' it used. An empty jti generates one. A retry of the same event should reuse
// the same 'jti', which is also the key of a poll response and of an acknowledgement.
//
// A stream whose issuer is not an https URL with no query or fragment uses SSFConfig.Issuer, and gives ErrServerError
// when that is not valid either (SSF Section 8.1.1).
//
// A SET requires 'iss', 'iat', 'jti', 'aud' and 'events'. A token whose protected header 'typ' is not 'secevent+jwt',
// with or without the 'application/' prefix, gives ErrServerError.
//
// See: https://www.rfc-editor.org/rfc/rfc8417.html#section-2
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-4.1.1
// See: https://www.rfc-editor.org/rfc/rfc8936.html#section-2.3
func (f *Fosite) GenerateSecurityEventToken(ctx context.Context, stream *SSFStream, subject *jwt.SubjectIdentifier, event jwt.SecurityEvent, jti, txn string) (token, usedJTI string, err error) {
	config := f.getSSFConfig(ctx)

	if config == nil || config.TokenStrategy == nil {
		return "", "", errorsx.WithStack(ErrServerError.WithDebug("Failed to generate the Security Event Token because the Shared Signals Framework token strategy is not configured."))
	}

	if stream == nil || len(stream.Audience) == 0 {
		return "", "", errorsx.WithStack(ErrServerError.WithDebug("Failed to generate the Security Event Token because the stream is missing or its audience is empty."))
	}

	stream = config.currentSSFStream(stream)

	if !isValidSSFIssuer(stream.Issuer) {
		return "", "", errorsx.WithStack(ErrServerError.WithDebug("Failed to generate the Security Event Token because the stream has no valid issuer."))
	}

	var claims *jwt.SecurityEventTokenClaims

	if claims, err = jwt.NewSecurityEventTokenClaims(stream.Issuer, stream.Audience, subject, event, txn); err != nil {
		return "", "", errorsx.WithStack(ErrServerError.WithHint("Failed to create the Security Event Token claims.").WithWrap(err).WithDebugError(err))
	}

	if jti != "" {
		claims.JTI = jti
	}

	if token, err = config.TokenStrategy.GenerateSecurityEventToken(ctx, claims); err != nil {
		return "", "", errorsx.WithStack(ErrServerError.WithHint("Failed to generate the Security Event Token.").WithWrap(err).WithDebugError(err))
	}

	if !isSecurityEventTokenType(token) {
		return "", "", errorsx.WithStack(ErrServerError.WithDebug("The Security Event Token strategy returned a token without the 'secevent+jwt' type header."))
	}

	return token, claims.JTI, nil
}

// isSecurityEventTokenType reports whether the protected header of the compact token has the 'secevent+jwt' type,
// compared case-insensitively with or without the 'application/' prefix (RFC 8725 Section 3.11).
func isSecurityEventTokenType(token string) (is bool) {
	segment, _, _ := strings.Cut(token, ".")

	data, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return false
	}

	var header struct {
		Type string `json:"typ"`
	}

	if err = json.Unmarshal(data, &header); err != nil {
		return false
	}

	return strings.EqualFold(header.Type, jwt.JSONWebTokenTypeSecurityEventToken) || strings.EqualFold(header.Type, "application/"+jwt.JSONWebTokenTypeSecurityEventToken)
}
