// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

const ssfInteroperabilityProfileSignatureBytes = 2048 / 8

// DefaultSecurityEventTokenStrategy signs a Security Event Token with the issuer key through a jwt.Strategy, setting
// the 'typ' header to 'secevent+jwt'. Claims that are nil or that fail SecurityEventTokenClaims.Valid are not signed and
// give ErrServerError.
//
// See: https://www.rfc-editor.org/rfc/rfc8417.html#section-2.2
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-4.1.1
type DefaultSecurityEventTokenStrategy struct {
	// Strategy encodes the token. It must have an issuer that holds the signing key.
	Strategy jwt.Strategy

	// SigningAlg selects the issuer key. Empty means RS256, which is the only value the CAEP Interoperability Profile
	// permits (Profile Section 2.6).
	SigningAlg string
}

// GenerateSecurityEventToken implements SecurityEventTokenStrategy.
func (s *DefaultSecurityEventTokenStrategy) GenerateSecurityEventToken(ctx context.Context, claims *jwt.SecurityEventTokenClaims) (token string, err error) {
	if s.Strategy == nil {
		return "", errorsx.WithStack(ErrServerError.WithDebug("The Security Event Token strategy has no JWT strategy."))
	}

	if claims == nil {
		return "", errorsx.WithStack(ErrServerError.WithDebug("The Security Event Token claims are nil."))
	}

	if err = claims.Valid(); err != nil {
		return "", errorsx.WithStack(ErrServerError.WithHint("The Security Event Token claims are not valid.").WithWrap(err).WithDebugError(err))
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
// A 'jti' the application supplies must be unique among the tokens of the stream (RFC 8417 Section 2.2), so it is
// reused only to send the same token again. The txn should be set, and one that is set must be unique to the underlying
// event that caused the token. Tokens with the same cause, such as a session revoked and a credential change, may share
// it (SSF Section 4.1.9).
//
// A stream whose issuer is not an https URL with no query or fragment uses the issuer, GetIssuer, and gives ErrServerError
// when that is not valid either (SSF Section 8.1.1).
//
// The subject of a verification event and of a stream updated event must be the opaque identifier of the stream, as
// NewSSFVerificationSubject returns for its StreamID, or the result is ErrServerError (SSF Section 8.1.4.1 and Section
// 8.1.5).
//
// A SET requires 'iss', 'iat', 'jti', 'aud' and 'events'. A JWS whose protected header 'typ' is not 'secevent+jwt',
// with or without the 'application/' prefix, gives ErrServerError. So does a JWS that is not signed: one with no 'alg'
// or an 'alg' of 'none', or with an empty signature (RFC 8417 Section 5.1).
//
// The strategy may instead return a JWE that nests the signed SET, which is how a SET that carries personally
// identifiable information or is distributed through a third party is kept confidential (RFC 8417 Section 5.1). The JWE
// requires 'alg', 'enc' and a 'cty' of 'JWT' (RFC 7519 Section 5.2), and a 'typ', when it has one, of 'JWT' or
// 'secevent+jwt'. The nested token is not visible here, so its signature and its 'typ' of 'secevent+jwt' are the duty
// of the strategy. A token that is neither a compact serialized JWS nor JWE gives ErrServerError.
//
// With SSFConfig.EnforceCAEPInteroperabilityProfile, a token that is not a JWS signed with RS256 by an RSA key of at
// least 2048 bits gives ErrServerError, and so does a JWE (CAEP Interoperability Profile Section 2.6).
//
// See: https://www.rfc-editor.org/rfc/rfc8417.html#section-2
// See: https://www.rfc-editor.org/rfc/rfc8417.html#section-5.1
// See: https://www.rfc-editor.org/rfc/rfc7519.html#section-5.2
// See: https://openid.net/specs/openid-caep-interoperability-profile-1_0.html#section-2.6
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-4.1.1
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-4.1.9
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.4.1
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.5
// See: https://www.rfc-editor.org/rfc/rfc8936.html#section-2.3
func (f *Fosite) GenerateSecurityEventToken(ctx context.Context, stream *SSFStream, subject *jwt.SubjectIdentifier, event jwt.SecurityEvent, jti, txn string) (token, usedJTI string, err error) {
	config := f.getSSFConfig(ctx)

	if config == nil || config.TokenStrategy == nil {
		return "", "", errorsx.WithStack(ErrServerError.WithDebug("Failed to generate the Security Event Token because the Shared Signals Framework token strategy is not configured."))
	}

	if stream == nil || len(stream.Audience) == 0 {
		return "", "", errorsx.WithStack(ErrServerError.WithDebug("Failed to generate the Security Event Token because the stream is missing or its audience is empty."))
	}

	stream = f.currentSSFStream(ctx, config, stream)

	if !isValidSSFIssuer(stream.Issuer) {
		return "", "", errorsx.WithStack(ErrServerError.WithDebug("Failed to generate the Security Event Token because the stream has no valid issuer."))
	}

	var claims *jwt.SecurityEventTokenClaims

	if claims, err = jwt.NewSecurityEventTokenClaims(stream.Issuer, stream.Audience, subject, event, txn); err != nil {
		return "", "", errorsx.WithStack(ErrServerError.WithHint("Failed to create the Security Event Token claims.").WithWrap(err).WithDebugError(err))
	}

	if isSSFStreamEvent(claims) && !isSSFStreamSubject(claims.SubjectIdentifier, stream) {
		return "", "", errorsx.WithStack(ErrServerError.WithDebug("Failed to generate the Security Event Token because the subject of a verification or stream updated event must be the opaque identifier of the stream."))
	}

	if jti != "" {
		claims.JTI = jti
	}

	if token, err = config.TokenStrategy.GenerateSecurityEventToken(ctx, claims); err != nil {
		return "", "", errorsx.WithStack(ErrServerError.WithHint("Failed to generate the Security Event Token.").WithWrap(err).WithDebugError(err))
	}

	if fault := securityEventTokenFault(token, config.EnforceCAEPInteroperabilityProfile); fault != "" {
		return "", "", errorsx.WithStack(ErrServerError.WithDebugf("The Security Event Token strategy returned a token %s.", fault))
	}

	return token, claims.JTI, nil
}

func isSSFStreamEvent(claims *jwt.SecurityEventTokenClaims) (is bool) {
	if _, is = claims.Events[jwt.SecurityEventTypeSSFVerification]; is {
		return true
	}

	_, is = claims.Events[jwt.SecurityEventTypeSSFStreamUpdated]

	return is
}

func isSSFStreamSubject(subject *jwt.SubjectIdentifier, stream *SSFStream) (is bool) {
	return subject != nil && stream.StreamID != "" && subject.Format == jwt.SubjectIdentifierFormatOpaque && subject.ID == stream.StreamID
}

type securityEventTokenHeader struct {
	Algorithm   string `json:"alg"`
	Encryption  string `json:"enc"`
	Type        string `json:"typ"`
	ContentType string `json:"cty"`
}

func securityEventTokenFault(token string, profile bool) (fault string) {
	segments := strings.Split(token, ".")

	if !isSecurityEventTokenCompact(segments) {
		return "that is not a compact serialized JWS or JWE"
	}

	// RFC 7515 Section 7.1, RFC 7516 Section 7.1: every segment is base64url without padding. The decoder ignores
	// CR and LF, which are not in the alphabet of RFC 4648 Section 5.
	for _, segment := range segments {
		if _, err := base64.RawURLEncoding.DecodeString(segment); err != nil || strings.ContainsAny(segment, "\r\n") {
			return "with a segment that is not base64url"
		}
	}

	data, err := base64.RawURLEncoding.DecodeString(segments[0])
	if err != nil {
		return "with a protected header that is not base64url"
	}

	var header securityEventTokenHeader

	if err = json.Unmarshal(data, &header); err != nil {
		return "with a protected header that is not valid"
	}

	if len(segments) == 5 {
		// CAEP Interoperability Profile Section 2.6: the signature of a nested token is not visible.
		if profile {
			return "that is encrypted, which hides the signature the CAEP Interoperability Profile constrains"
		}

		return securityEventTokenFaultJWE(&header)
	}

	if fault = securityEventTokenFaultJWS(&header, segments[2]); fault != "" || !profile {
		return fault
	}

	return securityEventTokenFaultCAEPInteroperabilityProfile(&header, segments[2])
}

func securityEventTokenFaultCAEPInteroperabilityProfile(header *securityEventTokenHeader, signature string) (fault string) {
	// CAEP Interoperability Profile Section 2.6: events are signed using RS256 with a key of at least 2048 bits.
	if header.Algorithm != string(jose.RS256) {
		return "that is not signed with RS256 as the CAEP Interoperability Profile requires"
	}

	// RFC 8017 Section 8.2.1: the signature has the octet length of the RSA modulus.
	if data, err := base64.RawURLEncoding.DecodeString(signature); err != nil || len(data) < ssfInteroperabilityProfileSignatureBytes {
		return "that is signed with an RSA key of less than the 2048 bits the CAEP Interoperability Profile requires"
	}

	return ""
}

func isSecurityEventTokenCompact(segments []string) (is bool) {
	switch len(segments) {
	case 3:
		// RFC 7515 Section 4.1.1: the header is never empty, as 'alg' is required.
		return segments[0] != "" && segments[1] != ""
	case 5:
		// RFC 7516 Section 4.1.1: the header is never empty. Section 5.1: the JWE Encrypted Key is empty for direct
		// encryption and direct key agreement. RFC 7518 Section 5.1: every 'enc' algorithm has an IV and a tag.
		return segments[0] != "" && segments[2] != "" && segments[3] != "" && segments[4] != ""
	default:
		return false
	}
}

func securityEventTokenFaultJWS(header *securityEventTokenHeader, signature string) (fault string) {
	// RFC 8417 Section 5.1: the SET is signed. RFC 7515 Section 4.1.1: 'alg' is required.
	if header.Algorithm == "" || strings.EqualFold(header.Algorithm, consts.JSONWebTokenAlgNone) || signature == "" {
		return "that is not signed"
	}

	// RFC 8417 Section 2.3: the SET is explicitly typed.
	if !isSecurityEventTokenHeaderType(header.Type, jwt.JSONWebTokenTypeSecurityEventToken) {
		return "without the 'secevent+jwt' type header"
	}

	return ""
}

func securityEventTokenFaultJWE(header *securityEventTokenHeader) (fault string) {
	// RFC 7516 Section 4.1.1, Section 4.1.2: 'alg' and 'enc' are required.
	if header.Algorithm == "" || strings.EqualFold(header.Algorithm, consts.JSONWebTokenAlgNone) || header.Encryption == "" {
		return "that is not encrypted"
	}

	// RFC 7519 Section 5.2: a Nested JWT has a 'cty' of 'JWT'.
	if !isSecurityEventTokenHeaderType(header.ContentType, jwt.JSONWebTokenTypeJWT) {
		return "that is encrypted without the 'JWT' content type header of a nested token"
	}

	// RFC 8725 Section 3.11: the explicit type of a nested token belongs to the inner token and may repeat on the outer.
	if header.Type != "" && !isSecurityEventTokenHeaderType(header.Type, jwt.JSONWebTokenTypeJWT, jwt.JSONWebTokenTypeSecurityEventToken) {
		return "that is encrypted with a type header other than 'JWT' or 'secevent+jwt'"
	}

	return ""
}

func isSecurityEventTokenHeaderType(value string, types ...string) (is bool) {
	// RFC 8725 Section 3.11: the type is compared case-insensitively, with or without the 'application/' prefix.
	for _, t := range types {
		if strings.EqualFold(value, t) || strings.EqualFold(value, "application/"+t) {
			return true
		}
	}

	return false
}
