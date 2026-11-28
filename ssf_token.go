// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/reflection"
	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

const ssfInteroperabilityProfileSignatureBytes = 2048 / 8

// DefaultSecurityEventTokenStrategy signs a Security Event Token with the issuer key through a jwt.Strategy, setting
// the 'typ' header to 'secevent+jwt'. Claims that are nil or that fail SecurityEventTokenClaims.Valid are not signed and
// give ErrServerError.
//
// The signed token is nested in a JWE when the client is a SecurityEventTokenClient with an encryption algorithm, which
// selects a key from the JSON Web Key Set of the client, or derives one from the secret of a confidential client for a
// symmetric algorithm (RFC 8417 Section 5.1). A client with no key the algorithm can use gives an error. The JWE has a
// 'cty' and a 'typ' of 'JWT'.
//
// The token, nested or not, is only signed with an algorithm the FAPI 2.0 Security Profile permits when the client or
// the authorization server is held to the profile, the latter as IsFAPI2SecurityProfile reports for the context.
//
// An encryption algorithm of 'none' gives ErrServerError rather than a signed token. So does a SigningAlg of HS256,
// HS384 or HS512 for a client with an encryption algorithm, as the key would be the client secret and not the issuer
// key. So does a Strategy that returns anything other than a JWE for a client with an encryption algorithm, and a
// client that is a nil pointer.
//
// See: https://www.rfc-editor.org/rfc/rfc8417.html#section-2.2
// See: https://www.rfc-editor.org/rfc/rfc8417.html#section-5.1
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-4.1.1
type DefaultSecurityEventTokenStrategy struct {
	// Strategy encodes the token. It must have an issuer that holds the signing key.
	Strategy jwt.Strategy

	// SigningAlg selects the issuer key. Empty means RS256, which is the only value the CAEP Interoperability Profile
	// permits (Profile Section 2.6), and which the FAPI 2.0 Security Profile does not permit (Section 5.4.1).
	SigningAlg string
}

// GenerateSecurityEventToken implements SecurityEventTokenStrategy.
func (s *DefaultSecurityEventTokenStrategy) GenerateSecurityEventToken(ctx context.Context, client Client, claims *jwt.SecurityEventTokenClaims) (token string, err error) {
	if s.Strategy == nil {
		return "", errorsx.WithStack(ErrServerError.WithDebug("The Security Event Token strategy has no JWT strategy."))
	}

	if claims == nil {
		return "", errorsx.WithStack(ErrServerError.WithDebug("The Security Event Token claims are nil."))
	}

	if err = claims.Valid(); err != nil {
		return "", errorsx.WithStack(ErrServerError.WithHint("The Security Event Token claims are not valid.").WithWrap(err).WithDebugError(err))
	}

	if client != nil && reflection.IsNil(client) {
		return "", errorsx.WithStack(ErrServerError.WithDebug("The Security Event Token client is a nil pointer."))
	}

	opts := append(FAPI2SecurityProfileEncodeOptions(ctx, nil, client),
		jwt.WithHeaders(&jwt.Headers{Extra: map[string]any{jwt.JSONWebTokenHeaderType: jwt.JSONWebTokenTypeSecurityEventToken}}),
	)

	enc := jwt.NewSecurityEventTokenClient(client, s.SigningAlg)

	if enc != nil {
		if jwt.IsNoneAlg(enc.GetEncryptionAlg()) {
			return "", errorsx.WithStack(ErrServerError.WithDebug("The Security Event Token encryption algorithm of the client must not be 'none'."))
		}

		if jwt.IsSignedJWTClientSecretAlgStr(enc.GetSigningAlg()) {
			return "", errorsx.WithStack(ErrServerError.WithDebugf("The Security Event Token signing algorithm '%s' is symmetric, which would sign the token with the client secret rather than the issuer key.", enc.GetSigningAlg()))
		}

		opts = append(opts, jwt.WithClient(enc))
	} else {
		opts = append(opts, jwt.WithIssuerSigningAlg(s.SigningAlg))
	}

	if token, _, err = s.Strategy.Encode(ctx, claims, opts...); err != nil {
		return "", errorsx.WithStack(err)
	}

	// RFC 8417 Section 5.1: a client that configures encryption is never given a token that is only signed.
	if enc != nil && !isSecurityEventTokenCompactJWE(token) {
		return "", errorsx.WithStack(ErrServerError.WithDebug("The JWT strategy returned a Security Event Token that is not a JWE for a client that configures encryption."))
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
// The client that owns the stream, its ClientID, is loaded from the store and passed to the strategy, which is how the
// strategy encrypts the token to that client. A stream with no ClientID, or one whose client does not load, gives
// ErrServerError. So does a token that is not a JWE when that client is a SecurityEventTokenClient with an encryption
// algorithm, whichever strategy returned it.
//
// With SSFConfig.EnforceCAEPInteroperabilityProfile, a token that is not a JWS signed with RS256 by an RSA key of at
// least 2048 bits gives ErrServerError, and so does a JWE (CAEP Interoperability Profile Section 2.6). A client
// configured for encryption therefore gives ErrServerError with it enabled.
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

	var client Client

	if client, err = f.ssfStreamOwner(ctx, stream); err != nil {
		return "", "", err
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

	if token, err = config.TokenStrategy.GenerateSecurityEventToken(newFAPI2SecurityProfileContext(ctx, f.Config), client, claims); err != nil {
		return "", "", errorsx.WithStack(ErrServerError.WithHint("Failed to generate the Security Event Token.").WithWrap(err).WithDebugError(err))
	}

	if err = f.validateSecurityEventToken(ctx, config, client, token); err != nil {
		return "", "", err
	}

	// RFC 8417 Section 5.1: a client that configures encryption is never given a token that is only signed.
	if isSecurityEventTokenEncryptionClient(client) && !isSecurityEventTokenCompactJWE(token) {
		return "", "", errorsx.WithStack(ErrServerError.WithDebug("The Security Event Token strategy returned a token that is not a JWE for a client that configures encryption."))
	}

	return token, claims.JTI, nil
}

func (f *Fosite) ssfStreamOwner(ctx context.Context, stream *SSFStream) (client Client, err error) {
	if stream.ClientID == "" || f.Store == nil {
		return nil, errorsx.WithStack(ErrServerError.WithDebug("Failed to generate the Security Event Token because the stream has no owner or the store is not configured."))
	}

	if client, err = f.Store.GetClient(ctx, stream.ClientID); err != nil {
		return nil, errorsx.WithStack(ErrServerError.WithHint("Failed to load the client that owns the stream.").WithWrap(err).WithDebugError(err))
	}

	if reflection.IsNil(client) {
		return nil, errorsx.WithStack(ErrServerError.WithDebug("Failed to generate the Security Event Token because the store returned no client for the owner of the stream."))
	}

	return client, nil
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

func (f *Fosite) validateSecurityEventToken(ctx context.Context, config *SSFConfig, client Client, token string) (err error) {
	if fault := securityEventTokenFault(token, config.EnforceCAEPInteroperabilityProfile); fault != "" {
		return errorsx.WithStack(ErrServerError.WithDebugf("The Security Event Token strategy returned a token %s.", fault))
	}

	if !IsFAPI2SecurityProfile(ctx, f.Config) && !IsFAPI2SecurityProfileClient(client) || isSecurityEventTokenCompactJWE(token) {
		return nil
	}

	if alg := securityEventTokenAlgorithm(token); !slices.Contains(FAPI2SecurityProfileSigningAlgValues, alg) {
		return errorsx.WithStack(ErrServerError.WithDebugf("The Security Event Token strategy returned a token signed with the 'alg' '%s', which the FAPI 2.0 Security Profile does not permit.", alg))
	}

	return nil
}

func securityEventTokenAlgorithm(token string) (alg string) {
	data, err := base64.RawURLEncoding.DecodeString(token[:max(strings.IndexByte(token, '.'), 0)])
	if err != nil {
		return ""
	}

	var header securityEventTokenHeader

	if err = json.Unmarshal(data, &header); err != nil {
		return ""
	}

	return header.Algorithm
}

func isSecurityEventTokenEncryptionClient(client Client) (is bool) {
	c, ok := client.(interface{ GetSecurityEventTokenEncryptedResponseAlg() string })

	return ok && c.GetSecurityEventTokenEncryptedResponseAlg() != ""
}

func isSecurityEventTokenCompactJWE(token string) (is bool) {
	segments := strings.Split(token, ".")

	return len(segments) == 5 && isSecurityEventTokenCompact(segments)
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
