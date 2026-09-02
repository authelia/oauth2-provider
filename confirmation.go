// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"encoding/json"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jose"
	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

// confirmationMethod is one member of the RFC 7800 'cnf' claim paired with the accessors that move it between a session
// and a set of token claims.
//
// Both directions live in a single entry deliberately. An issuing side without a matching recovery side silently drops
// the binding whenever a stateless token is introspected, because such a token's own claims are the only record of what
// it is bound to; that asymmetry is exactly how 'jkt' came to be lost. Pairing them means a confirmation method cannot
// be half-implemented.
type confirmationMethod struct {
	// name is the member name within the 'cnf' claim, for example 'jkt'.
	name string

	// enabled reports whether the binding method this confirmation describes is turned on. A disabled method is never
	// asserted, because a session outlives a configuration change: a binding recorded while the method was enabled
	// survives on the session after it is turned off, and the handler that would verify it no longer runs. Emitting
	// the confirmation anyway would tell the resource server a proof-of-possession check was performed when none was.
	//
	// Only ApplyConfirmation consults this. RestoreConfirmation deliberately does not: it recovers what a signed token
	// already asserts, which is a statement about how the token was issued rather than about current configuration.
	enabled func(ctx context.Context, config ConfirmationConfigProvider) bool

	// get returns the binding recorded on session, or an empty string when session records none or does not support a
	// binding of this kind at all.
	get func(session Session) string

	// set records value as the binding on session, and does nothing when session does not support a binding of this
	// kind.
	set func(session Session, value string)
}

// confirmationMethods enumerates every RFC 7800 confirmation method this library understands. Adding an entry is all
// that is required for a binding to be minted into JWT profile access tokens, reported by token introspection, and
// recovered from a stateless token; the call sites iterate this table and need no change.
var confirmationMethods = []confirmationMethod{
	{
		name: jwt.ClaimConfirmationJWKThumbprint,
		enabled: func(ctx context.Context, config ConfirmationConfigProvider) bool {
			return config.GetDPoPEnabled(ctx)
		},
		get: func(session Session) (jkt string) {
			if bound, ok := session.(DPoPBoundSession); ok {
				return bound.GetDPoPJWKThumbprint()
			}

			return ""
		},
		set: func(session Session, value string) {
			if bound, ok := session.(DPoPBoundSession); ok {
				bound.SetDPoPJWKThumbprint(value)
			}
		},
	},
	{
		name: jwt.ClaimConfirmationX509SHA256Thumbprint,
		enabled: func(ctx context.Context, config ConfirmationConfigProvider) bool {
			return config.GetMTLSEnabled(ctx)
		},
		get: func(session Session) (x5t string) {
			if bound, ok := session.(MTLSBoundSession); ok {
				return bound.GetClientCertificateSHA256Thumbprint()
			}

			return ""
		},
		set: func(session Session, value string) {
			if bound, ok := session.(MTLSBoundSession); ok {
				bound.SetClientCertificateSHA256Thumbprint(value)
			}
		},
	},
}

// ApplyConfirmation rebuilds the RFC 7800 'cnf' claim in claims from the bindings recorded on session whose binding
// method is currently enabled, and is the only supported way to write that claim.
//
// The claim is rebuilt rather than merged into, so it asserts exactly the bindings the server established and nothing
// else. That matters because the claims a token is minted from include the session's extra claims, which are free-form:
// were the existing value merged into, a 'cnf' placed there would travel into the token, and a resource server reads
// 'cnf' as evidence that a proof-of-possession check was performed. A 'cnf' that would be left empty is removed
// entirely, since an empty confirmation asserts nothing while still suggesting the token is bound.
//
// A binding whose method is disabled is skipped for the same reason, and is skipped rather than erased: a session
// restored from storage still carries a binding recorded while the method was enabled, but the handler that would
// verify it no longer runs, so asserting it would claim a check that did not happen. Leaving the value on the session
// keeps the binding dormant rather than lost, so re-enabling the method resumes both enforcement and this claim.
func ApplyConfirmation(ctx context.Context, config ConfirmationConfigProvider, claims map[string]any, session Session) {
	if claims == nil {
		return
	}

	cnf := map[string]any{}

	for _, method := range confirmationMethods {
		// A nil config asserts nothing, so no method is enabled. Failing closed is deliberate: the alternative
		// direction would emit a confirmation on a misconfigured server, which is the one outcome this claim must
		// never produce. Any existing 'cnf' is still stripped below.
		if config == nil || !method.enabled(ctx, config) {
			continue
		}

		if value := method.get(session); value != "" {
			cnf[method.name] = value
		}
	}

	if len(cnf) == 0 {
		delete(claims, jwt.ClaimConfirmation)

		return
	}

	claims[jwt.ClaimConfirmation] = cnf
}

// RestoreConfirmation records on session the bindings asserted by the RFC 7800 'cnf' claim in claims. It is the inverse
// of ApplyConfirmation, for a stateless token whose own claims are the only record of what it is bound to.
//
// The claims MUST already have been validated, because this trusts them: it is the token's signature that makes 'cnf'
// evidence of a binding the server established rather than an assertion by whoever presented the token.
func RestoreConfirmation(claims map[string]any, session Session) {
	cnf := confirmationClaim(claims)

	for _, method := range confirmationMethods {
		if value, ok := cnf[method.name].(string); ok && value != "" {
			method.set(session, value)
		}
	}
}

// GetDPoPConfirmationJWKThumbprint returns the 'jkt' confirmation method of the RFC 7800 'cnf' claim in claims, or an
// empty string when the claim is absent, is not a JSON object, or carries no JWK thumbprint. It serves callers holding
// claims but no session, such as a resource server taking the bound thumbprint out of an introspection response to hand
// to the RFC 9449 ValidateResourceAccess.
func GetDPoPConfirmationJWKThumbprint(claims map[string]any) (jkt string) {
	jkt, _ = confirmationClaim(claims)[jwt.ClaimConfirmationJWKThumbprint].(string)

	return jkt
}

// GetMTLSConfirmationX509SHA256Thumbprint returns the 'x5t#S256' confirmation method of the RFC 7800 'cnf' claim in
// claims, or an empty string when the claim is absent, is not a JSON object, or carries no certificate thumbprint. It
// serves callers holding claims but no session, such as a resource server taking the bound thumbprint out of an
// introspection response to hand to ValidateClientCertificateBinding.
func GetMTLSConfirmationX509SHA256Thumbprint(claims map[string]any) (x5t string) {
	x5t, _ = confirmationClaim(claims)[jwt.ClaimConfirmationX509SHA256Thumbprint].(string)

	return x5t
}

// GetOIDCKeyBindingConfirmationJWKThumbprint returns the RFC 7638 SHA-256 JWK Thumbprint of the public key carried by
// the 'jwk' confirmation method of the RFC 7800 'cnf' claim in claims, or an empty string when the claim is absent, is
// not a JSON object, or carries no key.
//
// OpenID Connect Key Binding 1.0 Section 4 puts the key itself into 'cnf' rather than its thumbprint, so a caller
// comparing that confirmation against a DPoP proof must first reduce it to the thumbprint the proof is identified by.
// GetDPoPConfirmationJWKThumbprint serves the 'jkt' method RFC 9449 Section 6.1 defines, which needs no reduction.
//
// It errors only when a key is present and cannot be read, which is a token asserting a confirmation that nothing can
// be checked against; that is distinct from, and must not be conflated with, a token asserting no confirmation at all.
func GetOIDCKeyBindingConfirmationJWKThumbprint(claims map[string]any) (jkt string, err error) {
	value, ok := confirmationClaim(claims)[consts.ClaimConfirmationJWK]
	if !ok {
		return "", nil
	}

	var raw []byte

	if raw, err = json.Marshal(value); err != nil {
		return "", err
	}

	key := &jose.JSONWebKey{}

	if err = key.UnmarshalJSON(raw); err != nil {
		return "", err
	}

	return jwt.ThumbprintJWK(key)
}

// confirmationClaim returns the RFC 7800 'cnf' claim from claims, or nil when it is absent or is not a JSON object.
// RFC 7800 Section 3.1 defines 'cnf' as a JSON object, so any other value asserts no confirmation method at all.
func confirmationClaim(claims map[string]any) map[string]any {
	switch value := claims[jwt.ClaimConfirmation].(type) {
	case map[string]any:
		return value
	case jwt.MapClaims:
		return value
	default:
		return nil
	}
}

// idTokenConfirmationGrants are the grant types that may produce a key-bound ID Token. OpenID Connect Key Binding 1.0
// Section 1.4 defines key binding for the Authorization Code Flow and the Device Authorization Flow, and Section 5
// extends it to a refresh of either; support for other flows is out of scope of that specification.
var idTokenConfirmationGrants = []string{
	consts.GrantTypeAuthorizationCode,
	consts.GrantTypeOAuthDeviceCode,
	consts.GrantTypeRefreshToken,
}

// ApplyIDTokenConfirmation writes the OpenID Connect Key Binding 1.0 Section 4 confirmation into an ID Token's claims
// and protected header: the proof-of-possession public key as 'cnf.jwk', and a 'typ' of 'dpop+id_token'. It is the
// only supported way to write that claim, and rebuilds rather than merges for the reason ApplyConfirmation does.
//
// The binding is resolved from the access request in ctx rather than from the requester the ID Token is generated
// from. The Authorization Code and Device Authorization flows generate theirs from the request persisted at the
// authorization endpoint, whose session necessarily predates the DPoP proof presented at the token endpoint, so that
// session can never carry the key. It also supplies the grant type and granted scopes, neither of which is on a
// session at all.
//
// It fails closed: an ID Token generated outside a token endpoint request carries no confirmation, which is what
// keeps the Implicit and Hybrid flows unbound as Section 1.4 requires. Whenever it emits no confirmation it also
// removes the 'typ' header, see clearIDTokenConfirmationHeader.
func ApplyIDTokenConfirmation(ctx context.Context, config IDTokenConfirmationConfigProvider, claims *jwt.IDTokenClaims, headers *jwt.Headers) (err error) {
	if claims == nil {
		return nil
	}

	claims.Confirmation = nil

	// The headers belong to the session rather than to a copy of it, so every path that leaves the confirmation
	// empty must also take the header back off; a deferred cleanup keyed on the claim keeps a later early return
	// from reintroducing the mismatch.
	defer func() {
		if len(claims.Confirmation) == 0 {
			clearIDTokenConfirmationHeader(headers)
		}
	}()

	// Both gates are required. A key recorded while DPoP was enabled survives on the session after it is turned off,
	// and the handlers that would demand a proof for it no longer run, so asserting the confirmation would tell the
	// Relying Party a proof of possession was checked when none was.
	if config == nil || !config.GetOIDCKeyBindingEnabled(ctx) || !config.GetDPoPEnabled(ctx) {
		return nil
	}

	requester, ok := ctx.Value(AccessRequestContextKey).(AccessRequester)
	if !ok || requester == nil {
		return nil
	}

	if !requester.GetGrantTypes().HasOneOf(idTokenConfirmationGrants...) {
		return nil
	}

	session := requester.GetSession()

	bound, ok := session.(DPoPBoundSession)
	if !ok {
		return nil
	}

	// The marker rather than the current request's granted scopes, so that Section 5 holds across a refresh that
	// narrows 'bound_key' away: the refreshed ID Token's 'cnf' must equal the original's, and the grant is still
	// bound to the key whatever the client asks for now.
	if !bound.GetOIDCKeyBindingGranted() {
		return nil
	}

	raw := bound.GetDPoPPublicKeyJWK()

	if len(raw) == 0 {
		// Section 2.3 requires the OP confirm the 'c_s256' claim of the DPoP proof, and no key is recorded unless
		// that check passed. A grant that reached this point with 'bound_key' granted and a DPoP bound session
		// therefore asked for a key-bound ID Token without proving possession.
		if bound.GetDPoPJWKThumbprint() != "" {
			return errorsx.WithStack(ErrInvalidDPoPProof.WithHint("The request requires a DPoP proof carrying the 'c_s256' claim because the 'bound_key' scope was granted, but none was provided."))
		}

		return nil
	}

	key := map[string]any{}

	if err = json.Unmarshal(raw, &key); err != nil {
		return errorsx.WithStack(ErrServerError.WithHint("The DPoP proof-of-possession key recorded on the session could not be read.").WithWrap(err).WithDebugError(err))
	}

	// Section 4 requires the 'cnf' claim and a 'typ' of 'dpop+id_token' together. A token carrying the claim without
	// the type is not a key-bound ID Token, and Section 9.3 has the Relying Party reject it for the missing type, so
	// the claim is not written at all when there is nowhere to record the type.
	if headers == nil {
		return errorsx.WithStack(ErrServerError.WithHint("The session did not provide ID Token headers to carry the key binding token type."))
	}

	claims.Confirmation = map[string]any{consts.ClaimConfirmationJWK: key}

	headers.Add(consts.JSONWebTokenHeaderType, consts.JSONWebTokenTypeDPoPIDToken)

	return nil
}

func clearIDTokenConfirmationHeader(headers *jwt.Headers) {
	if headers == nil {
		return
	}

	if typ, ok := headers.Get(consts.JSONWebTokenHeaderType).(string); ok && typ == consts.JSONWebTokenTypeDPoPIDToken {
		delete(headers.Extra, consts.JSONWebTokenHeaderType)
	}
}
