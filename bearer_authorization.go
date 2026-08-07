// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"net/http"
	"strings"

	"authelia.com/provider/oauth2/x/errorsx"
)

// BearerAuthorizationConfig is the configuration ValidateBearerAuthorization depends on.
//
// It names no ScopeStrategyProvider or AudienceStrategyProvider. An endpoint authorises a bearer credential by exact
// containment of a required scope and audience in the grant it already carries, never through a configured or
// client-supplied strategy.
type BearerAuthorizationConfig interface {
	DPoPConfigProvider
	MTLSConfigProvider
}

// BearerAuthorization is the per-endpoint policy a caller resolves from its own configuration and hands to
// ValidateBearerAuthorization.
type BearerAuthorization struct {
	// Audiences are the permitted audiences. The credential must carry at least one. When empty the check falls back
	// to Endpoint, and then to RequestURL.
	Audiences []string

	// Endpoint is the configured absolute endpoint URL, used as the permitted audience when Audiences is empty.
	//
	// It exists so a deployment which has configured its endpoint URL does not depend on RequestURL, which is
	// reconstructed from the client-controlled Host header and X-Forwarded-Proto. Without it a caller holding a token
	// audienced at another origin could send a matching Host header and satisfy the check.
	//
	// Only the client registration endpoint has such a URL to supply. The introspection endpoint has none, so it
	// leaves this empty and falls through from its configured list to RequestURL.
	Endpoint string

	// Scopes are the required scopes. The credential must carry at least one. Empty means no scope check; both
	// shipped endpoints substitute a non-empty default, so only a custom Configurator can reach that state.
	Scopes []string
}

// ValidateBearerAuthorization performs the checks common to every endpoint that accepts an Access Token as a bearer
// credential authorizing the call. requester is the resolved credential; token is the raw value as presented.
//
// The order is proof-of-possession, then scope, then audience, and it bounds disclosure. ErrInvalidDPoPProof and
// ErrInsufficientScope are distinguishable, while every other failure reports ErrInvalidToken (RFC 6750 Section 3.1:
// "expired, revoked, malformed, or invalid for other reasons"). A distinguishable error implies every check before it
// passed:
//
//   - Proof-of-possession runs first, so ErrInvalidDPoPProof discloses only that the credential resolved and is
//     bound, which its holder already knows. The scope diagnostic is therefore only ever delivered to a caller who
//     has proven possession of the key. The enforcement rejection of an unbound credential runs here for the same
//     reason.
//   - Scope runs before audience, so ErrInsufficientScope discloses nothing about the audience. The audience failure
//     reports ErrInvalidToken and stays indistinguishable from expiry, revocation, and an unknown token.
//
// Proof-of-possession cannot run earlier: validating the proof requires the token's bound thumbprint, which requires
// the resolved session the caller has already fetched.
func ValidateBearerAuthorization(ctx context.Context, config BearerAuthorizationConfig, r *http.Request, requester Requester, token string, auth BearerAuthorization) (err error) {
	if err = validateBearerProofOfPossession(ctx, config, r, requester, token); err != nil {
		return err
	}

	if err = validateBearerScope(requester, auth.Scopes); err != nil {
		return err
	}

	return validateBearerAudience(r, requester, auth)
}

// validateBearerProofOfPossession enforces the RFC 9449 (DPoP) and RFC 8705 (mTLS) bindings the credential carries,
// and where the deployment enforces a binding method, that it carries one at all. The endpoint is the resource server
// for that credential: a DPoP-bound token accepted as a plain bearer credential can be lifted out of a proxy log and
// replayed with no key.
//
// Each enabled method contributes one of three outcomes, chosen by whether the credential is bound:
//
//   - Bound. The binding is verified unconditionally, however the deployment has configured enforcement.
//   - Unbound and the method is enforced. The credential is rejected, including one issued before enforcement was
//     turned on. Admitting it would leave the deployment enforcing binding at issuance but not at use.
//   - Unbound and the method is not enforced. Admitted unchanged.
//
// A method disabled in configuration contributes no check, whatever its enforcement setting. That matches
// ApplyConfirmation: a session outlives a configuration change, and enforcing a binding the rest of the deployment
// has stopped asserting would reject a credential nothing else considers bound.
//
// The two methods are independent in both directions. A credential carrying both bindings must satisfy both, and a
// deployment enforcing both requires the credential to carry both.
//
// The rejection of an unbound credential reports ErrInvalidToken, the code both underlying validators already use for
// a credential that is not bound, so an enforcement rejection stays indistinguishable on the wire from the mismatch
// it precedes. It is not ErrInvalidDPoPProof: no proof was deemed invalid under the RFC 9449 Section 4.3 criteria,
// and there may be no proof at all.
//
// Errors from the underlying strategies are returned unwrapped, since rfc9449 and ValidateClientCertificateBinding
// already report the codes their specifications require and the response writers depend on that distinction.
func validateBearerProofOfPossession(ctx context.Context, config BearerAuthorizationConfig, r *http.Request, requester Requester, token string) (err error) {
	// A nil session, and one whose type cannot record a binding, both leave the thumbprint empty below rather than
	// returning early: such a credential is unbound as far as this endpoint can tell, which is the condition an
	// enforced method must reject.
	session := requester.GetSession()

	if config.GetDPoPEnabled(ctx) {
		var jkt string

		if bound, ok := session.(DPoPBoundSession); ok {
			jkt = bound.GetDPoPJWKThumbprint()
		}

		switch {
		case jkt != "":
			strategy, isResourceStrategy := config.GetDPoPStrategy(ctx).(DPoPResourceStrategy)

			// Fail closed: the credential asserts a binding this deployment cannot verify, so it must not be
			// accepted as if it carried none. This is a server capability gap and not a failure of the Section 4.3
			// criteria, so it reports ErrInvalidToken.
			if !isResourceStrategy {
				return errorsx.WithStack(ErrInvalidToken.
					WithDebug("The credential used to authenticate the request is bound to a DPoP key but the configured DPoP strategy cannot validate resource access."))
			}

			if _, err = strategy.ValidateResourceAccess(ctx, r, token, jkt, config.GetDPoPNonceRequired(ctx)); err != nil {
				return err
			}
		case config.GetDPoPEnforce(ctx):
			return errorsx.WithStack(ErrInvalidToken.
				WithHint("The credential used to authenticate the request is not bound to a DPoP key.").
				WithDebug("DPoP is enforced, so every credential presented to authenticate a request must be bound to a DPoP key, but this credential records no binding."))
		}
	}

	if config.GetMTLSEnabled(ctx) {
		var x5t string

		if bound, ok := session.(MTLSBoundSession); ok {
			x5t = bound.GetClientCertificateSHA256Thumbprint()
		}

		switch {
		case x5t != "":
			if _, err = ValidateClientCertificateBinding(r, config.GetMTLSClientCertificateHeader(ctx), x5t); err != nil {
				return err
			}
		case config.GetMTLSEnforce(ctx):
			return errorsx.WithStack(ErrInvalidToken.
				WithHint("The credential used to authenticate the request is not bound to a client certificate.").
				WithDebug("Mutual-TLS client certificate bound access tokens are enforced, so every credential presented to authenticate a request must be bound to a client certificate, but this credential records no binding."))
		}
	}

	return nil
}

// validateBearerScope enforces that the credential carries at least one of the required scopes.
//
// The comparison is exact containment and never resolves a ScopeStrategy, not even the server's own. A strategy is a
// policy about what a client may ask for; this is an endpoint authorization decision about what a credential already
// carries. The default WildcardScopeStrategy would let a token granted '*' satisfy every required scope, including
// the client registration scope that ExcludeRegistrationScope and CheckGrantableScopes exist to withhold.
//
// The required scopes are recorded on the returned error's ScopeField so a challenge can name them in its RFC 6750
// Section 3.1 'scope' parameter.
func validateBearerScope(requester Requester, scopes []string) (err error) {
	if len(scopes) == 0 {
		return nil
	}

	if requester.GetGrantedScopes().HasOneOf(scopes...) {
		return nil
	}

	rfc := ErrInsufficientScope.
		WithHintf("The credential used to authenticate the request is not granted any of the scopes '%s', at least one of which is required.", strings.Join(scopes, "', '"))

	rfc.ScopeField = strings.Join(scopes, " ")

	return errorsx.WithStack(rfc)
}

// validateBearerAudience enforces that the credential carries at least one permitted audience, resolved through the
// fallback chain documented on BearerAuthorization.
//
// The granted audience and the granted RFC 8707 resource indicators are both considered. A credential with no
// audience at all is therefore rejected, because the fallback chain always yields a non-empty permitted set.
//
// Like validateBearerScope this is exact containment, and for the same reason: a deployment-configured
// AudienceStrategy loose enough to match by prefix or wildcard would admit a credential never issued for this
// endpoint.
//
// The failure reports ErrInvalidToken, which keeps it indistinguishable from an expired, revoked or unknown
// credential. The distinguishing detail goes in the debug field, surfaced only when the deployment opts in.
func validateBearerAudience(r *http.Request, requester Requester, auth BearerAuthorization) (err error) {
	permitted := auth.Audiences

	switch {
	case len(permitted) != 0:
		break
	case auth.Endpoint != "":
		permitted = []string{auth.Endpoint}
	default:
		permitted = []string{RequestURL(r)}
	}

	granted := JoinGrantedAudienceAndResource(requester.GetGrantedAudience(), requester.GetGrantedResource())

	if granted.HasOneOf(permitted...) {
		return nil
	}

	outer := ErrInvalidToken.WithHint("The credential used to authenticate the request does not have an audience which is permitted at this endpoint.")

	if len(granted) == 0 {
		return errorsx.WithStack(outer.WithDebugf("The credential was expected to have an audience matching one of the values '%s' but it does not have an audience.", strings.Join(permitted, "', '")))
	}

	return errorsx.WithStack(outer.WithDebugf("The credential was expected to have an audience matching one of the values '%s' but the audience had the values '%s'.", strings.Join(permitted, "', '"), strings.Join(granted, "', '")))
}
