// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"net/http"
	"strings"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

// BearerAuthorizationConfig is the configuration ValidateBearerAuthorization depends on. It deliberately names no
// ScopeStrategyProvider or AudienceStrategyProvider: scope and audience are checked by exact containment, see
// validateBearerScope.
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

	// Endpoint is the configured absolute endpoint URL, used as the permitted audience when Audiences is empty. It is
	// preferred over RequestURL, which is reconstructed from the client-controlled Host header and X-Forwarded-Proto.
	Endpoint string

	// Scopes are the required scopes. The credential must carry at least one. Empty means no scope check.
	Scopes []string
}

// ValidateBearerAuthorization performs the checks common to every endpoint that accepts an Access Token as a bearer
// credential authorizing the call. requester is the resolved credential; token is the raw value as presented.
//
// The order is proof-of-possession, then scope, then audience, and must not change. ErrInvalidDPoPProof and
// ErrInsufficientScope are distinguishable from the generic ErrInvalidToken and each implies every earlier check
// passed, so the order bounds what an error discloses: the scope diagnostic only reaches a caller who has proven
// possession, and discloses nothing about the audience.
//
// See: https://www.rfc-editor.org/rfc/rfc6750#section-3.1
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
// and - where the deployment enforces a binding method - that it carries one at all.
//
// The two methods are independent, and for each:
//
//   - A bound credential always has the binding verified.
//   - An unbound credential is rejected with ErrInvalidToken, not ErrInvalidDPoPProof, when the method is enforced
//     or the credential was presented using the DPoP authentication scheme, and is otherwise admitted.
//   - A method disabled in configuration contributes neither check, whatever its enforcement setting.
//
// Errors from the underlying strategies are returned unwrapped, as the response writers depend on their codes.
//
// See: https://www.rfc-editor.org/rfc/rfc9449 and https://www.rfc-editor.org/rfc/rfc8705
func validateBearerProofOfPossession(ctx context.Context, config BearerAuthorizationConfig, r *http.Request, requester Requester, token string) (err error) {
	// A nil session, and one whose type cannot record a binding, both leave the thumbprint empty below rather than
	// returning early, which would bypass enforcement.
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
			// accepted as if it carried none. This is a server capability gap rather than a failure of the
			// Section 4.3 criteria, so it reports ErrInvalidToken and not ErrInvalidDPoPProof.
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
		case isDPoPAuthorizationScheme(r):
			return errorsx.WithStack(ErrInvalidToken.
				WithHint("The credential used to authenticate the request is not bound to a DPoP key.").
				WithDebug("The credential was presented using the DPoP authentication scheme, which requires it to be bound to the key of the DPoP proof, but this credential records no binding."))
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

func isDPoPAuthorizationScheme(r *http.Request) bool {
	if r == nil {
		return false
	}

	scheme, _, _ := strings.Cut(r.Header.Get(consts.HeaderAuthorization), " ")

	return strings.EqualFold(scheme, DPoPAccessToken)
}

// validateBearerScope enforces that the credential carries at least one of the required scopes.
//
// The comparison is exact containment and must never resolve a ScopeStrategy: a strategy such as
// WildcardScopeStrategy would let a token granted '*' satisfy every required scope.
//
// The required scopes are recorded on the returned error's ScopeField so a challenge can name them in its 'scope'
// parameter.
//
// See: https://www.rfc-editor.org/rfc/rfc6750#section-3.1
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
// The granted audience and the granted RFC 8707 resource indicators are both considered, by exact containment and
// never an AudienceStrategy. A credential with no audience at all is rejected.
//
// The failure reports ErrInvalidToken so it stays indistinguishable from an expired, revoked or unknown credential;
// the distinguishing detail goes in the debug field only.
//
// See: https://www.rfc-editor.org/rfc/rfc6750#section-3.1
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
