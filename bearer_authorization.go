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
	// to Endpoints, and then to RequestURL.
	Audiences []string

	// Endpoints are the configured absolute URLs of the endpoint, such as its URL and its RFC 8705 mutual TLS alias,
	// used as the permitted audiences when Audiences is empty, and accepted as the 'htu' of a DPoP proof alongside
	// RequestURL. Empty values are ignored. For the audience they are preferred over RequestURL, which is reconstructed
	// from the client-controlled Host header and X-Forwarded-Proto.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc8705#section-5
	// See: https://datatracker.ietf.org/doc/html/rfc9449#section-4.3
	Endpoints []string

	// Scopes are the required scopes. The credential must carry at least one. Empty means no scope check.
	Scopes []string
}

// ValidateBearerAuthorization performs the checks common to every endpoint that accepts an Access Token as a bearer
// credential authorizing the call. requester is the resolved credential; token is the raw value as presented.
//
// The client recorded with the credential is a copy taken when it was issued, and for a stateless JWT access token
// only its identifier, so store resolves the current registration of that client, which the DPoP proof policy and the
// sender-constrained check apply as well as the recorded client. It returns the registration, or nil when the
// credential identifies no client. A registration which cannot be found is answered with ErrInvalidToken. store is
// nil only for a credential issued by another authorization server, whose client has no registration here.
//
// The order is the registration, then proof-of-possession, then scope, then audience, and must not change.
// ErrInvalidDPoPProof and ErrInsufficientScope are distinguishable from the generic ErrInvalidToken and each implies
// every earlier check passed, so the order bounds what an error discloses: the scope diagnostic only reaches a caller
// who has proven possession, and discloses nothing about the audience.
//
// An access token bound to neither a DPoP key nor a client certificate is rejected when the configuration implements
// EnforceSenderConstrainedAccessTokensProvider and enforces them, or the client it was issued to requires them, as a
// client held to the FAPI 2.0 Security Profile does.
//
// See: https://www.rfc-editor.org/rfc/rfc6750#section-3.1
// See: https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.3.4
func ValidateBearerAuthorization(ctx context.Context, config BearerAuthorizationConfig, store ClientGetter, r *http.Request, requester Requester, token string, auth BearerAuthorization) (client Client, err error) {
	if store != nil {
		if client, err = resolveBearerClient(ctx, config, store, requester); err != nil {
			return nil, err
		}
	}

	if err = validateBearerTransport(ctx, config, r, requester.GetClient(), client, token); err != nil {
		return nil, err
	}

	if err = validateBearerProofOfPossession(ctx, config, r, requester, client, token, auth.Endpoints); err != nil {
		return nil, err
	}

	if err = validateBearerScope(requester, auth.Scopes); err != nil {
		return nil, err
	}

	if err = validateBearerAudience(r, requester, auth); err != nil {
		return nil, err
	}

	return client, nil
}

func validateBearerTransport(ctx context.Context, config any, r *http.Request, recorded, client Client, token string) (err error) {
	if !IsFAPI2SecurityProfile(ctx, config) && !IsFAPI2SecurityProfileClient(recorded) && !IsFAPI2SecurityProfileClient(client) {
		return nil
	}

	if isAccessTokenURIQueryParameter(r, token) {
		return errorsx.WithStack(ErrInvalidRequest.WithHint("An access token in the URI query is not accepted under the FAPI 2.0 Security Profile."))
	}

	return nil
}

func isAccessTokenURIQueryParameter(r *http.Request, token string) bool {
	if r == nil || r.URL == nil || token == "" {
		return false
	}

	if scheme, value, err := AuthorizationCredentialFromRequest(r); err == nil && value == token && (strings.EqualFold(scheme, BearerAccessToken) || strings.EqualFold(scheme, DPoPAccessToken)) {
		return false
	}

	return r.URL.Query().Get(consts.FormParameterAccessToken) == token && r.PostForm.Get(consts.FormParameterAccessToken) != token
}

func resolveBearerClient(ctx context.Context, config any, store ClientGetter, requester Requester) (client Client, err error) {
	if client = requester.GetClient(); client == nil || client.GetID() == "" {
		return nil, nil
	}

	id := client.GetID()

	if client, err = GetClient(ctx, config, store, id); err != nil {
		if failure, ok := requestServerFailure(err); ok {
			return nil, failure
		}

		return nil, errorsx.WithStack(ErrInvalidToken.WithHint("The Access Token is missing, malformed, or invalid.").WithWrap(err).WithDebugf("The client with id '%s' the credential was issued to could not be found.", id))
	}

	return client, nil
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
// A credential bound by neither enabled method is rejected with ErrInvalidToken when
// IsSenderConstrainedAccessTokenEnforced reports that the configuration, the client recorded with the credential, or
// client requires sender-constrained access tokens. The DPoP proof is validated with the policy of client, or of the
// recorded client when client is nil.
//
// Errors from the underlying strategies are returned unwrapped, as the response writers depend on their codes.
//
// See: https://www.rfc-editor.org/rfc/rfc9449 and https://www.rfc-editor.org/rfc/rfc8705
func validateBearerProofOfPossession(ctx context.Context, config BearerAuthorizationConfig, r *http.Request, requester Requester, client Client, token string, endpoints []string) (err error) {
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

			if _, err = strategy.ValidateResourceAccess(NewDPoPProofClientContext(ctx, bearerProofClient(requester, client)), r, token, jkt, config.GetDPoPNonceRequired(ctx), endpoints...); err != nil {
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

	return validateBearerSenderConstrainedClients(ctx, config, requester.GetClient(), client, session)
}

func bearerProofClient(requester Requester, client Client) Client {
	if client == nil {
		return requester.GetClient()
	}

	return client
}

func validateBearerSenderConstrainedClients(ctx context.Context, config BearerAuthorizationConfig, recorded, client Client, session Session) (err error) {
	if err = validateBearerSenderConstrained(ctx, config, recorded, session); err != nil || client == nil {
		return err
	}

	return validateBearerSenderConstrained(ctx, config, client, session)
}

func validateBearerSenderConstrained(ctx context.Context, config BearerAuthorizationConfig, client Client, session Session) (err error) {
	enforced, _ := config.(EnforceSenderConstrainedAccessTokensProvider)

	// See: https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.3.4
	if !IsSenderConstrainedAccessTokenEnforced(ctx, enforced, client) || isSenderConstrained(ctx, config, session) {
		return nil
	}

	return errorsx.WithStack(ErrInvalidToken.
		WithHint("The credential used to authenticate the request is not sender-constrained.").
		WithDebug("Sender-constrained access tokens are enforced, so every credential presented to authenticate a request must be bound to a DPoP key or a client certificate, but this credential records no binding of an enabled method."))
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

	if len(permitted) == 0 {
		for _, endpoint := range auth.Endpoints {
			if endpoint != "" {
				permitted = append(permitted, endpoint)
			}
		}
	}

	if len(permitted) == 0 {
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
