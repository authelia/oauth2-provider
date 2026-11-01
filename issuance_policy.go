// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"reflect"
	"slices"
	"strings"
	"time"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

const issuancePolicyRetryAfter = 5

// ExchangedToken identifies, in an IssuanceDecision, the output of an RFC 8693 token exchange which is not an access,
// refresh, or ID Token, such as an Identity Assertion JWT Authorization Grant.
const ExchangedToken TokenType = "exchanged_token"

// IssuancePolicy decides whether the token endpoint issues the tokens of a validated request. It is consulted after
// the grant and client are validated and before any token is minted or any grant is consumed. A permit does not
// substitute for any of those validations. It governs the token endpoint only, so tokens issued by the authorization
// endpoint through the implicit and hybrid flows are not subject to it.
type IssuancePolicy interface {
	// EvaluateIssuance returns the decision for the request. An error or a nil decision fails the request closed with
	// ErrTemporarilyUnavailable, which is not reported as a denial.
	EvaluateIssuance(ctx context.Context, request *IssuanceRequest) (decision *IssuanceDecision, err error)
}

// IssuancePolicyProvider returns the provider for configuring the issuance policy.
type IssuancePolicyProvider interface {
	// GetIssuancePolicy returns the issuance policy, or nil when issuance is not externally decided.
	GetIssuancePolicy(ctx context.Context) (policy IssuancePolicy)
}

// IssuanceGrantPreparer is implemented by a TokenEndpointHandler which assigns grants while populating the response.
// It assigns them before the IssuancePolicy is consulted, so the decision covers them, and a wrapper around such a
// handler must forward this method. Grants assigned while populating by a handler which does not implement this are not
// seen by the policy.
type IssuanceGrantPreparer interface {
	// PrepareIssuance assigns the grants of a request this handler can handle.
	PrepareIssuance(ctx context.Context, request AccessRequester) (err error)
}

// IssuanceRequest describes the issuance of a validated token request.
type IssuanceRequest struct {
	// GrantType is the 'grant_type' of the request.
	GrantType string

	// RequestedTokenType is the RFC 8693 'requested_token_type' after applying the default, if a token exchange.
	RequestedTokenType string

	// SubjectTokenType is the RFC 8693 'subject_token_type', if a token exchange.
	SubjectTokenType string

	// ActorTokenType is the RFC 8693 'actor_token_type', if any.
	ActorTokenType string

	// ClientID is the identifier of the authenticated client, if any.
	ClientID string

	// Subject is the subject of the session, which is empty when the client acts on its own behalf.
	Subject string

	// Actor is the subject of the RFC 8693 'actor_token', if any.
	Actor string

	// Act is the RFC 8693 'act' claim of the subject token, if any.
	Act any

	// MayAct is the RFC 8693 'may_act' claim of the subject token, if any.
	MayAct any

	// Tokens are the token types the request would mint.
	Tokens []TokenType

	// Scopes are the scopes the authorization server would grant.
	Scopes Arguments

	// Audience is the audience the authorization server would grant.
	Audience Arguments

	// Resources are the RFC 8707 resource indicators the authorization server would grant.
	Resources Arguments

	// AuthorizationDetails are the RFC 9396 authorization details the authorization server would grant.
	AuthorizationDetails AuthorizationDetails
}

// IssuanceDecision is the result of an IssuancePolicy. It may only narrow what the authorization server would issue.
// A decision that names anything else is treated as a denial.
type IssuanceDecision struct {
	// Denied fails the request.
	Denied bool

	// Rejection fails the request with this error when not nil, as when the request itself is at fault.
	Rejection error

	// DeniedTokens are the token types not to mint. Denying an access token, or every token of the request, fails the
	// request as a token response requires one. Any other type is omitted from the response.
	DeniedTokens []TokenType

	// Scopes replaces the granted scopes when not nil, and must be a subset of them. Removing every refresh token scope
	// also denies the refresh token, and removing 'openid' also denies the ID Token.
	Scopes Arguments

	// AuthorizationDetails replaces the granted authorization details when not nil. Each entry must equal a granted
	// entry, as narrowing within an entry is not decidable for an arbitrary type.
	AuthorizationDetails AuthorizationDetails

	// Lifespans are the ceilings of the lifespan of each token type, which must be positive.
	Lifespans map[TokenType]time.Duration
}

// DeniesToken returns true if the decision denies minting a token of the given type.
func (d *IssuanceDecision) DeniesToken(token TokenType) bool {
	return d != nil && slices.Contains(d.DeniedTokens, token)
}

// CapLifespan returns the lesser of lifespan and the ceiling for the given token type.
func (d *IssuanceDecision) CapLifespan(token TokenType, lifespan time.Duration) time.Duration {
	if d != nil {
		if ceiling, ok := d.Lifespans[token]; ok && (lifespan < 0 || ceiling < lifespan) {
			return ceiling
		}
	}

	return lifespan
}

// CapExpiry returns the earlier of expires and the ceiling for the given token type. A zero expires never expires.
func (d *IssuanceDecision) CapExpiry(token TokenType, expires time.Time) time.Time {
	if d != nil {
		if ceiling, ok := d.Lifespans[token]; ok {
			if limit := time.Now().UTC().Add(ceiling); expires.IsZero() || limit.Before(expires) {
				return limit
			}
		}
	}

	return expires
}

// IssuanceDecisionFromContext returns the decision applying to the token response being populated, or nil if there
// is none.
func IssuanceDecisionFromContext(ctx context.Context) *IssuanceDecision {
	decision, _ := ctx.Value(IssuanceDecisionContextKey).(*IssuanceDecision)

	return decision
}

// IssuanceGrantsPending returns true if an IssuanceGrantPreparer must assign its grants while populating the response,
// as no policy applies. It returns an error if a policy applied but no preparer ran, as the policy did not see the grants.
func IssuanceGrantsPending(ctx context.Context) (pending bool, err error) {
	if IssuanceDecisionFromContext(ctx) == nil {
		return true, nil
	}

	if prepared, _ := ctx.Value(IssuanceGrantsPreparedContextKey).(bool); !prepared {
		return false, errorsx.WithStack(ErrServerError.WithDebug("The issuance policy was consulted without preparing the grants of this handler, probably as a wrapper does not forward PrepareIssuance."))
	}

	return false, nil
}

func (f *Fosite) applyIssuancePolicy(ctx context.Context, request AccessRequester) (out context.Context, err error) {
	policy := f.Config.GetIssuancePolicy(ctx)
	if policy == nil {
		return ctx, nil
	}

	prepared := false

	for _, handler := range f.Config.GetTokenEndpointHandlers(ctx) {
		if preparer, ok := handler.(IssuanceGrantPreparer); ok && handler.CanHandleTokenEndpointRequest(ctx, request) {
			if err = preparer.PrepareIssuance(ctx, request); err != nil {
				return ctx, err
			}

			prepared = true
		}
	}

	var decision *IssuanceDecision

	issuance := f.newIssuanceRequest(ctx, request)

	if decision, err = policy.EvaluateIssuance(ctx, issuance); err != nil || decision == nil {
		unavailable := ErrTemporarilyUnavailable.WithRetryAfter(issuancePolicyRetryAfter)

		if err != nil {
			unavailable = unavailable.WithWrap(err)
		}

		return ctx, errorsx.WithStack(unavailable)
	}

	effective := *decision
	effective.DeniedTokens = slices.Clone(decision.DeniedTokens)

	if err = enforceIssuanceDecision(request, issuance.Tokens, f.Config.GetRefreshTokenScopes(ctx), &effective); err != nil {
		return ctx, err
	}

	ctx = context.WithValue(ctx, IssuanceGrantsPreparedContextKey, prepared)

	return context.WithValue(ctx, IssuanceDecisionContextKey, &effective), nil
}

func (f *Fosite) newIssuanceRequest(ctx context.Context, request AccessRequester) *IssuanceRequest {
	out := &IssuanceRequest{
		GrantType:            strings.Join(request.GetGrantTypes(), " "),
		Scopes:               slices.Clone(request.GetGrantedScopes()),
		Audience:             slices.Clone(request.GetGrantedAudience()),
		Resources:            slices.Clone(request.GetGrantedResource()),
		AuthorizationDetails: request.GetGrantedAuthorizationDetails().Clone(),
	}

	if client := request.GetClient(); client != nil {
		out.ClientID = client.GetID()
	}

	if session := request.GetSession(); session != nil {
		out.Subject = session.GetSubject()
	}

	if exchange, ok := request.GetSession().(interface {
		GetSubjectToken() map[string]any
		GetActorToken() map[string]any
	}); ok {
		out.Actor, _ = exchange.GetActorToken()[consts.ClaimSubject].(string)
		out.Act = exchange.GetSubjectToken()[consts.ClaimActor]
		out.MayAct = exchange.GetSubjectToken()[consts.ClaimAuthorizedActor]
	}

	if out.GrantType == consts.GrantTypeOAuthTokenExchange {
		out.SubjectTokenType = request.GetRequestForm().Get(consts.FormParameterSubjectTokenType)
		out.ActorTokenType = request.GetRequestForm().Get(consts.FormParameterActorTokenType)
		out.RequestedTokenType = request.GetRequestForm().Get(consts.FormParameterRequestedTokenType)

		if out.RequestedTokenType == "" {
			out.RequestedTokenType = f.Config.GetDefaultRFC8693RequestedTokenType(ctx)
		}
	}

	out.Tokens = f.issuanceTokens(ctx, request, out)

	return out
}

//nolint:gocyclo
func (f *Fosite) issuanceTokens(ctx context.Context, request AccessRequester, issuance *IssuanceRequest) (tokens []TokenType) {
	refreshScopes := f.Config.GetRefreshTokenScopes(ctx)
	refreshScoped := len(refreshScopes) == 0 || request.GetGrantedScopes().HasOneOf(refreshScopes...)
	openid := request.GetGrantedScopes().Has(consts.ScopeOpenID)

	switch issuance.GrantType {
	case consts.GrantTypeOAuthTokenExchange:
		switch issuance.RequestedTokenType {
		case consts.TokenTypeRFC8693AccessToken:
			client, ok := request.GetClient().(interface{ GetAllowTokenExchangeRefreshToken() bool })

			if ok && client.GetAllowTokenExchangeRefreshToken() && refreshScoped && request.GetClient().GetGrantTypes().Has(consts.GrantTypeRefreshToken) {
				return []TokenType{AccessToken, RefreshToken}
			}

			return []TokenType{AccessToken}
		case consts.TokenTypeRFC8693RefreshToken:
			return []TokenType{RefreshToken}
		case consts.TokenTypeRFC8693IDToken:
			return []TokenType{IDToken}
		default:
			return []TokenType{ExchangedToken}
		}
	case consts.GrantTypeAuthorizationCode, consts.GrantTypeOAuthDeviceCode:
		tokens = []TokenType{AccessToken}

		if refreshScoped && request.GetClient().GetGrantTypes().Has(consts.GrantTypeRefreshToken) {
			tokens = append(tokens, RefreshToken)
		}

		if openid {
			tokens = append(tokens, IDToken)
		}

		return tokens
	case consts.GrantTypeRefreshToken:
		tokens = []TokenType{AccessToken}

		if !IsRefreshTokenRotationDisabledForRequest(ctx, f.Config, request) {
			tokens = append(tokens, RefreshToken)
		}

		if openid {
			tokens = append(tokens, IDToken)
		}

		return tokens
	case consts.GrantTypeResourceOwnerPasswordCredentials:
		if refreshScoped {
			return []TokenType{AccessToken, RefreshToken}
		}

		return []TokenType{AccessToken}
	default:
		return []TokenType{AccessToken}
	}
}

//nolint:gocyclo
func enforceIssuanceDecision(request AccessRequester, tokens []TokenType, refreshScopes Arguments, decision *IssuanceDecision) (err error) {
	denied := func() error {
		if request.GetGrantTypes().ExactOne(consts.GrantTypeOAuthTokenExchange) {
			return errorsx.WithStack(ErrInvalidTarget)
		}

		return errorsx.WithStack(ErrAccessDenied)
	}

	if decision.Rejection != nil {
		return errorsx.WithStack(decision.Rejection)
	}

	if decision.Denied || decision.DeniesToken(AccessToken) {
		return denied()
	}

	for _, lifespan := range decision.Lifespans {
		if lifespan <= 0 {
			return denied()
		}
	}

	scopes := request.GetGrantedScopes()

	for _, scope := range decision.Scopes {
		if !scopes.Has(scope) {
			return denied()
		}
	}

	if decision.Scopes != nil {
		if len(refreshScopes) != 0 && scopes.HasOneOf(refreshScopes...) && !decision.Scopes.HasOneOf(refreshScopes...) {
			decision.DeniedTokens = append(decision.DeniedTokens, RefreshToken)
		}

		if scopes.Has(consts.ScopeOpenID) && !decision.Scopes.Has(consts.ScopeOpenID) {
			decision.DeniedTokens = append(decision.DeniedTokens, IDToken)
		}
	}

	if len(tokens) != 0 && !slices.ContainsFunc(tokens, func(token TokenType) bool { return !decision.DeniesToken(token) }) {
		return denied()
	}

	for _, entry := range decision.AuthorizationDetails {
		if !slices.ContainsFunc(request.GetGrantedAuthorizationDetails(), func(granted AuthorizationDetail) bool {
			return reflect.DeepEqual(granted, entry)
		}) {
			return denied()
		}
	}

	narrowed, narrowable := request.(interface{ SetGrantedScopes(scopes Arguments) })

	if decision.Scopes != nil && !narrowable {
		return errorsx.WithStack(ErrServerError.WithDebug("The issuance policy narrowed the scopes of a request which does not implement SetGrantedScopes."))
	}

	survivingDetails := len(request.GetGrantedAuthorizationDetails())

	if decision.AuthorizationDetails != nil {
		survivingDetails = len(decision.AuthorizationDetails)

		if survivingDetails == 0 && len(request.GetGrantedAuthorizationDetails()) != 0 {
			return errorsx.WithStack(ErrInvalidAuthorizationDetails)
		}

		request.SetGrantedAuthorizationDetails(decision.AuthorizationDetails)
	}

	if decision.Scopes != nil {
		if len(decision.Scopes) == 0 && len(scopes) != 0 && survivingDetails == 0 {
			return errorsx.WithStack(ErrInvalidScope)
		}

		narrowed.SetGrantedScopes(slices.Clone(decision.Scopes))
	}

	session := request.GetSession()
	now := time.Now().UTC()

	for _, token := range []TokenType{AccessToken, RefreshToken} {
		lifespan, ok := decision.Lifespans[token]
		if !ok || session == nil {
			continue
		}

		ceiling := now.Add(lifespan).Truncate(time.Second)

		if current := session.GetExpiresAt(token); current.IsZero() || ceiling.Before(current) {
			session.SetExpiresAt(token, ceiling)
		}
	}

	return nil
}

var (
	_ IssuancePolicyProvider = (*Config)(nil)
)
