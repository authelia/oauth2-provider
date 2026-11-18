// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/pkg/errors"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/openid/asc"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/slicesx"
	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

// ASCSourceClaimsSession is an optional interface of a Session which provides claims a Transformed Claim may be based
// on without being released themselves. The sources must hold only claims the End-User consented to release in their
// transformed form.
//
// See: https://openid.net/specs/openid-connect-advanced-syntax-for-claims-1_0.html#section-8.7
type ASCSourceClaimsSession interface {
	// GetASCSourceClaims returns the source claims of the delivery type, which is 'id_token' or 'userinfo'.
	GetASCSourceClaims(delivery string) (sources map[string]any)
}

// ASCUserInfoClaimsSession is an optional interface of a Session which provides the claims that would be released at
// the UserInfo endpoint, so the Selective Abort/Omit rules of the 'userinfo' delivery can abort the transaction at the
// authorization endpoint.
//
// See: https://openid.net/specs/openid-connect-advanced-syntax-for-claims-1_0.html#section-7.2
type ASCUserInfoClaimsSession interface {
	// GetASCUserInfoClaims returns the UserInfo claims, or nil when they are not known.
	GetASCUserInfoClaims() (claims map[string]any)
}

// EvaluateUserInfoClaims returns the claims of a UserInfo response with the Transformed Claims added and the Selective
// Abort/Omit rules of the 'userinfo' delivery applied. The requester is the one returned by IntrospectToken for the
// Access Token. The claims are returned unchanged unless the config enables the Advanced Syntax for Claims and the
// requester carries a claims request. Numbers in an evaluated result are [json.Number] values. An *asc.AbortError is
// returned when a rule aborts the transaction.
//
// The claims and sources must hold only what the End-User consented to release.
//
// See: https://openid.net/specs/openid-connect-advanced-syntax-for-claims-1_0.html#section-7.2
func EvaluateUserInfoClaims(ctx context.Context, config any, requester oauth2.Requester, claims, sources map[string]any) (result map[string]any, err error) {
	carrier, ok := requester.(oauth2.ClaimsRequester)
	if !ok {
		return claims, nil
	}

	asc, requested, enabled := claimsASC(ctx, config, carrier.GetClaims())
	if !enabled {
		return claims, nil
	}

	return asc.Evaluator.Evaluate(ctx, requested, deliveryUserInfo, claims, sources, userInfoProtectedClaims)
}

func claimsASC(ctx context.Context, config any, requested *oauth2.ClaimsRequest) (asc oauth2.ClaimsASC, masked *oauth2.ClaimsRequest, enabled bool) {
	asc = oauth2.GetClaimsASC(ctx, config)

	if requested == nil || asc.Evaluator == nil || (!asc.SelectiveAbortOmit && !asc.TransformedClaims) {
		return asc, nil, false
	}

	return asc, maskClaimsRequest(asc, requested), true
}

func maskClaimsRequest(config oauth2.ClaimsASC, requested *oauth2.ClaimsRequest) (masked *oauth2.ClaimsRequest) {
	if config.SelectiveAbortOmit && config.TransformedClaims {
		return requested
	}

	masked = requested.Clone()

	if !config.SelectiveAbortOmit && masked.ASC != nil {
		masked.ASC.SAO = nil
	}

	if !config.TransformedClaims {
		if masked.ASC != nil {
			masked.ASC.TransformedClaims = nil
		}

		stripTransformedClaimRequests(masked.IDToken)
		stripTransformedClaimRequests(masked.UserInfo)
	}

	return masked
}

func stripTransformedClaimRequests(requests map[string]*oauth2.ClaimRequest) {
	for name, request := range requests {
		if strings.HasPrefix(name, ":") {
			delete(requests, name)

			continue
		}

		if request != nil {
			stripTransformedClaimRequests(request.Members)
		}
	}
}

func evaluateClaimsASC(ctx context.Context, config oauth2.ClaimsASC, requested *oauth2.ClaimsRequest, delivery string, claims map[string]any, session any, protected []string) (result map[string]any, err error) {
	var sources map[string]any

	if provider, ok := session.(ASCSourceClaimsSession); ok {
		sources = provider.GetASCSourceClaims(delivery)
	}

	return config.Evaluator.Evaluate(ctx, requested, delivery, claims, sources, protected)
}

func claimsASCError(err error, abort *oauth2.RFC6749Error) error {
	var aborted *asc.AbortError

	if errors.As(err, &aborted) {
		return errorsx.WithStack(abort.WithHint("A Selective Abort/Omit rule of the 'claims' parameter was not fulfilled.").WithWrap(err).WithDebugError(err))
	}

	var rfc *oauth2.RFC6749Error

	if errors.As(err, &rfc) {
		return err
	}

	return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
}

var userInfoProtectedClaims = []string{consts.ClaimSubject}

var idTokenProtectedClaims = []string{
	consts.ClaimIssuer,
	consts.ClaimSubject,
	consts.ClaimAudience,
	consts.ClaimExpirationTime,
	consts.ClaimIssuedAt,
	consts.ClaimNonce,
	consts.ClaimAuthenticationTime,
	consts.ClaimAccessTokenHash,
	consts.ClaimCodeHash,
	consts.ClaimStateHash,
	consts.ClaimConfirmation,
	consts.ClaimSessionID,
}

func provisionalIDTokenClaims(ctx context.Context, config any, request oauth2.AuthorizeRequester, claims map[string]any) {
	if provider, ok := config.(oauth2.IssuerProvider); ok && claims[consts.ClaimIssuer] == nil {
		claims[consts.ClaimIssuer] = provider.GetIssuer(ctx)
	}

	now := time.Now().Unix()

	for _, name := range []string{consts.ClaimExpirationTime, consts.ClaimIssuedAt} {
		if claims[name] == nil {
			claims[name] = now
		}
	}

	audience, _ := claims[consts.ClaimAudience].([]string)

	claims[consts.ClaimAudience] = slicesx.Unique(append(slices.Clone(audience), request.GetClient().GetID()))

	if nonce := request.GetRequestForm().Get(consts.FormParameterNonce); nonce != "" {
		claims[consts.ClaimNonce] = nonce
	}

	types := request.GetResponseTypes()
	code, token, implicit := types.Has(consts.ResponseTypeAuthorizationCodeFlow), types.Has(consts.ResponseTypeImplicitFlowToken), types.Has(consts.ResponseTypeImplicitFlowIDToken)

	hashes := map[string]bool{
		consts.ClaimAccessTokenHash: token || !implicit,
		consts.ClaimCodeHash:        code && implicit,
		consts.ClaimStateHash:       code && implicit && !token && request.GetState() != "",
	}

	for name, present := range hashes {
		if present && claims[name] == nil {
			claims[name] = ""
		}
	}
}

func applyIDTokenClaimsASC(ctx context.Context, config any, request oauth2.Requester, session Session, claims jwt.MapClaims) (result jwt.MapClaims, err error) {
	carrier, ok := request.(oauth2.ClaimsRequester)
	if !ok {
		return claims, nil
	}

	asc, requested, enabled := claimsASC(ctx, config, carrier.GetClaims())
	if !enabled {
		return claims, nil
	}

	evaluated, err := evaluateClaimsASC(ctx, asc, requested, deliveryIDToken, claims, session, idTokenProtectedClaims)
	if err != nil {
		abort := oauth2.ErrInvalidGrant

		if _, ok = request.(oauth2.AuthorizeRequester); ok {
			abort = oauth2.ErrAccessDenied
		}

		return nil, claimsASCError(err, abort)
	}

	return nativeNumbersASC(evaluated).(map[string]any), nil
}

func nativeNumbersASC(value any) any {
	switch v := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))

		for key, item := range v {
			out[key] = nativeNumbersASC(item)
		}

		return out
	case []any:
		out := make([]any, len(v))

		for i, item := range v {
			out[i] = nativeNumbersASC(item)
		}

		return out
	case json.Number:
		if i, err := v.Int64(); err == nil {
			return i
		}

		if f, err := v.Float64(); err == nil {
			return f
		}

		return v
	default:
		return value
	}
}

const (
	deliveryIDToken  = asc.DeliveryIDToken
	deliveryUserInfo = asc.DeliveryUserInfo
)
