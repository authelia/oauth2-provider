// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package ciba

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

const (
	slowDownIncrement   = 5 * time.Second
	longPollingInterval = 500 * time.Millisecond
)

// TokenHandler redeems the 'auth_req_id' of an OpenID Connect CIBA authentication request at the token endpoint for
// poll and ping clients.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.1
type TokenHandler struct {
	Storage  Storage
	Strategy AuthRequestIDStrategy
	Config   interface {
		oauth2.CIBAConfigProvider
	}
}

// TokenEndpointHandler is the token endpoint handler for the 'urn:openid:params:grant-type:ciba' grant type.
type TokenEndpointHandler struct {
	hoauth2.GenericCodeTokenEndpointHandler
}

// ValidateGrantTypes returns 'unauthorized_client' unless the client uses the poll or ping token delivery mode and is
// registered for the 'urn:openid:params:grant-type:ciba' grant type. Tokens issued internally for an approved push
// request are exempt, as a push client is not registered for the grant type.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.4
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.1
func (c *TokenHandler) ValidateGrantTypes(ctx context.Context, request oauth2.AccessRequester) (err error) {
	if oauth2.IsInternalIssuance(ctx) {
		return nil
	}

	switch oauth2.GetCIBADeliveryMode(request.GetClient()) {
	case consts.CIBAModePoll, consts.CIBAModePing:
	default:
		return errorsx.WithStack(oauth2.ErrUnauthorizedClient.WithHint("The OAuth 2.0 Client is not registered for the 'poll' or 'ping' token delivery mode."))
	}

	if !request.GetClient().GetGrantTypes().Has(consts.GrantTypeOpenIDCIBA) {
		return errorsx.WithStack(oauth2.ErrUnauthorizedClient.WithHint("The OAuth 2.0 Client is not allowed to use authorization grant 'urn:openid:params:grant-type:ciba'."))
	}

	return nil
}

// ValidateCodeAndSession validates the 'auth_req_id' against the authentication request with the configured strategy.
func (c *TokenHandler) ValidateCodeAndSession(ctx context.Context, _ oauth2.AccessRequester, authorizeRequest oauth2.Requester, code string) (err error) {
	return c.Strategy.ValidateCIBAAuthRequestID(ctx, authorizeRequest, code)
}

// GetCodeAndSession loads the authentication request for the 'auth_req_id' parameter and decides the outcome of this
// poll: 'invalid_grant' for an unknown request or one issued to another client, 'unauthorized_client' for a push
// request, 'expired_token', 'access_denied', 'transaction_failed', 'slow_down' and 'authorization_pending'. An approved
// request is returned for issuance. A pending request is held open for the long polling timeout, if enabled. Tokens
// issued internally for an approved push request skip the push rejection and the polling checks.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.1
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.11
func (c *TokenHandler) GetCodeAndSession(ctx context.Context, request oauth2.AccessRequester) (code string, signature string, r oauth2.Requester, err error) {
	if code = request.GetRequestForm().Get(consts.FormParameterAuthReqID); code == "" {
		return "", "", nil, errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("The 'auth_req_id' parameter is required."))
	}

	if signature, err = c.Strategy.CIBAAuthRequestIDSignature(ctx, code); err != nil {
		return "", "", nil, errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The 'auth_req_id' is invalid.").WithWrap(err).WithDebugError(err))
	}

	var (
		session = request.GetSession()
		base    oauth2.Session
		stored  oauth2.BackChannelAuthenticationRequester
		pending bool
	)

	if session != nil {
		base = session.Clone()
	}

	stored, err = c.Storage.GetCIBASession(ctx, signature, session)

	if r, pending, err = c.evaluate(ctx, request, code, stored, err); !pending {
		return code, signature, r, err
	}

	now := request.GetRequestedAt()
	if now.IsZero() {
		now = time.Now().UTC()
	}

	interval := stored.GetPollingInterval()
	if interval <= 0 {
		interval = c.Config.GetCIBAPollingInterval(ctx)
	}

	// The interval is measured from the instant a polling request is sent, or for the first from the instant the
	// authentication request was received, and grows by 5 seconds for this and every later request after each
	// 'slow_down'.
	//
	// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.3
	// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.1
	// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.11
	last := stored.GetLastPolled()
	if last.IsZero() {
		last = stored.GetRequestedAt()
	}

	if !last.IsZero() && now.Before(last.Add(interval)) {
		return code, signature, nil, c.slowDown(ctx, signature, stored, now, interval)
	}

	// The poll is recorded before it is held open, so a poll overlapping it is answered 'slow_down'.
	stored.SetLastPolled(now)
	stored.SetPollingInterval(interval)
	stored.SetSlowDownCount(0)

	if err = c.Storage.UpdateCIBASession(ctx, signature, stored); err != nil {
		return "", "", nil, errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	if timeout := c.longPollingTimeout(ctx, now); timeout > 0 {
		var decided bool

		if r, decided, err = c.longPoll(ctx, request, code, signature, base, timeout); decided {
			return code, signature, r, err
		}
	}

	return "", "", nil, errorsx.WithStack(oauth2.ErrAuthorizationPending.WithHint("The end-user has not yet been authenticated."))
}

// evaluate decides the outcome for a stored authentication request. It returns pending as true only for a request
// which is valid for this client and still awaits the end user's decision.
func (c *TokenHandler) evaluate(ctx context.Context, request oauth2.AccessRequester, code string, stored oauth2.BackChannelAuthenticationRequester, getErr error) (r oauth2.Requester, pending bool, err error) {
	switch {
	case errors.Is(getErr, oauth2.ErrInvalidatedCIBASession):
		return stored, false, getErr
	case errors.Is(getErr, oauth2.ErrNotFound):
		return nil, false, errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The 'auth_req_id' is unknown.").WithWrap(getErr).WithDebugError(getErr))
	case getErr != nil:
		return nil, false, errorsx.WithStack(oauth2.ErrServerError.WithWrap(getErr).WithDebugError(getErr))
	}

	if stored.GetClient().GetID() != request.GetClient().GetID() {
		return nil, false, errorsx.WithStack(oauth2.ErrInvalidGrant.
			WithHint("The OAuth 2.0 Client ID from this request does not match the one from the authentication request."))
	}

	internal := oauth2.IsInternalIssuance(ctx)

	// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.11
	if !internal && (oauth2.GetCIBADeliveryMode(request.GetClient()) == consts.CIBAModePush || stored.GetDeliveryMode() == consts.CIBAModePush) {
		return nil, false, errorsx.WithStack(oauth2.ErrUnauthorizedClient.WithHint("The authentication request uses the 'push' token delivery mode and cannot be redeemed at the token endpoint."))
	}

	if verr := c.Strategy.ValidateCIBAAuthRequestID(ctx, stored, code); errors.Is(verr, oauth2.ErrDeviceExpiredToken) {
		return nil, false, verr
	}

	switch stored.GetStatus() {
	case oauth2.CIBAStatusApproved:
		return stored, false, nil
	case oauth2.CIBAStatusDenied:
		return nil, false, errorsx.WithStack(oauth2.ErrAccessDenied.WithHint("The end-user denied the authentication request."))
	case oauth2.CIBAStatusFailed:
		return nil, false, errorsx.WithStack(oauth2.ErrTransactionFailed.WithDebug(stored.GetFailureCause()))
	default:
		if internal {
			return nil, false, errorsx.WithStack(oauth2.ErrServerError.WithDebug("The backchannel authentication request issued internally has not been approved."))
		}

		return nil, true, nil
	}
}

// slowDown records a poll sent before the interval elapsed. It answers 'slow_down', or invalidates the request and
// answers 'invalid_request' once the configured slow down limit is exceeded.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.11
func (c *TokenHandler) slowDown(ctx context.Context, signature string, stored oauth2.BackChannelAuthenticationRequester, now time.Time, interval time.Duration) (err error) {
	count := stored.GetSlowDownCount() + 1

	stored.SetLastPolled(now)
	stored.SetPollingInterval(interval + slowDownIncrement)
	stored.SetSlowDownCount(count)

	if limit := c.Config.GetCIBASlowDownLimit(ctx); limit > 0 && count > limit {
		if err = c.Storage.InvalidateCIBASession(ctx, signature); err != nil && !errors.Is(err, oauth2.ErrInvalidatedCIBASession) {
			return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
		}

		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("The client exceeded the limit of [%d] 'slow_down' responses and the authentication request is no longer valid.", limit))
	}

	if err = c.Storage.UpdateCIBASession(ctx, signature, stored); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	return errorsx.WithStack(oauth2.ErrSlowDown.WithHintf("The client polled within [%d] seconds of its previous request.", int(interval.Seconds())))
}

// longPollingTimeout returns how long a pending poll is held open. The DPoP proof of the poll is validated once the
// hold ends, so a poll carrying one is held only while the proof remains acceptable, measured from both the receipt of
// the request and the proof's 'iat', and is not held when a server nonce is required but the proof carries no valid
// one.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.1
// See: https://www.rfc-editor.org/rfc/rfc9449#section-4.3
func (c *TokenHandler) longPollingTimeout(ctx context.Context, receivedAt time.Time) (timeout time.Duration) {
	if timeout = c.Config.GetCIBALongPollingTimeout(ctx); timeout <= 0 {
		return 0
	}

	config, ok := c.Config.(oauth2.DPoPConfigProvider)
	if !ok || !config.GetDPoPEnabled(ctx) {
		return timeout
	}

	r, _ := ctx.Value(oauth2.RequestContextKey).(*http.Request)
	if r == nil {
		return timeout
	}

	headers := r.Header.Values(consts.HeaderDPoP)

	switch len(headers) {
	case 0:
		return timeout
	case 1:
	default:
		return 0
	}

	claims, ok := unverifiedDPoPProofClaims(headers[0])
	if !ok {
		return 0
	}

	if config.GetDPoPNonceRequired(ctx) {
		if claims.Nonce == "" {
			return 0
		}

		if strategy := config.GetDPoPStrategy(ctx); strategy != nil && strategy.ValidateDPoPNonce(ctx, claims.Nonce) != nil {
			return 0
		}
	}

	now := time.Now()
	window := config.GetDPoPProofLifespan(ctx) + config.GetDPoPClockSkew(ctx)

	expires := receivedAt.Add(window)

	if claims.IssuedAt != nil {
		if iat := time.Unix(int64(*claims.IssuedAt), 0); iat.Add(window).Before(expires) {
			expires = iat.Add(window)
		}
	}

	// The margin leaves time for the binding handlers to validate the proof after the last read.
	if remaining := expires.Sub(now) - longPollingInterval; remaining < timeout {
		return max(remaining, 0)
	}

	return timeout
}

// dpopProofClaims are the claims of a DPoP proof that bound how long a poll carrying it is held open.
type dpopProofClaims struct {
	Nonce    string   `json:"nonce"`
	IssuedAt *float64 `json:"iat"`
}

// unverifiedDPoPProofClaims decodes the claims of a DPoP proof without verifying it. They only shorten the hold of a
// poll; the binding handlers verify the proof itself.
func unverifiedDPoPProofClaims(proof string) (claims dpopProofClaims, ok bool) {
	segments := strings.Split(proof, ".")
	if len(segments) != 3 {
		return claims, false
	}

	payload, err := base64.RawURLEncoding.DecodeString(segments[1])
	if err != nil {
		return claims, false
	}

	if err = json.Unmarshal(payload, &claims); err != nil {
		return claims, false
	}

	return claims, true
}

// longPoll reads the authentication request every 500 milliseconds until it is no longer pending, the timeout elapses
// or the context is done. It returns decided as true with the outcome once the request is no longer pending.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.1
func (c *TokenHandler) longPoll(ctx context.Context, request oauth2.AccessRequester, code, signature string, base oauth2.Session, timeout time.Duration) (r oauth2.Requester, decided bool, err error) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	ticker := time.NewTicker(longPollingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, false, nil
		case <-timer.C:
			return nil, false, nil
		case <-ticker.C:
		}

		var session oauth2.Session

		if base != nil {
			session = base.Clone()
		}

		stored, gerr := c.Storage.GetCIBASession(ctx, signature, session)

		var pending bool

		if r, pending, err = c.evaluate(ctx, request, code, stored, gerr); !pending {
			return r, true, err
		}
	}
}

// UpdateLastChecked records the time of this request as the last poll of the authentication request. Tokens issued
// internally for an approved push request are not a poll, so nothing is recorded for them.
func (c *TokenHandler) UpdateLastChecked(ctx context.Context, request oauth2.AccessRequester, authorizeRequest oauth2.Requester) (err error) {
	if oauth2.IsInternalIssuance(ctx) {
		return nil
	}

	r, ok := authorizeRequest.(oauth2.BackChannelAuthenticationRequester)
	if !ok {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to update the backchannel authentication request because it is not of the right type."))
	}

	lastPolled := request.GetRequestedAt()
	if lastPolled.IsZero() {
		lastPolled = time.Now().UTC()
	}

	r.SetLastPolled(lastPolled)

	return c.Storage.UpdateCIBASession(ctx, r.GetAuthRequestIDSignature(), r)
}

// InvalidateSession invalidates the authentication request with the given 'auth_req_id' signature, so the
// 'auth_req_id' is redeemed once.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.1.1
func (c *TokenHandler) InvalidateSession(ctx context.Context, signature string, _ oauth2.Requester) (err error) {
	return c.Storage.InvalidateCIBASession(ctx, signature)
}

// CanSkipClientAuth always returns false: the client must be authenticated.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.1
func (c *TokenHandler) CanSkipClientAuth(_ context.Context, _ oauth2.AccessRequester) (skip bool) {
	return false
}

// CanHandleTokenEndpointRequest reports whether the 'grant_type' is exactly 'urn:openid:params:grant-type:ciba'.
func (c *TokenHandler) CanHandleTokenEndpointRequest(_ context.Context, request oauth2.AccessRequester) (handle bool) {
	return request.GetGrantTypes().ExactOne(consts.GrantTypeOpenIDCIBA)
}

// DeviceCodeSignature returns the signature of the 'auth_req_id' from the configured strategy.
func (c *TokenHandler) DeviceCodeSignature(ctx context.Context, code string) (signature string, err error) {
	return c.Strategy.CIBAAuthRequestIDSignature(ctx, code)
}

// GrantTypesSupported returns the 'urn:openid:params:grant-type:ciba' grant type when the poll or ping token delivery
// mode is enabled and the backchannel authentication endpoint is advertised, which requires its URL and its handler.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.4
func (c *TokenEndpointHandler) GrantTypesSupported(ctx context.Context) (types []string) {
	handler, ok := c.CodeTokenEndpointHandler.(*TokenHandler)
	if !ok || handler.Config == nil {
		return nil
	}

	config, ok := handler.Config.(interface {
		oauth2.EndpointURLsProvider
		oauth2.BackChannelAuthenticationEndpointHandlersProvider
	})
	if !ok || config.GetEndpointURLs(ctx).BackChannelAuthentication == "" {
		return nil
	}

	if !slices.ContainsFunc(config.GetBackChannelAuthenticationEndpointHandlers(ctx), func(h oauth2.BackChannelAuthenticationEndpointHandler) bool {
		_, ok := h.(interface{ IsCIBAEndpointHandler() })

		return ok
	}) {
		return nil
	}

	modes := handler.Config.GetCIBATokenDeliveryModes(ctx)

	if slices.Contains(modes, consts.CIBAModePoll) || slices.Contains(modes, consts.CIBAModePing) {
		return []string{consts.GrantTypeOpenIDCIBA}
	}

	return nil
}

var (
	_ hoauth2.CodeTokenEndpointHandler = (*TokenHandler)(nil)
	_ oauth2.TokenEndpointHandler      = (*TokenEndpointHandler)(nil)
)
