// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"errors"
	"time"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/reflection"
	"authelia.com/provider/oauth2/internal/transaction"
	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

// CIBADecisionStorage loads an OpenID Connect CIBA authentication request by its request ID for the decision API. The
// Storage of the Fosite must implement it; handler/ciba.Storage does.
type CIBADecisionStorage interface {
	// GetCIBASessionByRequestID hydrates the session based on the given request ID, as returned by the GetID method of
	// the request, and returns the authentication request. It returns ErrNotFound when no request is stored.
	GetCIBASessionByRequestID(ctx context.Context, requestID string, session Session) (request BackChannelAuthenticationRequester, err error)
}

// BackChannelAuthenticationDecisionResult is the outcome of recording the end user's decision on an OpenID Connect
// CIBA authentication request.
type BackChannelAuthenticationDecisionResult struct {
	// Status is the recorded decision.
	Status CIBAStatus

	// Notification is the ping or push notification sent to the client, if any.
	Notification *BackChannelNotification

	// DeliveryError is the error delivering the notification, if any. It never reverts the recorded decision.
	DeliveryError error

	// IssuanceError is the error issuing the tokens of a push client, if any.
	IssuanceError error
}

// NewBackChannelAuthenticationDecisionRequest loads the pending authentication request with the given request ID,
// hydrating session with its session, so the application can show the end user the 'binding_message', the scopes,
// the client and the authorization details before the end user decides it. It returns ErrNotFound for an unknown
// request, ErrInvalidRequest for a decided request, and ErrDeviceExpiredToken for an expired request. An expired request
// is returned with ErrDeviceExpiredToken, so a sweep of expired requests can pass it to ExpireBackChannelAuthentication;
// it cannot be decided.
//
// The request ID is not an authorization capability. The application must verify that the caller is the subject of
// the request, the subject of the returned session, before revealing the 'binding_message', the scopes or the client.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.8
func (f *Fosite) NewBackChannelAuthenticationDecisionRequest(ctx context.Context, requestID string, session Session) (request BackChannelAuthenticationRequester, err error) {
	if reflection.IsNil(session) {
		return nil, errorsx.WithStack(ErrServerError.WithDebug("The session must not be nil."))
	}

	storage, ok := f.Store.(CIBADecisionStorage)
	if !ok {
		return nil, errorsx.WithStack(ErrServerError.WithDebug("The storage does not implement CIBADecisionStorage."))
	}

	request, err = storage.GetCIBASessionByRequestID(ctx, requestID, session)

	switch {
	case errors.Is(err, ErrNotFound):
		return nil, errorsx.WithStack(err)
	case errors.Is(err, ErrInvalidatedCIBASession):
		return nil, errorsx.WithStack(errBackChannelAuthenticationDecided.WithWrap(err).WithDebugError(err))
	case err != nil:
		return nil, errorsx.WithStack(ErrServerError.WithWrap(err).WithDebugError(err))
	case request == nil:
		return nil, errorsx.WithStack(ErrNotFound)
	}

	if err = f.validateBackChannelAuthenticationDecision(ctx, request); err != nil {
		if errors.Is(err, ErrDeviceExpiredToken) {
			return request, err
		}

		return nil, err
	}

	return request, nil
}

// ApproveBackChannelAuthentication records the end user's approval of the authentication request and runs the
// decision handlers. The session is the application's approval session, which replaces the stored session: it must
// carry the subject set when the request was made, else ErrAccessDenied, and the 'auth_time', 'acr' and 'amr' of the
// authentication. An OpenID Connect approval session must carry an ID Token subject when the 'openid' scope is
// granted, else ErrAccessDenied. The proof-of-possession bindings and the expiry recorded when the request was made
// are carried onto it, so a session which cannot carry a recorded binding is ErrServerError. The scopes, audience,
// resources and authorization details granted on the request may narrow but never widen those requested, and the
// 'openid' scope must be granted when requested, else ErrAccessDenied. An ID Token subject set on the session must be
// the ID Token subject recorded when the request was made or, when none was recorded and the client does not use
// pairwise subject identifiers, the subject, else ErrAccessDenied. The request time of the session is set to when the
// request was made.
//
// The application must grant the scopes, audience, resources and authorization details the end user approved on
// request, with GrantScope, GrantAudience, GrantResource and SetGrantedAuthorizationDetails, before calling it.
//
// For a push request the tokens are issued and the request invalidated in the transaction which records the approval,
// and the tokens are sent to the client. When issuance fails the request is recorded as failed instead, the client is
// sent 'transaction_failed', and the error is the IssuanceError of the result; no error is returned. The exceptions:
//
//   - A push approval without a configured BackChannelNotifier is ErrServerError and records nothing.
//   - A request another decision has already decided, such as a concurrent approval which won, is ErrInvalidRequest
//     ("already decided") and sends nothing.
//   - When ctx carries an enclosing transaction begun with storage.JoinOrBeginTx, a failure is returned as the error
//     for the caller to roll back, and nothing is sent. On success the token notification, or the ping notification of
//     a ping request, is set as the Notification of the result but not delivered: the caller MUST deliver it through its BackChannelNotifier after it commits, and
//     MUST discard it if it rolls back.
//   - Without storage.Transactional the approval cannot be rolled back. When issuance fails the request stays
//     approved with no tokens delivered; access and refresh token sessions written before the failure remain
//     persisted but are never sent. The client is still sent 'transaction_failed', and the result, with the Status
//     CIBAStatusFailed, is returned with ErrServerError wrapping the issuance error.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.8
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.3.1
func (f *Fosite) ApproveBackChannelAuthentication(ctx context.Context, request BackChannelAuthenticationRequester, session Session) (result *BackChannelAuthenticationDecisionResult, err error) {
	if reflection.IsNil(session) {
		return nil, errorsx.WithStack(ErrServerError.WithDebug("The approval session must not be nil."))
	}

	if err = f.validateBackChannelAuthenticationDecision(ctx, request); err != nil {
		return nil, err
	}

	restored := request.GetSession()

	if subject := session.GetSubject(); subject != restored.GetSubject() {
		return nil, errorsx.WithStack(ErrAccessDenied.WithDebugf("The subject '%s' of the approval session is not the subject of the backchannel authentication request.", subject))
	}

	if err = validateBackChannelAuthenticationIDTokenSubject(request, restored, session); err != nil {
		return nil, err
	}

	if err = validateBackChannelAuthenticationGrant(request); err != nil {
		return nil, err
	}

	if err = validateSessionBindingCarry(restored, session); err != nil {
		return nil, err
	}

	carrySessionBinding(restored, session)

	// The 'max_age' and 'prompt' of the request are measured from when the authentication request was received.
	//
	// See: https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
	if s, ok := session.(interface{ SetRequestedAt(rat time.Time) }); ok {
		if rat := backChannelAuthenticationRequestedAt(request, restored); !rat.IsZero() {
			s.SetRequestedAt(rat)
		}
	}

	// Key binding follows the granted scopes, as it does when the device flow is approved: an approval that does not
	// grant 'bound_key' issues ID Tokens without the 'cnf' claim.
	//
	// See: https://openid.net/specs/openid-connect-key-binding-1_0.html#section-3.1
	if bound, ok := session.(DPoPBoundSession); ok && !request.GetGrantedScopes().Has(consts.ScopeBoundKey) {
		bound.SetOIDCKeyBindingGranted(false)
	}

	if exp := restored.GetExpiresAt(CIBAAuthRequestID); !exp.IsZero() {
		session.SetExpiresAt(CIBAAuthRequestID, exp)
	}

	request.SetSession(session)

	RecordAuthenticationContextRequirements(request, session)

	if request.GetDeliveryMode() == consts.CIBAModePush {
		result, err = f.approveBackChannelAuthenticationPush(ctx, request, restored)
	} else {
		result, err = f.decideBackChannelAuthentication(ctx, request, CIBAStatusApproved, "")
	}

	if err != nil {
		request.SetSession(restored)

		return result, err
	}

	return result, nil
}

// DenyBackChannelAuthentication records the end user's denial of the authentication request and runs the decision
// handlers. A ping client is sent a ping, and a push client 'access_denied'. When ctx carries an enclosing transaction
// begun with storage.JoinOrBeginTx, the notification is set as the Notification of the result but not delivered: the
// caller MUST deliver it through its BackChannelNotifier after it commits, and MUST discard it if it rolls back.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.8
func (f *Fosite) DenyBackChannelAuthentication(ctx context.Context, request BackChannelAuthenticationRequester) (result *BackChannelAuthenticationDecisionResult, err error) {
	if err = f.validateBackChannelAuthenticationDecision(ctx, request); err != nil {
		return nil, err
	}

	return f.decideBackChannelAuthentication(ctx, request, CIBAStatusDenied, "")
}

// FailBackChannelAuthentication records that the authentication request failed for the given cause, such as an
// unreachable authentication device, and runs the decision handlers. A ping client is sent a ping, and a push client
// 'transaction_failed'. A notification within an enclosing transaction is left to the caller to deliver, as for
// DenyBackChannelAuthentication.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.12
func (f *Fosite) FailBackChannelAuthentication(ctx context.Context, request BackChannelAuthenticationRequester, cause string) (result *BackChannelAuthenticationDecisionResult, err error) {
	if err = f.validateBackChannelAuthenticationDecision(ctx, request); err != nil {
		return nil, err
	}

	return f.decideBackChannelAuthentication(ctx, request, CIBAStatusFailed, cause)
}

var errBackChannelAuthenticationDecided = ErrInvalidRequest.WithHint("The backchannel authentication request is already decided.")

// validateBackChannelAuthenticationDecision requires the request to be pending and unexpired.
func (f *Fosite) validateBackChannelAuthenticationDecision(ctx context.Context, request BackChannelAuthenticationRequester) (err error) {
	if reflection.IsNil(request) || reflection.IsNil(request.GetSession()) {
		return errorsx.WithStack(ErrServerError.WithDebug("The backchannel authentication request and its session must not be nil."))
	}

	if request.GetStatus() != CIBAStatusPending {
		return errorsx.WithStack(errBackChannelAuthenticationDecided)
	}

	exp := request.GetSession().GetExpiresAt(CIBAAuthRequestID)

	if exp.IsZero() {
		exp = request.GetRequestedAt().Add(f.Config.GetCIBAAuthRequestLifespan(ctx))
	}

	if exp.Before(time.Now().UTC()) {
		return errorsx.WithStack(ErrDeviceExpiredToken.WithHintf("The backchannel authentication request expired at '%s'.", exp))
	}

	return nil
}

// decideBackChannelAuthentication records the decision on the request and runs the decision handlers in one
// transaction, then sends the notification of the decision. When a handler fails the transaction is rolled back, so
// the request stays pending and the decision can be retried. A transaction joined from ctx is left for its owner to
// finish, and so is delivering the notification set on the result. Without storage.Transactional the writes of the handlers before the failure are not rolled back.
func (f *Fosite) decideBackChannelAuthentication(ctx context.Context, request BackChannelAuthenticationRequester, status CIBAStatus, cause string) (result *BackChannelAuthenticationDecisionResult, err error) {
	txCtx, owned, err := transaction.JoinOrBegin(ctx, f.Store)
	if err != nil {
		return nil, errorsx.WithStack(ErrServerError.WithWrap(err).WithDebugError(err))
	}

	if result, err = f.runBackChannelAuthenticationDecisionHandlers(txCtx, request, status, cause); err != nil {
		if owned {
			if rollbackErr := transaction.Rollback(txCtx, f.Store); rollbackErr != nil {
				err = errors.Join(err, rollbackErr)
			}
		}

		return nil, err
	}

	if owned {
		if err = transaction.Commit(txCtx, f.Store); err != nil {
			request.SetStatus(CIBAStatusPending)
			request.SetFailureCause("")

			return nil, errorsx.WithStack(ErrServerError.WithWrap(err).WithDebugError(err))
		}
	}

	// The notification of an enclosing transaction is delivered by its owner once it commits.
	f.notifyBackChannelAuthenticationDecision(ctx, request, result, owned)

	return result, nil
}

// runBackChannelAuthenticationDecisionHandlers records the decision on the request and runs the decision handlers.
// When one fails it restores the status and failure cause of the in-memory request; anything an earlier handler wrote
// to storage is not rolled back unless ctx carries a transaction.
func (f *Fosite) runBackChannelAuthenticationDecisionHandlers(ctx context.Context, request BackChannelAuthenticationRequester, status CIBAStatus, cause string) (result *BackChannelAuthenticationDecisionResult, err error) {
	handlers := f.Config.GetBackChannelAuthenticationDecisionHandlers(ctx)

	if len(handlers) == 0 {
		return nil, errorsx.WithStack(ErrServerError.WithDebug("No backchannel authentication decision handlers are configured."))
	}

	previous, previousCause := request.GetStatus(), request.GetFailureCause()

	request.SetStatus(status)
	request.SetFailureCause(cause)

	result = &BackChannelAuthenticationDecisionResult{Status: status}

	for _, h := range handlers {
		if err = h.HandleBackChannelAuthenticationDecision(ctx, request, result); err != nil {
			request.SetStatus(previous)
			request.SetFailureCause(previousCause)

			return nil, err
		}
	}

	return result, nil
}

// notifyBackChannelAuthenticationDecision sends the ping notification of a ping client, or the push error notification
// of a denied or failed push client, once the decision is recorded. A failure to build or deliver it is recorded on
// the result and never reverts the decision. When deliver is false the notification is only built and set on the
// result.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.2
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.12
func (f *Fosite) notifyBackChannelAuthenticationDecision(ctx context.Context, request BackChannelAuthenticationRequester, result *BackChannelAuthenticationDecisionResult, deliver bool) {
	switch request.GetDeliveryMode() {
	case consts.CIBAModePing:
		notification, err := NewBackChannelPingNotification(request.GetClient(), request, GetAuthRequestID(request))

		f.deliverBackChannelNotification(ctx, result, notification, err, deliver)
	case consts.CIBAModePush:
		switch result.Status {
		case CIBAStatusDenied:
			f.notifyBackChannelPushError(ctx, request, result, ErrAccessDenied, deliver)
		case CIBAStatusFailed:
			f.notifyBackChannelPushError(ctx, request, result, ErrTransactionFailed, deliver)
		}
	}
}

// deliverBackChannelNotification records the built notification on the result and, when deliver is true, delivers it.
// A failure to build or deliver it is recorded as the DeliveryError of the result.
func (f *Fosite) deliverBackChannelNotification(ctx context.Context, result *BackChannelAuthenticationDecisionResult, notification *BackChannelNotification, err error, deliver bool) {
	if err != nil {
		result.DeliveryError = err

		return
	}

	result.Notification = notification

	if !deliver {
		return
	}

	notifier := f.Config.GetBackChannelNotifier(ctx)
	if reflection.IsNil(notifier) {
		result.DeliveryError = errors.New("no backchannel notifier is configured")

		return
	}

	result.DeliveryError = notifier.NotifyBackChannelClient(ctx, notification)
}

// validateBackChannelAuthenticationGrant requires the scopes, audience, resources and authorization details granted on
// the request to be among those requested. Granting fewer narrows the grant, as consent does.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.8
func validateBackChannelAuthenticationGrant(request BackChannelAuthenticationRequester) (err error) {
	for _, check := range []struct {
		name               string
		granted, requested Arguments
	}{
		{"scope", request.GetGrantedScopes(), request.GetRequestedScopes()},
		{"audience", request.GetGrantedAudience(), request.GetRequestedAudience()},
		{"resource", request.GetGrantedResource(), request.GetRequestedResource()},
	} {
		for _, value := range check.granted {
			if !check.requested.Has(value) {
				return errorsx.WithStack(ErrAccessDenied.WithDebugf("The %s '%s' was granted but not requested.", check.name, value))
			}
		}
	}

	if !narrowsAuthorizationDetails(request.GetGrantedAuthorizationDetails(), request.GetRequestedAuthorizationDetails()) {
		return errorsx.WithStack(ErrAccessDenied.WithDebug("The granted authorization details are not a narrowing of the requested authorization details."))
	}

	// The Client receives an ID Token in every token delivery mode, so the 'openid' scope it requested is never
	// narrowed away.
	//
	// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.3
	// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1
	if request.GetRequestedScopes().Has(consts.ScopeOpenID) && !request.GetGrantedScopes().Has(consts.ScopeOpenID) {
		return errorsx.WithStack(ErrAccessDenied.WithDebug("The 'openid' scope was requested but not granted."))
	}

	return nil
}

// validateBackChannelAuthenticationIDTokenSubject requires the ID Token subject of an OpenID Connect approval session to
// be set when the 'openid' scope is granted on a request with a subject, and, when set, to be the ID Token subject
// recorded on the session when the request was made or, when none was recorded and the client does not use pairwise
// subject identifiers, the subject of that session. A pairwise subject identifier is computed by the application, so
// without a recorded ID Token subject there is nothing to compare it with.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.8
// See: https://openid.net/specs/openid-connect-core-1_0.html#SubjectIDTypes
func validateBackChannelAuthenticationIDTokenSubject(request BackChannelAuthenticationRequester, restored, session Session) (err error) {
	client := request.GetClient()

	approval, ok := session.(interface{ IDTokenClaims() *jwt.IDTokenClaims })
	if !ok {
		return nil
	}

	if approval.IDTokenClaims() == nil || approval.IDTokenClaims().Subject == "" {
		// An ID Token is issued for a granted 'openid' scope and cannot be issued without a subject.
		if request.GetGrantedScopes().Has(consts.ScopeOpenID) && restored.GetSubject() != "" {
			return errorsx.WithStack(ErrAccessDenied.WithDebug("The approval session has no ID Token subject but the 'openid' scope was granted."))
		}

		return nil
	}

	subject, expected := approval.IDTokenClaims().Subject, ""

	if r, ok := restored.(interface{ IDTokenClaims() *jwt.IDTokenClaims }); ok && r.IDTokenClaims() != nil {
		expected = r.IDTokenClaims().Subject
	}

	if expected == "" {
		if c, ok := client.(SubjectTypeClient); ok && c.GetSubjectType() == consts.SubjectTypePairwise {
			return nil
		}

		expected = restored.GetSubject()
	}

	if subject != expected {
		return errorsx.WithStack(ErrAccessDenied.WithDebugf("The ID Token subject '%s' of the approval session is not the subject of the backchannel authentication request.", subject))
	}

	return nil
}

// backChannelAuthenticationRequestedAt returns when the authentication request was received, else the request time
// recorded on its session.
func backChannelAuthenticationRequestedAt(request BackChannelAuthenticationRequester, restored Session) (rat time.Time) {
	if rat = request.GetRequestedAt(); !rat.IsZero() {
		return rat
	}

	if s, ok := restored.(interface{ GetRequestedAt() (rat time.Time) }); ok {
		return s.GetRequestedAt()
	}

	return time.Time{}
}

// narrowsAuthorizationDetails reports whether each granted detail narrows a distinct requested detail: it has the type
// and identifier of the requested detail, carries each common data field the requested detail carries with only
// values the requested detail carries, and carries exactly the type-specific members of the requested detail.
//
// See: https://www.rfc-editor.org/rfc/rfc9396#section-2
func narrowsAuthorizationDetails(granted, requested AuthorizationDetails) bool {
	_, ok := MatchAuthorizationDetails(requested, granted, func(requested, granted AuthorizationDetail) bool {
		if !containsAuthorizationDetail(requested, granted) || len(granted.Extra) != len(requested.Extra) {
			return false
		}

		if requested.Identifier != nil && granted.Identifier == nil {
			return false
		}

		for _, field := range [][2][]string{
			{requested.Locations, granted.Locations},
			{requested.Actions, granted.Actions},
			{requested.DataTypes, granted.DataTypes},
			{requested.Privileges, granted.Privileges},
		} {
			if field[0] != nil && field[1] == nil {
				return false
			}
		}

		return true
	})

	return ok
}
