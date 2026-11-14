// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"errors"
	"maps"
	"net/url"
	"time"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/reflection"
	"authelia.com/provider/oauth2/internal/transaction"
	"authelia.com/provider/oauth2/x/errorsx"
)

// NewBackChannelPushTokenNotification builds the push notification carrying the token response for the request: the
// members of the token response and the 'auth_req_id'. The authReqID is the raw 'auth_req_id' the request was issued,
// which is the AuthRequestID of the stored request.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.3.1
func NewBackChannelPushTokenNotification(client Client, request BackChannelAuthenticationRequester, authReqID string, response AccessResponder) (notification *BackChannelNotification, err error) {
	if reflection.IsNil(response) {
		return nil, errors.New("the push token notification requires a token response")
	}

	members := maps.Clone(response.ToMap())
	if members == nil {
		members = map[string]any{}
	}

	members[consts.FormParameterAuthReqID] = authReqID

	return newBackChannelNotification(client, request, authReqID, consts.CIBAModePush, members)
}

// ExpireBackChannelAuthentication sends the 'expired_token' push error notification for an expired authentication
// request of a push client, such as from a sweep of expired requests. It records nothing, so each call on the same
// request sends the notification again; a sweep must track the requests it has notified. It returns ErrInvalidRequest
// for a request of another token delivery mode, a decided request, or an unexpired request.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.12
func (f *Fosite) ExpireBackChannelAuthentication(ctx context.Context, request BackChannelAuthenticationRequester) (result *BackChannelAuthenticationDecisionResult, err error) {
	if reflection.IsNil(request) || reflection.IsNil(request.GetSession()) {
		return nil, errorsx.WithStack(ErrServerError.WithDebug("The backchannel authentication request and its session must not be nil."))
	}

	if request.GetDeliveryMode() != consts.CIBAModePush {
		return nil, errorsx.WithStack(ErrInvalidRequest.WithHint("Only a backchannel authentication request in the 'push' token delivery mode is notified of its expiry."))
	}

	switch err = f.validateBackChannelAuthenticationDecision(ctx, request); {
	case err == nil:
		return nil, errorsx.WithStack(ErrInvalidRequest.WithHint("The backchannel authentication request has not expired."))
	case !errors.Is(err, ErrDeviceExpiredToken):
		return nil, err
	}

	result = &BackChannelAuthenticationDecisionResult{Status: request.GetStatus()}

	f.notifyBackChannelPushError(ctx, request, result, ErrDeviceExpiredToken)

	return result, nil
}

// approveBackChannelAuthenticationPush records the approval of a push request, issues its tokens and invalidates it in
// one transaction, then sends the tokens to the client. When any step fails the transaction is rolled back, and the
// request is recorded as failed and the client sent 'transaction_failed', so the request always reaches a terminal
// state; restored is the session the failed request is recorded with. A transaction joined from ctx is not finished
// here: the error is returned for its owner to roll back, and on success the token notification is built but left for
// the owner to deliver once it commits. Without storage.Transactional a recorded approval cannot be rolled back: the
// client is still sent 'transaction_failed', and the result is returned with the error. Without a notifier, the
// 'auth_req_id', the client notification token or the client notification endpoint nothing is recorded. A token
// response without an ID Token is an issuance failure.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.3.1
func (f *Fosite) approveBackChannelAuthenticationPush(ctx context.Context, request BackChannelAuthenticationRequester, restored Session) (result *BackChannelAuthenticationDecisionResult, err error) {
	// The tokens are only ever delivered by the notifier, so none are issued without one.
	if reflection.IsNil(f.Config.GetBackChannelNotifier(ctx)) {
		return nil, errorsx.WithStack(ErrServerError.WithDebug("No backchannel notifier is configured to deliver the tokens of the 'push' token delivery mode."))
	}

	if _, err = newBackChannelNotification(request.GetClient(), request, GetAuthRequestID(request), consts.CIBAModePush, nil); err != nil {
		return nil, errorsx.WithStack(ErrServerError.WithWrap(err).WithDebugf("The tokens of the 'push' token delivery mode cannot be delivered: %s.", err))
	}

	txCtx, owned, err := transaction.JoinOrBegin(ctx, f.Store)
	if err != nil {
		return nil, errorsx.WithStack(ErrServerError.WithWrap(err).WithDebugError(err))
	}

	var (
		response             AccessResponder
		recorded, committing bool
	)

	if result, err = f.runBackChannelAuthenticationDecisionHandlers(txCtx, request, CIBAStatusApproved, ""); err == nil {
		recorded = true

		if response, err = f.issueBackChannelPushAccessResponse(txCtx, request); err == nil && owned {
			committing = true

			// A failed commit ends the transaction without telling whether it persisted, so it is not rolled back.
			// Recording the failure then succeeds only if the approval did not persist; otherwise it is already decided.
			err = transaction.Commit(txCtx, f.Store)
		}
	}

	if err != nil {
		// The owner of an enclosing transaction rolls it back on the returned error.
		if !owned {
			return nil, err
		}

		// Without a transaction the recorded approval cannot be undone, but the client still receives a final answer.
		if _, transactional := f.Store.(transaction.Transactional); !transactional && recorded {
			result.Status = CIBAStatusFailed
			result.IssuanceError = err

			f.notifyBackChannelPushError(ctx, request, result, ErrTransactionFailed)

			return result, errorsx.WithStack(ErrServerError.WithWrap(err).WithDebugf("The approval of the backchannel authentication request could not be rolled back because the storage does not implement storage.Transactional: %s", backChannelIssuanceFailureCause(err)))
		}

		if !committing {
			if rollbackErr := transaction.Rollback(txCtx, f.Store); rollbackErr != nil {
				err = errors.Join(err, rollbackErr)
			}
		}

		return f.failBackChannelAuthenticationPush(ctx, request, restored, err)
	}

	notification, err := NewBackChannelPushTokenNotification(request.GetClient(), request, GetAuthRequestID(request), response)

	// The tokens of an enclosing transaction are delivered by its owner once it commits.
	if !owned {
		result.Notification, result.DeliveryError = notification, err

		return result, nil
	}

	f.deliverBackChannelNotification(ctx, result, notification, err)

	return result, nil
}

// failBackChannelAuthenticationPush records the push request as failed for the issuance error and sends the client
// 'transaction_failed'. A request another decision has decided returns that error and sends nothing.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.12
func (f *Fosite) failBackChannelAuthenticationPush(ctx context.Context, request BackChannelAuthenticationRequester, restored Session, issuanceErr error) (result *BackChannelAuthenticationDecisionResult, err error) {
	request.SetSession(restored)

	if result, err = f.runBackChannelAuthenticationDecisionHandlers(ctx, request, CIBAStatusFailed, backChannelIssuanceFailureCause(issuanceErr)); err != nil {
		return nil, err
	}

	result.IssuanceError = issuanceErr

	f.notifyBackChannelPushError(ctx, request, result, ErrTransactionFailed)

	return result, nil
}

// notifyBackChannelPushError sends the push error notification for the request.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.12
func (f *Fosite) notifyBackChannelPushError(ctx context.Context, request BackChannelAuthenticationRequester, result *BackChannelAuthenticationDecisionResult, rfcErr *RFC6749Error) {
	notification, err := NewBackChannelPushErrorNotification(request.GetClient(), request, GetAuthRequestID(request), rfcErr)

	f.deliverBackChannelNotification(ctx, result, notification, err)
}

// issueBackChannelPushAccessResponse issues the tokens of an approved push request. The push token notification must
// carry an ID Token, so a response without one is an issuance failure.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.3.1
func (f *Fosite) issueBackChannelPushAccessResponse(ctx context.Context, request BackChannelAuthenticationRequester) (response AccessResponder, err error) {
	if response, err = f.issueInternalAccessResponse(ctx, newBackChannelPushAccessRequest(request)); err != nil {
		return nil, err
	}

	if token, _ := response.GetExtra(consts.AccessResponseIDToken).(string); token == "" {
		return nil, errorsx.WithStack(ErrServerError.WithDebug("The token response of the 'push' token delivery mode has no ID Token."))
	}

	return response, nil
}

// newBackChannelPushAccessRequest builds the token request of an approved push request from the stored request. It
// names no audience, resource or authorization details, so the grant handler applies those granted, as for a token
// request naming none.
func newBackChannelPushAccessRequest(request BackChannelAuthenticationRequester) (requester *AccessRequest) {
	requester = NewAccessRequest(request.GetSession().Clone())
	requester.Client = request.GetClient()
	requester.GrantTypes = Arguments{consts.GrantTypeOpenIDCIBA}
	requester.RequestedAt = time.Now().UTC()
	requester.Form = url.Values{
		consts.FormParameterGrantType: {consts.GrantTypeOpenIDCIBA},
		consts.FormParameterAuthReqID: {GetAuthRequestID(request)},
	}

	requester.SetRequestedScopes(request.GetRequestedScopes())

	return requester
}

// backChannelIssuanceFailureCause returns the failure cause recorded for an issuance error.
func backChannelIssuanceFailureCause(err error) (cause string) {
	var rfcErr *RFC6749Error

	if errors.As(err, &rfcErr) && rfcErr.Debug() != "" {
		return rfcErr.Error() + ": " + rfcErr.Debug()
	}

	return err.Error()
}
