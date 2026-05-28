// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package ciba

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/hashicorp/go-retryablehttp"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

// notificationBodyReadLimit caps how much of an error response body the handler will read for diagnostics so a
// misbehaving client notification endpoint cannot exhaust memory on the authorization server.
const notificationBodyReadLimit = 4 << 10

// ClientNotificationHandler dispatches the OpenID Connect CIBA backchannel client notification HTTP POST per Sections
// 10.2 (ping) and 10.3 (push) of the specification. The handler is intended to be invoked by the implementer after the
// end user has completed the backchannel authentication request; it inspects the registered client's delivery mode and
// posts the corresponding JSON payload to the client's 'backchannel_client_notification_endpoint' authenticated with
// the 'client_notification_token' submitted in the original CIBA request.
//
// The handler is a no-op when the client's delivery mode is 'poll', so the same call site can be used regardless of
// the negotiated delivery mode.
//
// See https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#successful_token_delivery
// and https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#token_error_response.
type ClientNotificationHandler struct {
	Config interface {
		oauth2.HTTPClientProvider
	}
}

// Notify dispatches the success notification to the client's backchannel_client_notification_endpoint.
//
// For 'ping' delivery the payload is the minimal {"auth_req_id": "<id>"} body and the AccessResponder argument is
// ignored. For 'push' delivery the payload additionally includes the access token, token type, expires_in, and any
// refresh_token, id_token and scope values exposed by the AccessResponder; a non-nil response is therefore required
// for push delivery. For 'poll' delivery (or a client that does not implement BackchannelAuthenticationClient) the
// call is a no-op and nil is returned.
//
// authReqID is the opaque auth_req_id value originally returned to the client at the backchannel authentication
// endpoint; it cannot be reconstructed from the storage signature and so must be supplied by the caller.
func (h *ClientNotificationHandler) Notify(ctx context.Context, request oauth2.CIBARequester, authReqID string, response oauth2.AccessResponder) (err error) {
	client, mode, ok := h.clientDelivery(request)
	if !ok {
		return nil
	}

	payload := map[string]any{
		consts.CIBANotificationAuthRequestID: authReqID,
	}

	switch mode {
	case consts.CIBATokenDeliveryModePing:
		// Section 10.2: only auth_req_id is sent; the client polls the token endpoint to retrieve the tokens.
	case consts.CIBATokenDeliveryModePush:
		if response == nil {
			return errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to send the OpenID Connect CIBA push notification because the access response is nil."))
		}

		populatePushSuccessPayload(payload, response)
	default:
		return errorsx.WithStack(oauth2.ErrServerError.WithDebugf("Failed to send the OpenID Connect CIBA notification because the client backchannel token delivery mode '%s' is not supported.", mode))
	}

	return h.send(ctx, request, client, payload)
}

// NotifyError dispatches a push-mode error notification per Section 12 of the specification. For 'poll' and 'ping'
// delivery modes the client retrieves the error from the token endpoint when it polls, so this call is a no-op and
// nil is returned. authReqID is included in the payload when non-empty.
func (h *ClientNotificationHandler) NotifyError(ctx context.Context, request oauth2.CIBARequester, authReqID string, err error) error {
	client, mode, ok := h.clientDelivery(request)
	if !ok || mode != consts.CIBATokenDeliveryModePush {
		return nil
	}

	rfc := oauth2.ErrorToRFC6749Error(err)

	payload := map[string]any{
		consts.CIBANotificationError: rfc.ErrorField,
	}

	if description := rfc.GetDescription(); description != "" {
		payload[consts.CIBANotificationErrorDescription] = description
	}

	if authReqID != "" {
		payload[consts.CIBANotificationAuthRequestID] = authReqID
	}

	return h.send(ctx, request, client, payload)
}

// clientDelivery returns the typed client and its delivery mode, or ok=false when the client is not registered for a
// backchannel notification (i.e. uses poll, or has no BackchannelAuthenticationClient capability).
func (h *ClientNotificationHandler) clientDelivery(request oauth2.CIBARequester) (client BackchannelAuthenticationClient, mode string, ok bool) {
	client, ok = request.GetClient().(BackchannelAuthenticationClient)
	if !ok {
		return nil, "", false
	}

	mode = client.GetBackchannelTokenDeliveryMode()
	if mode == "" || mode == consts.CIBATokenDeliveryModePoll {
		return client, mode, false
	}

	return client, mode, true
}

func (h *ClientNotificationHandler) send(ctx context.Context, request oauth2.CIBARequester, client BackchannelAuthenticationClient, payload map[string]any) (err error) {
	endpoint := client.GetBackchannelClientNotificationEndpoint()
	if endpoint == "" {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to send the OpenID Connect CIBA notification because the client has no 'backchannel_client_notification_endpoint' registered."))
	}

	token := request.GetRequestForm().Get(consts.FormParameterClientNotificationToken)
	if token == "" {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to send the OpenID Connect CIBA notification because the 'client_notification_token' parameter was not present on the original backchannel authentication request."))
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	req, err := retryablehttp.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	req.Header.Set(consts.HeaderContentType, consts.ContentTypeApplicationJSON)
	req.Header.Set(consts.HeaderAuthorization, "Bearer "+token)

	resp, err := h.Config.GetHTTPClient(ctx).Do(req)
	if err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, notificationBodyReadLimit))

		return errorsx.WithStack(oauth2.ErrServerError.WithDebug(fmt.Sprintf("The OpenID Connect CIBA client notification endpoint responded with status %d: %s", resp.StatusCode, string(snippet))))
	}

	return nil
}

// populatePushSuccessPayload adds the access/refresh/id token fields produced by the token endpoint flow to the push
// notification payload. Optional fields are only included when the responder exposes a non-empty value, matching the
// JSON shape produced by oauth2.AccessResponse.ToMap.
func populatePushSuccessPayload(payload map[string]any, response oauth2.AccessResponder) {
	payload[consts.CIBANotificationAccessToken] = response.GetAccessToken()
	payload[consts.CIBANotificationTokenType] = response.GetTokenType()

	if v := response.GetExtra(consts.AccessResponseExpiresIn); v != nil {
		payload[consts.CIBANotificationExpiresIn] = v
	}

	if v := response.GetExtra(consts.AccessResponseRefreshToken); v != nil {
		if s, ok := v.(string); !ok || s != "" {
			payload[consts.CIBANotificationRefreshToken] = v
		}
	}

	if v := response.GetExtra(consts.AccessResponseIDToken); v != nil {
		if s, ok := v.(string); !ok || s != "" {
			payload[consts.CIBANotificationIDToken] = v
		}
	}

	if v := response.GetExtra(consts.AccessResponseScope); v != nil {
		if s, ok := v.(string); !ok || s != "" {
			payload[consts.CIBANotificationScope] = v
		}
	}
}
