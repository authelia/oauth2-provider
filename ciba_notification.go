// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"

	"authelia.com/provider/oauth2/internal/consts"
)

// BackChannelNotification is a ping or push notification to the client of an OpenID Connect CIBA authentication
// request. The library builds Body so that a queued notifier stores exactly what is sent.
//
// A push Body contains live tokens. A notifier which stores it MUST store it encrypted and delete it once delivered.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10
type BackChannelNotification struct {
	// ClientID is the identifier of the client the notification is for.
	ClientID string

	// RequestID is the application handle of the authentication request, for correlation in logs and queues.
	RequestID string

	// Mode is the token delivery mode of the notification: ping or push.
	Mode string

	// Endpoint is the 'backchannel_client_notification_endpoint' of the client.
	Endpoint string

	// BearerToken is the 'client_notification_token' the client supplied, sent as the bearer credential.
	BearerToken string

	// Body is exactly the JSON body to POST.
	Body json.RawMessage
}

// BackChannelNotifier delivers ping and push notifications to the client of an OpenID Connect CIBA authentication
// request.
//
// The application MUST ensure the notification endpoint is within the administrative authority of the client. The
// library cannot verify this.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.14
type BackChannelNotifier interface {
	// NotifyBackChannelClient delivers the notification. A returned error marks the delivery as failed.
	NotifyBackChannelClient(ctx context.Context, notification *BackChannelNotification) (err error)
}

// NewBackChannelPingNotification builds the ping notification for the request. The authReqID is the raw 'auth_req_id'
// the request was issued, which is the AuthRequestID of the stored request.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.2
func NewBackChannelPingNotification(client Client, request BackChannelAuthenticationRequester, authReqID string) (notification *BackChannelNotification, err error) {
	return newBackChannelNotification(client, request, authReqID, consts.CIBAModePing, map[string]any{
		consts.FormParameterAuthReqID: authReqID,
	})
}

// NewBackChannelPushErrorNotification builds the push error notification for the request. The 'error_description' is
// restricted to the characters permitted by the specification.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.12
func NewBackChannelPushErrorNotification(client Client, request BackChannelAuthenticationRequester, authReqID string, rfcErr *RFC6749Error) (notification *BackChannelNotification, err error) {
	if rfcErr == nil {
		return nil, errors.New("the push error notification requires an error")
	}

	switch rfcErr.ErrorField {
	case errAccessDeniedName, errDeviceExpiredTokenName, errTransactionFailedName:
	default:
		return nil, fmt.Errorf("the push error notification does not permit the error '%s'", rfcErr.ErrorField)
	}

	members := map[string]any{
		consts.FormParameterAuthReqID: authReqID,
		consts.FormParameterError:     rfcErr.ErrorField,
	}

	if description := sanitizeErrorDescription(rfcErr.GetDescription()); description != "" {
		members[consts.FormParameterErrorDescription] = description
	}

	return newBackChannelNotification(client, request, authReqID, consts.CIBAModePush, members)
}

func newBackChannelNotification(client Client, request BackChannelAuthenticationRequester, authReqID, mode string, members map[string]any) (notification *BackChannelNotification, err error) {
	if authReqID == "" {
		return nil, errors.New("the notification requires the auth_req_id")
	}

	cc, ok := client.(CIBAClient)
	if !ok {
		return nil, errors.New("the client does not support CIBA")
	}

	notification = &BackChannelNotification{
		ClientID:    client.GetID(),
		RequestID:   request.GetID(),
		Mode:        mode,
		Endpoint:    cc.GetBackChannelClientNotificationEndpoint(),
		BearerToken: GetClientNotificationToken(request),
	}

	if notification.Endpoint == "" {
		return nil, errors.New("the client has no backchannel_client_notification_endpoint")
	}

	if !isCIBANotificationEndpointSecure(notification.Endpoint) {
		return nil, errors.New("the client backchannel_client_notification_endpoint is not an absolute https URL")
	}

	if notification.BearerToken == "" {
		return nil, errors.New("the request has no client_notification_token")
	}

	if notification.Body, err = json.Marshal(members); err != nil {
		return nil, err
	}

	return notification, nil
}

// isCIBANotificationEndpointSecure reports whether the endpoint is an absolute 'https' URL with a host.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.4
func isCIBANotificationEndpointSecure(endpoint string) (secure bool) {
	uri, err := url.Parse(endpoint)
	if err != nil {
		return false
	}

	return uri.IsAbs() && uri.Scheme == consts.SchemeHTTPS && uri.Host != ""
}
