// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package ciba

// BackchannelAuthenticationClient is an oauth2.Client which is registered to use the OpenID Connect Client Initiated
// Backchannel Authentication (CIBA) flow. The interface exposes the registration metadata required to dispatch a
// notification to the client after the user has completed the backchannel authentication request.
//
// See https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#registration.
type BackchannelAuthenticationClient interface {
	// GetBackchannelTokenDeliveryMode returns the 'backchannel_token_delivery_mode' client metadata value. Valid values
	// are 'poll', 'ping', and 'push'.
	GetBackchannelTokenDeliveryMode() (mode string)

	// GetBackchannelClientNotificationEndpoint returns the 'backchannel_client_notification_endpoint' client metadata
	// value to which the authorization server delivers the ping or push notification once the end user has completed
	// the backchannel authentication request. It is required for the ping and push delivery modes.
	GetBackchannelClientNotificationEndpoint() (endpoint string)
}
