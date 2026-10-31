// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"net/url"
	"time"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
)

const (
	// ScopeSSFRead grants read access to the SSF stream management endpoints.
	ScopeSSFRead = consts.ScopeSSFRead

	// ScopeSSFManage grants read and write access to the SSF stream management endpoints.
	ScopeSSFManage = consts.ScopeSSFManage
)

const defaultSSFMaxRequestBytes int64 = 1 << 16

// SecurityEventTokenStrategy signs the Security Event Tokens delivered to receivers.
//
// See: https://www.rfc-editor.org/rfc/rfc8417.html
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-4.1.1
type SecurityEventTokenStrategy interface {
	// GenerateSecurityEventToken returns the signed compact serialization of the claims. Its protected header must have
	// a 'typ' of 'secevent+jwt' (SSF Section 4.1.1), or Provider.GenerateSecurityEventToken refuses the token.
	GenerateSecurityEventToken(ctx context.Context, claims *jwt.SecurityEventTokenClaims) (token string, err error)
}

// SSFConfig configures the OpenID Shared Signals Framework transmitter.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html
type SSFConfig struct {
	// Issuer is the transmitter issuer, used as the 'iss' of every SET. Required to create a stream; empty gives
	// ErrServerError.
	Issuer string

	// Audience is the transmitter audience. Empty means Issuer.
	Audience string

	// TokenStrategy signs the SETs.
	TokenStrategy SecurityEventTokenStrategy

	// MaxRequestBytes bounds the size of a request body. Defaults to 64 KiB.
	MaxRequestBytes int64

	// Policy resolves the per-client stream policy. Required to create or update a stream or its status, to request
	// verification and to poll; nil gives ErrServerError.
	Policy SSFStreamPolicy

	// EndpointValidator validates a receiver endpoint URL when it is submitted, when a stream holding it is updated or
	// enabled, on a verification request, and on every push.
	EndpointValidator SSFEndpointValidator

	// PollEndpointURL returns the poll endpoint URL of a stream.
	PollEndpointURL SSFPollEndpointURLFunc

	// VerificationHandler is called to deliver a verification event.
	VerificationHandler SSFVerificationHandler

	// MinVerificationInterval is the minimum interval between verification events on a stream.
	MinVerificationInterval time.Duration
}

// WithDefaults returns a copy with an empty Audience defaulted to Issuer and an unset MaxRequestBytes defaulted to
// 64 KiB.
func (c SSFConfig) WithDefaults() (config SSFConfig) {
	config = c

	if config.Audience == "" {
		config.Audience = config.Issuer
	}

	if config.MaxRequestBytes <= 0 {
		config.MaxRequestBytes = defaultSSFMaxRequestBytes
	}

	return config
}

// getSSFConfig returns the configured SSFConfig with defaults applied, or nil.
func (f *Fosite) getSSFConfig(ctx context.Context) (config *SSFConfig) {
	if config = f.Config.GetSSFConfig(ctx); config == nil {
		return nil
	}

	applied := config.WithDefaults()

	return &applied
}

// SSFStreamPolicy resolves the stream policy of a client. The policy applies at create and update only; a status update,
// a verification request and a poll check only that it resolves, so an application narrowing a policy must re-apply it
// in its emitter.
type SSFStreamPolicy interface {
	// SSFStreamPolicy returns the policy of the client.
	SSFStreamPolicy(ctx context.Context, client Client) (policy *SSFClientPolicy, err error)
}

// SSFClientPolicy is the stream policy of a client.
type SSFClientPolicy struct {
	// Audience is the stream audience. Empty means the client ID. An empty element is a server error.
	Audience []string

	// EventsSupported are the event types the client may receive.
	EventsSupported []string

	// DeliveryMethods are the delivery method URIs the client may use. Empty permits none.
	DeliveryMethods []string
}

// SSFEndpointValidator validates receiver endpoint URLs.
//
// URL validation alone cannot block private addresses because DNS can change after validation. The application must
// also check the resolved address at connection time in the transport of the HTTP client returned by
// Config.GetHTTPClient.
type SSFEndpointValidator interface {
	// ValidateSSFEndpoint returns an error when the endpoint is not permitted for the client.
	ValidateSSFEndpoint(ctx context.Context, client Client, endpoint *url.URL) (err error)
}

// SSFPollEndpointURLFunc returns the poll endpoint URL of the stream. The result must be stable for a stream ID.
type SSFPollEndpointURLFunc func(ctx context.Context, streamID string) (endpoint string, err error)

// SSFVerificationHandler handles a verification request for a stream.
type SSFVerificationHandler interface {
	// HandleSSFVerification delivers a verification event with the given state on the stream. Verification bypasses
	// SSFStream.Accepts, so it must refuse or not transmit on a disabled stream (SSF Section 8.1.2.1).
	HandleSSFVerification(ctx context.Context, stream *SSFStream, state string) (err error)
}
