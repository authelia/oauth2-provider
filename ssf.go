// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"net/url"
	"time"

	"github.com/hashicorp/go-retryablehttp"

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

// SecurityEventTokenStrategy signs, and optionally encrypts, the Security Event Tokens delivered to receivers.
//
// A SET that carries personally identifiable information, or that is distributed through a third party, must be
// encrypted with JWE or kept confidential by other means (RFC 8417 Section 5.1). A signed SET is not confidential: it
// relies on the TLS of each delivery, and it is readable by anything that terminates that TLS or stores the token, such
// as a queue. An application that cannot rely on that registers an encryption algorithm for the client that owns the
// stream, see SecurityEventTokenClient, or returns a JWE from its own strategy, encrypted to a key of the receiver.
//
// See: https://www.rfc-editor.org/rfc/rfc8417.html
// See: https://www.rfc-editor.org/rfc/rfc8417.html#section-5.1
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-4.1.1
type SecurityEventTokenStrategy interface {
	// GenerateSecurityEventToken returns the compact serialization of the claims as a JWS, or as a JWE that nests that
	// JWS, or Provider.GenerateSecurityEventToken refuses the token.
	//
	// The client is the owner of the stream, and Provider.GenerateSecurityEventToken never passes nil. When it is a
	// SecurityEventTokenClient with an encryption algorithm the strategy must return the JWE, encrypted to a key of the
	// client (RFC 8417 Section 5.1), or Provider.GenerateSecurityEventToken refuses the token.
	//
	// The protected header of the JWS must have a 'typ' of 'secevent+jwt' (SSF Section 4.1.1) and an 'alg' other than
	// 'none', and its signature must not be empty (RFC 8417 Section 5.1).
	//
	// The protected header of the JWE must have 'alg', 'enc' and a 'cty' of 'JWT' (RFC 7519 Section 5.2), and a 'typ',
	// when it has one, of 'JWT' or 'secevent+jwt'. The nested JWS is not inspected, so the strategy must sign it and
	// give it a 'typ' of 'secevent+jwt' (RFC 8725 Section 3.11).
	GenerateSecurityEventToken(ctx context.Context, client Client, claims *jwt.SecurityEventTokenClaims) (token string, err error)
}

// SSFConfig configures the OpenID Shared Signals Framework transmitter.
//
// The provider signs a Security Event Token, serves the stream, status, verification and poll requests, and makes a
// single push attempt. Every other part of the Transmitter is a duty of the application:
//
//   - Serve the endpoints over TLS 1.2 or later and follow RFC 9325 (CAEP Interoperability Profile Section 2.1). See
//     HTTPClient for the connections made to a Receiver.
//   - Queue the tokens of each stream: retry a push, answer a poll, and hold or drop the tokens of a stream that is
//     not enabled. See Provider.PushSecurityEventTokenToStream, Provider.NewSSFPollRequest and
//     Provider.WriteSSFPollResponse.
//   - Choose the 'jti' and 'txn' of each token. See Provider.GenerateSecurityEventToken.
//   - Deliver the verification event a Receiver requests, and tell the Receiver of a status change it did not
//     request. See SSFVerificationHandler, Provider.HandleSSFVerificationRequest and NewSSFStreamUpdatedEvent.
//   - Apply a changed stream policy to the streams it was not applied to. See Provider.ReconcileSSFStream.
//   - Send a Receiver only the events it is permitted to have (SSF Section 9.2), and obtain the consent of the user
//     before an event releases data the user has not consented to release (SSF Section 10.3.2, RFC 8417 Section 6).
//   - Identify a subject so that the Receiver cannot correlate claims it does not already know to be about that
//     subject, and with the same identifier format and values for a given Receiver every time (SSF Section 10.1). See
//     jwt.SubjectIdentifier.
//   - Keep a token that carries personally identifiable information confidential. See SecurityEventTokenStrategy.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-9.2
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-10.1
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-10.3.2
// See: https://www.rfc-editor.org/rfc/rfc8417.html#section-6
type SSFConfig struct {
	// Audience is the transmitter audience. Empty means the issuer, GetIssuer.
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

	// HTTPClient is the HTTP client used to push a Security Event Token. Nil means Config.GetHTTPClient. It is guarded
	// by GuardHTTPClient unless SpecialUseAddressGuardProvider disables the guard. See
	// NewSpecialUseAddressGuardedHTTPClient. A push is one request made with its inner HTTP client, so its retry policy
	// and hooks do not apply, and its transport, with the idle connections it holds, is shared by every push.
	//
	// A transport the application supplies must use TLS 1.2 or later, check the certificate of the Receiver against
	// the host name of its endpoint, and follow RFC 7525 and its successor RFC 9325 (RFC 8935 Section 5.3, CAEP
	// Interoperability Profile Section 2.1). The default transport of Go does all three unless it is configured not to.
	HTTPClient *retryablehttp.Client

	// PollEndpointURL returns the poll endpoint URL of a stream.
	PollEndpointURL SSFPollEndpointURLFunc

	// VerificationHandler is called to deliver a verification event.
	VerificationHandler SSFVerificationHandler

	// EnforceCAEPInteroperabilityProfile enforces the requirements of the CAEP Interoperability Profile that the
	// provider is able to check. It is disabled by default. When enabled:
	//
	//   - Provider.GenerateSecurityEventToken gives ErrServerError for a token that is not a JWS signed with RS256 by an
	//     RSA key of at least 2048 bits, measured by the length of the signature. A JWE is refused, as the signature of
	//     the token it nests cannot be inspected (Profile Section 2.6). Encryption and the profile are mutually
	//     exclusive, so a stream whose client is configured for an encrypted token, as a SecurityEventTokenClient with
	//     an encryption algorithm, gives ErrServerError.
	//   - Provider.ValidateSSFConfiguration, and so Provider.WriteSSFConfiguration, gives ErrServerError for Transmitter
	//     Configuration Metadata without a 'spec_version' of '1_0' or greater, 'delivery_methods_supported',
	//     'configuration_endpoint', 'status_endpoint', 'verification_endpoint', or the SSFAuthorizationSchemeOAuth2 entry
	//     of 'authorization_schemes' (Profile Section 2.3.1 to 2.3.7).
	//
	// The rest of the profile is not checked, whatever the value, and is a duty of the application:
	//
	//   - TLS 1.2 or later, following RFC 9325, at the endpoints it serves and on the connections it makes (Profile
	//     Section 2.1).
	//   - Access tokens for a Receiver that live for 60 minutes or less (Profile Section 2.7.1).
	//   - A 'reason_admin' with at least one entry in each session-revoked, credential-change and
	//     device-compliance-change event (Profile Section 3.1 to 3.3).
	//   - A 'jwks_uri' that serves the current signing keys (Profile Section 2.3.3).
	//
	// See: https://openid.net/specs/openid-caep-interoperability-profile-1_0.html#section-2.1
	// See: https://openid.net/specs/openid-caep-interoperability-profile-1_0.html#section-2.3
	// See: https://openid.net/specs/openid-caep-interoperability-profile-1_0.html#section-2.6
	// See: https://openid.net/specs/openid-caep-interoperability-profile-1_0.html#section-2.7.1
	// See: https://openid.net/specs/openid-caep-interoperability-profile-1_0.html#section-3
	EnforceCAEPInteroperabilityProfile bool

	// MinVerificationInterval is the minimum interval between verification events on a stream. It applies to existing
	// streams as well as new ones, and is reported as 'min_verification_interval' in whole seconds, rounded up. Zero or
	// less disables the limit.
	MinVerificationInterval time.Duration
}

// WithDefaults returns a copy with an unset MaxRequestBytes defaulted to 64 KiB.
func (c SSFConfig) WithDefaults() (config SSFConfig) {
	config = c

	if config.MaxRequestBytes <= 0 {
		config.MaxRequestBytes = defaultSSFMaxRequestBytes
	}

	return config
}

func (c *SSFConfig) minVerificationIntervalSeconds() (seconds int) {
	if c.MinVerificationInterval <= 0 {
		return 0
	}

	return int((c.MinVerificationInterval + time.Second - 1) / time.Second)
}

func (c *SSFConfig) isVerificationThrottled(stream *SSFStream, now time.Time) (throttled bool) {
	return c.MinVerificationInterval > 0 && !stream.LastVerificationAt.IsZero() && now.Sub(stream.LastVerificationAt) < c.MinVerificationInterval
}

func isValidSSFIssuer(issuer string) (valid bool) {
	_, err := SSFConfigurationURL(issuer)

	return err == nil
}

func (f *Fosite) currentSSFStream(ctx context.Context, config *SSFConfig, stream *SSFStream) (current *SSFStream) {
	current = stream.Clone()
	current.MinVerificationInterval = config.minVerificationIntervalSeconds()

	if issuer := f.Config.GetIssuer(ctx); !isValidSSFIssuer(current.Issuer) && isValidSSFIssuer(issuer) {
		current.Issuer = issuer
	}

	return current
}

func (f *Fosite) ssfAudience(ctx context.Context, config *SSFConfig) (audience string) {
	if config.Audience != "" {
		return config.Audience
	}

	return f.Config.GetIssuer(ctx)
}

// getSSFConfig returns the configured SSFConfig with defaults applied, or nil.
func (f *Fosite) getSSFConfig(ctx context.Context) (config *SSFConfig) {
	if config = f.Config.GetSSFConfig(ctx); config == nil {
		return nil
	}

	applied := config.WithDefaults()

	return &applied
}

// SSFStreamPolicy resolves the stream policy of a client. The events of the policy apply at create, at an update that
// replaces the stream or changes 'events_requested', and at Provider.ReconcileSSFStream; the audience applies at create
// only. Any other update, a status update, a verification request and a poll check only that it resolves, so an
// application narrowing a policy must call Provider.ReconcileSSFStream for the streams of the client.
type SSFStreamPolicy interface {
	// SSFStreamPolicy returns the policy of the client. An error denies the request with 403, except that:
	//
	//   - An error matching ErrTemporarilyUnavailable gives 503, for a policy that could not be resolved for a reason
	//     that is expected to pass, such as a storage failure.
	//   - An error matching ErrSSFStreamUpdatePending gives 202 with the stored status on a stream status update, which
	//     is not applied (SSF Section 8.1.2.2). Every other request has no such response and is denied.
	SSFStreamPolicy(ctx context.Context, client Client) (policy *SSFClientPolicy, err error)
}

// SSFClientPolicy is the stream policy of a client.
type SSFClientPolicy struct {
	// Audience is the stream audience. Empty means the client ID. An empty element is a server error.
	//
	// More than one value is for Receivers the application knows to be the same entity, which must all use the same
	// delivery method (SSF Section 4.1.8). Receivers that may be different entities each get their own stream and so
	// their own Security Event Tokens, or a token names a Receiver it should not be disclosed to.
	Audience []string

	// EventsSupported are the event types the client may receive.
	EventsSupported []string

	// DeliveryMethods are the delivery method URIs the client may use. Empty permits none.
	DeliveryMethods []string
}

// SSFEndpointValidator validates receiver endpoint URLs.
//
// URL validation alone cannot block private addresses because DNS can change after validation. The application must
// also check the resolved address at connection time in the transport of SSFConfig.HTTPClient, or of the HTTP client
// returned by Config.GetHTTPClient when it is nil, which the special-use address guard does unless it is disabled.
type SSFEndpointValidator interface {
	// ValidateSSFEndpoint returns an error when the endpoint is not permitted for the client. An error matching
	// ErrTemporarilyUnavailable makes a push SSFPushRetryable rather than SSFPushRejected.
	ValidateSSFEndpoint(ctx context.Context, client Client, endpoint *url.URL) (err error)
}

// SSFPollEndpointURLFunc returns the poll endpoint URL of the stream. The result must be stable for a stream ID, and
// an absolute https URL with no userinfo or fragment, or the stream request gives ErrServerError (RFC 8936 Section 4.3).
type SSFPollEndpointURLFunc func(ctx context.Context, streamID string) (endpoint string, err error)

// SSFVerificationHandler handles a verification request for a stream.
type SSFVerificationHandler interface {
	// HandleSSFVerification delivers a verification event with the given state on the stream. Verification bypasses
	// SSFStream.Accepts. It is not called for a disabled stream. It is called for a paused stream, where it must hold
	// the event until the stream is enabled rather than transmit it (SSF Section 8.1.2.1), which
	// Provider.PushSecurityEventTokenToStream reports with ErrSSFStreamPaused.
	//
	// The state is nil when the request had none. Any other value, the empty string included, must be echoed as the
	// 'state' of the event (SSF Section 8.1.4.2), which jwt.SSFVerification does when given the pointer. A verification
	// event the application sends without a request has no 'state'.
	//
	// The event may be transmitted after this method returns, and the application should publish how long that can
	// take (SSF Section 8.1.4.2).
	HandleSSFVerification(ctx context.Context, stream *SSFStream, state *string) (err error)
}
