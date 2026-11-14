// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"time"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
)

// CIBAStatus is the end user's progress through an OpenID Connect CIBA authentication request. The values are
// persisted by storage implementations, so new values are appended rather than inserted.
type CIBAStatus int

const (
	// CIBAStatusPending marks a request the end user has not yet decided. The client keeps receiving
	// 'authorization_pending'.
	CIBAStatusPending CIBAStatus = iota

	// CIBAStatusApproved marks a request the end user has approved.
	CIBAStatusApproved

	// CIBAStatusDenied marks a request the end user has denied. The client receives 'access_denied'.
	CIBAStatusDenied

	// CIBAStatusFailed marks a request which failed after it was accepted, such as a failed ping or push notification.
	CIBAStatusFailed

	// CIBAStatusExpired marks a push request which expired before the end user decided it, recorded by
	// ExpireBackChannelAuthentication. The client receives 'expired_token'.
	CIBAStatusExpired
)

// CIBAHintKind identifies which hint parameter of the authentication request identifies the end user.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#auth_request
type CIBAHintKind string

const (
	// CIBAHintKindLoginHint is the 'login_hint' parameter. Under the FAPI-CIBA profile it should not convey an intent
	// id or any other authorization metadata.
	//
	// See: https://openid.net/specs/fapi-ciba.html#section-4.1.1
	CIBAHintKindLoginHint CIBAHintKind = "login_hint"

	// CIBAHintKindLoginHintToken is the 'login_hint_token' parameter. It SHOULD be signed by its issuer, and its
	// signature verified before the end user it identifies is trusted. Under the FAPI-CIBA profile it should not convey
	// an intent id or any other authorization metadata.
	//
	// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.14
	// See: https://openid.net/specs/fapi-ciba.html#section-4.1.1
	CIBAHintKindLoginHintToken CIBAHintKind = "login_hint_token" //nolint:gosec // This is a parameter name, not a credential.

	// CIBAHintKindIDTokenHint is the 'id_token_hint' parameter.
	CIBAHintKindIDTokenHint CIBAHintKind = "id_token_hint"
)

// BackChannelAuthenticationRequester represents an OpenID Connect CIBA authentication request and its state.
//
// The client notification token and the issued 'auth_req_id' are carried only by the concrete
// *BackChannelAuthenticationRequest; see GetClientNotificationToken and GetAuthRequestID. A custom implementation
// receives no HTTP request at the binding stage and cannot carry these secrets, so it cannot be used for the ping or
// push token delivery modes.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html
type BackChannelAuthenticationRequester interface {
	Requester

	// GetDeliveryMode returns the token delivery mode of the client: poll, ping or push.
	GetDeliveryMode() (mode string)

	// GetHint returns the kind and the raw value of the hint which identifies the end user. A 'login_hint_token' is
	// returned unverified: its signature SHOULD be verified before it is trusted.
	//
	// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.14
	GetHint() (kind CIBAHintKind, value string)

	// GetIDTokenHintClaims returns the verified claims of the 'id_token_hint', if one was given.
	GetIDTokenHintClaims() (claims jwt.MapClaims)

	// GetBindingMessage returns the 'binding_message' parameter.
	GetBindingMessage() (message string)

	// GetUserCode returns the 'user_code' parameter, a secret known only to the end user which must be verified before
	// the authentication device is contacted. Attempts should be rate limited per end user and client.
	//
	// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#auth_request
	GetUserCode() (code string)

	// GetRequestedExpiry returns the 'requested_expiry' parameter, or 0 when absent.
	GetRequestedExpiry() (expiry time.Duration)

	// GetRequestContext returns the opaque context supplied with the request, if any.
	GetRequestContext() (context json.RawMessage)

	// GetAuthRequestIDSignature returns the signature of the 'auth_req_id'.
	GetAuthRequestIDSignature() (signature string)

	// SetAuthRequestIDSignature sets the signature of the 'auth_req_id'.
	SetAuthRequestIDSignature(signature string)

	// GetStatus returns the end user's decision status.
	GetStatus() (status CIBAStatus)

	// SetStatus sets the end user's decision status.
	SetStatus(status CIBAStatus)

	// GetLastPolled returns the time of the most recent token endpoint poll.
	GetLastPolled() (t time.Time)

	// SetLastPolled sets the time of the most recent token endpoint poll.
	SetLastPolled(t time.Time)

	// GetPollingInterval returns the minimum polling interval currently in force for the request.
	GetPollingInterval() (interval time.Duration)

	// SetPollingInterval sets the minimum polling interval currently in force for the request.
	SetPollingInterval(interval time.Duration)

	// GetSlowDownCount returns the number of 'slow_down' responses issued for the request.
	GetSlowDownCount() (count int)

	// SetSlowDownCount sets the number of 'slow_down' responses issued for the request.
	SetSlowDownCount(count int)

	// GetFailureCause returns the reason the request failed, if it did.
	GetFailureCause() (cause string)

	// SetFailureCause sets the reason the request failed.
	SetFailureCause(cause string)
}

// BackChannelAuthenticationRequest is an implementation of BackChannelAuthenticationRequester.
type BackChannelAuthenticationRequest struct {
	Request

	DeliveryMode           string
	HintKind               CIBAHintKind
	HintValue              string
	IDTokenHintClaims      jwt.MapClaims
	BindingMessage         string
	UserCode               string
	RequestedExpiry        time.Duration
	RequestContext         json.RawMessage
	AuthRequestIDSignature string
	Status                 CIBAStatus
	LastPolled             time.Time
	PollingInterval        time.Duration
	SlowDownCount          int
	FailureCause           string

	// ClientNotificationToken is the bearer token the client supplied for ping and push notifications. It is not on
	// the BackChannelAuthenticationRequester interface; see GetClientNotificationToken.
	ClientNotificationToken string

	// AuthRequestID is the issued 'auth_req_id'. It is persisted only for ping and push clients, whose notification
	// to the client must carry it and cannot recover it from its signature. It is a secret; see Sanitize.
	AuthRequestID string

	// httpRequest is the HTTP request the authentication request was parsed from. It is never persisted; see
	// Sanitize.
	httpRequest *http.Request
}

// NewBackChannelAuthenticationRequest returns an empty BackChannelAuthenticationRequest with its embedded Request
// initialized.
func NewBackChannelAuthenticationRequest() *BackChannelAuthenticationRequest {
	return &BackChannelAuthenticationRequest{
		Request: *NewRequest(),
	}
}

// GetClientNotificationToken returns the client notification token of the request, or an empty string when the
// requester is not a *BackChannelAuthenticationRequest. A custom BackChannelAuthenticationRequester receives no HTTP
// request at the binding stage and cannot carry the token, so the ping and push notifications require the concrete
// type, and storage must round-trip it; see handler/ciba.Storage.
func GetClientNotificationToken(r BackChannelAuthenticationRequester) (token string) {
	if req, ok := r.(*BackChannelAuthenticationRequest); ok {
		return req.ClientNotificationToken
	}

	return ""
}

// GetAuthRequestID returns the persisted 'auth_req_id' of the request, which is set only for ping and push clients, or
// an empty string when the requester is not a *BackChannelAuthenticationRequest.
func GetAuthRequestID(r BackChannelAuthenticationRequester) (id string) {
	if req, ok := r.(*BackChannelAuthenticationRequest); ok {
		return req.AuthRequestID
	}

	return ""
}

func (r *BackChannelAuthenticationRequest) GetDeliveryMode() string { return r.DeliveryMode }

func (r *BackChannelAuthenticationRequest) GetHint() (kind CIBAHintKind, value string) {
	return r.HintKind, r.HintValue
}

func (r *BackChannelAuthenticationRequest) GetIDTokenHintClaims() jwt.MapClaims {
	return r.IDTokenHintClaims
}

func (r *BackChannelAuthenticationRequest) GetBindingMessage() string { return r.BindingMessage }

func (r *BackChannelAuthenticationRequest) GetUserCode() string { return r.UserCode }

func (r *BackChannelAuthenticationRequest) GetRequestedExpiry() time.Duration {
	return r.RequestedExpiry
}

func (r *BackChannelAuthenticationRequest) GetRequestContext() json.RawMessage {
	return r.RequestContext
}

func (r *BackChannelAuthenticationRequest) GetAuthRequestIDSignature() string {
	return r.AuthRequestIDSignature
}

func (r *BackChannelAuthenticationRequest) SetAuthRequestIDSignature(signature string) {
	r.AuthRequestIDSignature = signature
}

func (r *BackChannelAuthenticationRequest) GetStatus() CIBAStatus { return r.Status }

func (r *BackChannelAuthenticationRequest) SetStatus(status CIBAStatus) { r.Status = status }

func (r *BackChannelAuthenticationRequest) GetLastPolled() time.Time { return r.LastPolled }

// SetLastPolled records the time of the most recent poll, normalized to UTC.
func (r *BackChannelAuthenticationRequest) SetLastPolled(t time.Time) { r.LastPolled = t.UTC() }

func (r *BackChannelAuthenticationRequest) GetPollingInterval() time.Duration {
	return r.PollingInterval
}

func (r *BackChannelAuthenticationRequest) SetPollingInterval(d time.Duration) {
	r.PollingInterval = d
}

func (r *BackChannelAuthenticationRequest) GetSlowDownCount() int { return r.SlowDownCount }

func (r *BackChannelAuthenticationRequest) SetSlowDownCount(n int) { r.SlowDownCount = n }

func (r *BackChannelAuthenticationRequest) GetFailureCause() string { return r.FailureCause }

func (r *BackChannelAuthenticationRequest) SetFailureCause(cause string) { r.FailureCause = cause }

// Merge copies the requester data into this request. When requester is a *BackChannelAuthenticationRequest every CIBA
// field is also copied.
func (r *BackChannelAuthenticationRequest) Merge(requester Requester) {
	r.Request.Merge(requester)

	src, ok := requester.(*BackChannelAuthenticationRequest)
	if !ok {
		return
	}

	r.DeliveryMode = src.DeliveryMode
	r.HintKind = src.HintKind
	r.HintValue = src.HintValue
	r.IDTokenHintClaims = maps.Clone(src.IDTokenHintClaims)
	r.BindingMessage = src.BindingMessage
	r.UserCode = src.UserCode
	r.RequestedExpiry = src.RequestedExpiry
	r.RequestContext = slices.Clone(src.RequestContext)
	r.AuthRequestIDSignature = src.AuthRequestIDSignature
	r.Status = src.Status
	r.LastPolled = src.LastPolled
	r.PollingInterval = src.PollingInterval
	r.SlowDownCount = src.SlowDownCount
	r.FailureCause = src.FailureCause
	r.ClientNotificationToken = src.ClientNotificationToken
	r.AuthRequestID = src.AuthRequestID
}

// Sanitize returns a shallow copy of the request with its form restricted to allowedParameters and the always-allowed
// parameters, with the AuthRequestID, ClientNotificationToken and UserCode fields cleared, and with
// 'client_notification_token' and 'user_code' removed whatever allowedParameters holds, as both are credentials which
// must not be persisted in the form.
func (r *BackChannelAuthenticationRequest) Sanitize(allowedParameters []string) Requester {
	b := *r

	b.httpRequest = nil
	b.AuthRequestID = ""
	b.ClientNotificationToken = ""
	b.UserCode = ""

	if sanitized, ok := r.Request.Sanitize(allowedParameters).(*Request); ok {
		b.Request = *sanitized
	}

	form := url.Values{}

	for k, v := range b.Form {
		if k == consts.FormParameterClientNotificationToken || k == consts.FormParameterUserCode {
			continue
		}

		form[k] = v
	}

	b.Form = form

	return &b
}

// GetCIBAAuthRequestLifespan returns the lifespan of the 'auth_req_id' of request: the 'requested_expiry' clamped to the
// configured minimum and maximum when given, otherwise the configured authentication request lifespan.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1
func GetCIBAAuthRequestLifespan(ctx context.Context, config CIBAConfigProvider, request BackChannelAuthenticationRequester) (lifespan time.Duration) {
	if requested := request.GetRequestedExpiry(); requested > 0 {
		return min(max(requested, config.GetCIBARequestedExpiryMinimum(ctx)), config.GetCIBARequestedExpiryMaximum(ctx))
	}

	return config.GetCIBAAuthRequestLifespan(ctx)
}

var (
	_ BackChannelAuthenticationRequester = (*BackChannelAuthenticationRequest)(nil)
)
