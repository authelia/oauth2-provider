// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"golang.org/x/net/http/httpguts"

	"authelia.com/provider/oauth2/i18n"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

const ssfStreamAllowedMethods = http.MethodGet + ", " + http.MethodPost + ", " + http.MethodPut + ", " + http.MethodPatch + ", " + http.MethodDelete

const ssfStreamQueryStreamID = "stream_id"

// SSFStreamRequester is a validated and authorized request to the SSF stream configuration endpoint.
type SSFStreamRequester interface {
	// GetMethod returns the HTTP method of the request.
	GetMethod() (method string)

	// GetClient returns the client that owns the Access Token, which is the stream owner.
	GetClient() (client Client)

	// GetStreamID returns the 'stream_id' query parameter, or empty.
	GetStreamID() (id string)

	// GetBody returns the decoded request body. It is nil unless the method is POST, PUT or PATCH.
	GetBody() (body *SSFStreamRequestBody)
}

// SSFStreamResponder is the response of the SSF stream configuration endpoint.
type SSFStreamResponder interface {
	// GetStatusCode returns the HTTP status code.
	GetStatusCode() (code int)

	// GetBody returns the value serialized as the JSON response body. A nil body writes no content.
	GetBody() (body any)
}

// SSFStreamRequestBody is the decoded body of a stream configuration request. Create ignores the Transmitter-supplied
// properties; update compares them to the stored stream. Unlike SSFDelivery, its delivery holds the
// 'authorization_header'. A nil EventsRequested, Delivery or Description is absent.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1
type SSFStreamRequestBody struct {
	EventsRequested []string                  `json:"events_requested"`
	Delivery        *SSFStreamRequestDelivery `json:"delivery"`
	Description     *string                   `json:"description"`

	StreamID        string          `json:"stream_id"`
	Issuer          *string         `json:"iss"`
	Audience        json.RawMessage `json:"aud"`
	EventsSupported []string        `json:"events_supported"`
	EventsDelivered []string        `json:"events_delivered"`

	MinVerificationInterval *int `json:"min_verification_interval"`
	InactivityTimeout       *int `json:"inactivity_timeout"`
}

// SSFStreamRequestDelivery is the delivery object of a request body.
type SSFStreamRequestDelivery struct {
	Method              string  `json:"method"`
	EndpointURL         string  `json:"endpoint_url"`
	AuthorizationHeader *string `json:"authorization_header"`
}

// MarshalJSON omits the authorization header.
func (d SSFStreamRequestDelivery) MarshalJSON() (data []byte, err error) {
	return json.Marshal(struct {
		Method      string `json:"method"`
		EndpointURL string `json:"endpoint_url,omitempty"`
	}{d.Method, d.EndpointURL})
}

// Format implements fmt.Formatter, redacting AuthorizationHeader for every verb.
func (d SSFStreamRequestDelivery) Format(f fmt.State, verb rune) {
	SSFDelivery{Method: d.Method, EndpointURL: d.EndpointURL, AuthorizationHeader: ptrString(d.AuthorizationHeader)}.Format(f, verb)
}

// SSFStreamRequest is the default SSFStreamRequester.
type SSFStreamRequest struct {
	Method   string
	Client   Client
	StreamID string
	Body     *SSFStreamRequestBody
}

func (r *SSFStreamRequest) GetMethod() (method string)            { return r.Method }
func (r *SSFStreamRequest) GetClient() (client Client)            { return r.Client }
func (r *SSFStreamRequest) GetStreamID() (id string)              { return r.StreamID }
func (r *SSFStreamRequest) GetBody() (body *SSFStreamRequestBody) { return r.Body }

// SSFStreamResponse is the default SSFStreamResponder.
type SSFStreamResponse struct {
	StatusCode int
	Body       any
}

func (r *SSFStreamResponse) GetStatusCode() (code int) { return r.StatusCode }
func (r *SSFStreamResponse) GetBody() (body any)       { return r.Body }

// NewSSFStreamRequest authorizes the request and decodes its body. Only GET, POST, PUT, PATCH and DELETE are served; reads need
// 'ssf.read' and writes 'ssf.manage'.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1
func (f *Fosite) NewSSFStreamRequest(ctx context.Context, r *http.Request, session Session) (requester SSFStreamRequester, err error) {
	switch r.Method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
	default:
		return nil, errorsx.WithStack(ErrInvalidRequest.WithHintf("HTTP method is '%s', expected one of '%s'.", r.Method, ssfStreamAllowedMethods).WithCode(http.StatusMethodNotAllowed))
	}

	var ar AccessRequester

	if ar, _, err = f.authorizeSSFRequest(ctx, r, session, r.Method != http.MethodGet); err != nil {
		return nil, err
	}

	request := &SSFStreamRequest{
		Method:   r.Method,
		Client:   ar.GetClient(),
		StreamID: r.URL.Query().Get(ssfStreamQueryStreamID),
	}

	if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
		if request.Body, err = decodeSSFRequestBody[SSFStreamRequestBody](f, ctx, r); err != nil {
			return nil, err
		}
	}

	return request, nil
}

func decodeSSFRequestBody[T any](f *Fosite, ctx context.Context, r *http.Request) (body *T, err error) {
	if !hasJSONContentType(r) {
		return nil, errorsx.WithStack(ErrInvalidRequest.WithHint("The Content-Type header must be 'application/json'."))
	}

	var data []byte

	if data, err = readSSFRequestBody(f, ctx, r); err != nil {
		return nil, err
	}

	return parseSSFRequestBody[T](data)
}

func readSSFRequestBody(f *Fosite, ctx context.Context, r *http.Request) (data []byte, err error) {
	limit := f.getSSFConfig(ctx).MaxRequestBytes

	// One byte over the limit is read so an oversize body is rejected rather than truncated into valid JSON.
	if data, err = io.ReadAll(io.LimitReader(r.Body, limit+1)); err != nil {
		return nil, errorsx.WithStack(ErrInvalidRequest.WithHint("Unable to read the HTTP body.").WithWrap(err).WithDebugError(err))
	}

	if int64(len(data)) > limit {
		return nil, errorsx.WithStack(ErrInvalidRequest.WithHint("The request body is too large."))
	}

	return data, nil
}

func parseSSFRequestBody[T any](data []byte) (body *T, err error) {
	decoder := json.NewDecoder(bytes.NewReader(data))

	if err = decoder.Decode(&body); err != nil {
		return nil, errorsx.WithStack(ErrInvalidRequest.WithHint("Unable to parse HTTP body, make sure to send a properly formatted JSON request body.").WithWrap(err).WithDebugError(err))
	}

	if body == nil {
		return nil, errorsx.WithStack(ErrInvalidRequest.WithHint("The request body must be a JSON object."))
	}

	if trailing := decoder.Decode(new(json.RawMessage)); !errors.Is(trailing, io.EOF) {
		return nil, errorsx.WithStack(ErrInvalidRequest.WithHint("The request body must contain a single JSON object.").WithWrap(trailing).WithDebugError(trailing))
	}

	return body, nil
}

// NewSSFStreamResponse creates, reads, lists, updates, replaces or deletes the streams of the requesting client.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1
func (f *Fosite) NewSSFStreamResponse(ctx context.Context, requester SSFStreamRequester) (responder SSFStreamResponder, err error) {
	var (
		config  *SSFConfig
		storage SSFStreamStorage
		ok      bool
	)

	if config = f.getSSFConfig(ctx); config == nil {
		return nil, errorsx.WithStack(ErrServerError.WithDebug("The Shared Signals Framework transmitter is not configured."))
	}

	if storage, ok = f.Store.(SSFStreamStorage); !ok {
		return nil, errorsx.WithStack(ErrServerError.WithDebug("The storage does not implement SSFStreamStorage."))
	}

	clientID := requester.GetClient().GetID()

	switch requester.GetMethod() {
	case http.MethodPost:
		return f.createSSFStream(ctx, config, storage, requester)
	case http.MethodPut, http.MethodPatch:
		return f.updateSSFStream(ctx, config, storage, requester)
	case http.MethodGet:
		return f.readSSFStreams(ctx, storage, clientID, requester.GetStreamID())
	case http.MethodDelete:
		if requester.GetStreamID() == "" {
			return nil, errorsx.WithStack(ErrInvalidRequest.WithHint("The 'stream_id' query parameter is required."))
		}

		if err = storage.DeleteSSFStream(ctx, clientID, requester.GetStreamID()); err != nil {
			return nil, ssfStreamStorageError(err)
		}

		return &SSFStreamResponse{StatusCode: http.StatusNoContent}, nil
	default:
		return nil, errorsx.WithStack(ErrInvalidRequest.WithHintf("HTTP method is '%s', expected one of '%s'.", requester.GetMethod(), ssfStreamAllowedMethods).WithCode(http.StatusMethodNotAllowed))
	}
}

// ssfMethodNotAllowedError is a 405 that names the methods the endpoint serves for the Allow header.
type ssfMethodNotAllowedError struct {
	error

	allow string
}

func (e *ssfMethodNotAllowedError) Unwrap() error { return e.error }

// ssfStreamStorageError gives an unknown stream and another client's stream the same error.
func ssfStreamStorageError(err error) error {
	if errors.Is(err, ErrNotFound) {
		return errorsx.WithStack(ErrNotFound.WithHint("The stream does not exist."))
	}

	return err
}

func (f *Fosite) readSSFStreams(ctx context.Context, storage SSFStreamStorage, clientID, streamID string) (responder SSFStreamResponder, err error) {
	if streamID != "" {
		var stream *SSFStream

		if stream, err = storage.GetSSFStream(ctx, clientID, streamID); err != nil {
			return nil, ssfStreamStorageError(err)
		}

		if stream == nil || stream.ClientID != clientID {
			return nil, ssfStreamStorageError(ErrNotFound)
		}

		return &SSFStreamResponse{StatusCode: http.StatusOK, Body: stream}, nil
	}

	var streams []*SSFStream

	if streams, err = storage.ListSSFStreams(ctx, clientID); err != nil {
		return nil, err
	}

	// An empty list is '[]', never 'null' (SSF Section 8.1.1.2).
	owned := make([]*SSFStream, 0, len(streams))

	for _, stream := range streams {
		if stream != nil && stream.ClientID == clientID {
			owned = append(owned, stream)
		}
	}

	return &SSFStreamResponse{StatusCode: http.StatusOK, Body: owned}, nil
}

func (f *Fosite) createSSFStream(ctx context.Context, config *SSFConfig, storage SSFStreamStorage, requester SSFStreamRequester) (responder SSFStreamResponder, err error) {
	client := requester.GetClient()
	body := requester.GetBody()

	if body == nil {
		body = &SSFStreamRequestBody{}
	}

	// Every SET of the stream uses this as 'iss' (SSF Section 4.1.6).
	if config.Issuer == "" {
		return nil, errorsx.WithStack(ErrServerError.WithDebug("The Shared Signals Framework transmitter is not configured with an issuer."))
	}

	var policy *SSFClientPolicy

	if policy, err = f.resolveSSFClientPolicy(ctx, config, client); err != nil {
		return nil, err
	}

	var streamID string

	if streamID, err = generateSSFStreamID(); err != nil {
		return nil, errorsx.WithStack(ErrServerError.WithDebugError(err))
	}

	var delivery SSFDelivery

	if delivery, err = f.newSSFDelivery(ctx, config, client, policy, streamID, body.Delivery); err != nil {
		return nil, err
	}

	audience := slices.Clone(policy.Audience)

	if slices.Contains(audience, "") {
		return nil, errorsx.WithStack(ErrServerError.WithDebug("The stream policy returned an empty audience."))
	}

	if len(audience) == 0 {
		audience = []string{client.GetID()}
	}

	stream := &SSFStream{
		StreamID:                streamID,
		ClientID:                client.GetID(),
		Issuer:                  config.Issuer,
		Audience:                audience,
		EventsSupported:         slices.Clone(policy.EventsSupported),
		EventsRequested:         slices.Clone(body.EventsRequested),
		EventsDelivered:         ssfIntersect(policy.EventsSupported, body.EventsRequested),
		Delivery:                delivery,
		Description:             ptrString(body.Description),
		Status:                  SSFStreamStatusEnabled,
		MinVerificationInterval: int(config.MinVerificationInterval / time.Second),
	}

	if err = storage.CreateSSFStream(ctx, stream); err != nil {
		return nil, err
	}

	return &SSFStreamResponse{StatusCode: http.StatusCreated, Body: stream}, nil
}

func ptrString(p *string) (s string) {
	if p == nil {
		return ""
	}

	return *p
}

// updateSSFStream applies a PATCH or PUT. PATCH changes only the Receiver-supplied properties present; PUT replaces
// them all, so a missing one is cleared, and requires 'delivery'. A Transmitter-supplied property that is present must
// equal the stored value before any change; 'aud', 'events_supported' and 'events_delivered' are compared as sets, and
// the 'endpoint_url' of a stream that stays poll is compared too. The stream ID must be in the body. The library
// supplies no 'inactivity_timeout', so a present one never matches.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1.3
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1.4
func (f *Fosite) updateSSFStream(ctx context.Context, config *SSFConfig, storage SSFStreamStorage, requester SSFStreamRequester) (responder SSFStreamResponder, err error) {
	client := requester.GetClient()
	body := requester.GetBody()

	if body == nil {
		body = &SSFStreamRequestBody{}
	}

	replace := requester.GetMethod() == http.MethodPut
	streamID := body.StreamID

	if streamID == "" {
		return nil, errorsx.WithStack(ErrInvalidRequest.WithHint("The 'stream_id' is required in the request body."))
	}

	var stored *SSFStream

	if stored, err = storage.GetSSFStream(ctx, client.GetID(), streamID); err != nil {
		return nil, ssfStreamStorageError(err)
	}

	if stored == nil || stored.ClientID != client.GetID() {
		return nil, ssfStreamStorageError(ErrNotFound)
	}

	var policy *SSFClientPolicy

	if policy, err = f.resolveSSFClientPolicy(ctx, config, client); err != nil {
		return nil, err
	}

	if err = checkSSFTransmitterProperties(body, stored); err != nil {
		return nil, err
	}

	// The delivery is REQUIRED (SSF Section 8.1.1), and a replace supplies the full set (SSF Section 8.1.1.4).
	if replace && body.Delivery == nil {
		return nil, errorsx.WithStack(ErrInvalidRequest.WithHint("The 'delivery' is required when replacing a stream."))
	}

	updated := *stored

	updated.Audience = slices.Clone(stored.Audience)
	updated.EventsSupported = slices.Clone(policy.EventsSupported)
	updated.EventsRequested = slices.Clone(stored.EventsRequested)

	if replace || body.EventsRequested != nil {
		updated.EventsRequested = slices.Clone(body.EventsRequested)
	}

	if replace || body.Description != nil {
		updated.Description = ptrString(body.Description)
	}

	updated.EventsDelivered = ssfIntersect(policy.EventsSupported, updated.EventsRequested)

	if body.Delivery != nil {
		// The poll endpoint URL is Transmitter-supplied (SSF Section 8.1.1.3).
		if stored.Delivery.Method == SSFDeliveryMethodPoll && body.Delivery.Method == SSFDeliveryMethodPoll &&
			body.Delivery.EndpointURL != "" && body.Delivery.EndpointURL != stored.Delivery.EndpointURL {
			return nil, errorsx.WithStack(ErrInvalidRequest.WithHint("A Transmitter-supplied property does not match the stream."))
		}

		var delivery SSFDelivery

		if delivery, err = f.newSSFDelivery(ctx, config, client, policy, streamID, body.Delivery); err != nil {
			return nil, err
		}

		// Deviates from SSF Section 8.1.1.4, where a missing property is deleted: the stored authorization header is
		// kept only when the push endpoint URL is unchanged and the header is absent or null; an empty string clears it.
		if delivery.Method == SSFDeliveryMethodPush && body.Delivery.AuthorizationHeader == nil &&
			stored.Delivery.Method == SSFDeliveryMethodPush && stored.Delivery.EndpointURL == delivery.EndpointURL {
			delivery.AuthorizationHeader = stored.Delivery.AuthorizationHeader
		}

		updated.Delivery = delivery
	} else if !slices.Contains(policy.DeliveryMethods, stored.Delivery.Method) {
		return nil, errorsx.WithStack(ErrInvalidRequest.WithHint("The delivery method is not permitted for the client."))
	} else if err = f.validateSSFStoredDelivery(ctx, config, client, stored.Delivery); err != nil {
		return nil, err
	}

	if err = storage.UpdateSSFStream(ctx, &updated); err != nil {
		return nil, ssfStreamStorageError(err)
	}

	return &SSFStreamResponse{StatusCode: http.StatusOK, Body: &updated}, nil
}

// checkSSFTransmitterProperties rejects a present Transmitter-supplied property that differs from the stored stream.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1.3
func checkSSFTransmitterProperties(body *SSFStreamRequestBody, stored *SSFStream) (err error) {
	mismatch := errorsx.WithStack(ErrInvalidRequest.WithHint("A Transmitter-supplied property does not match the stream."))

	if body.Issuer != nil && *body.Issuer != stored.Issuer {
		return mismatch
	}

	if len(body.Audience) != 0 && string(body.Audience) != "null" {
		var audience []string

		if err = json.Unmarshal(body.Audience, &audience); err != nil {
			var single string

			if err = json.Unmarshal(body.Audience, &single); err != nil {
				return errorsx.WithStack(ErrInvalidRequest.WithHint("The 'aud' property must be a string or an array of strings."))
			}

			audience = []string{single}
		}

		if !ssfSameSet(audience, stored.Audience) {
			return mismatch
		}
	}

	if body.EventsSupported != nil && !ssfSameSet(body.EventsSupported, stored.EventsSupported) {
		return mismatch
	}

	if body.EventsDelivered != nil && !ssfSameSet(body.EventsDelivered, stored.EventsDelivered) {
		return mismatch
	}

	if body.MinVerificationInterval != nil && *body.MinVerificationInterval != stored.MinVerificationInterval {
		return mismatch
	}

	if body.InactivityTimeout != nil {
		return mismatch
	}

	return nil
}

// ssfSameSet reports whether a and b hold the same values, ignoring order and duplicates.
func ssfSameSet(a, b []string) bool {
	for _, v := range a {
		if !slices.Contains(b, v) {
			return false
		}
	}

	for _, v := range b {
		if !slices.Contains(a, v) {
			return false
		}
	}

	return true
}

// resolveSSFClientPolicy returns the policy of the client. A missing policy is a misconfiguration, and a policy error
// denies the request.
func (f *Fosite) resolveSSFClientPolicy(ctx context.Context, config *SSFConfig, client Client) (policy *SSFClientPolicy, err error) {
	if config.Policy == nil {
		return nil, errorsx.WithStack(ErrServerError.WithDebug("The Shared Signals Framework transmitter is not configured with a stream policy."))
	}

	if policy, err = config.Policy.SSFStreamPolicy(ctx, client); err != nil {
		return nil, errorsx.WithStack(ErrAccessDenied.WithHint("The client is not permitted to use the stream.").WithWrap(err).WithDebugError(err))
	}

	if policy == nil {
		return nil, errorsx.WithStack(ErrServerError.WithDebug("The stream policy returned no policy."))
	}

	return policy, nil
}

// newSSFDelivery builds the delivery of a stream from the Receiver-supplied delivery. An absent delivery is poll. The
// poll endpoint URL is Transmitter-supplied and the Receiver value is not used, nor is its authorization header. A push
// endpoint URL must be https and pass the SSFEndpointValidator, which must be configured.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1.1
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-6.1.2
func (f *Fosite) newSSFDelivery(ctx context.Context, config *SSFConfig, client Client, policy *SSFClientPolicy, streamID string, in *SSFStreamRequestDelivery) (delivery SSFDelivery, err error) {
	method := SSFDeliveryMethodPoll

	if in != nil {
		method = in.Method
	}

	if method != SSFDeliveryMethodPush && method != SSFDeliveryMethodPoll {
		return SSFDelivery{}, errorsx.WithStack(ErrInvalidRequest.WithHint("The delivery method is not supported."))
	}

	if !slices.Contains(policy.DeliveryMethods, method) {
		return SSFDelivery{}, errorsx.WithStack(ErrInvalidRequest.WithHint("The delivery method is not permitted for the client."))
	}

	if method == SSFDeliveryMethodPoll {
		if config.PollEndpointURL == nil {
			return SSFDelivery{}, errorsx.WithStack(ErrServerError.WithDebug("The Shared Signals Framework transmitter is not configured with a poll endpoint URL."))
		}

		var endpoint string

		if endpoint, err = config.PollEndpointURL(ctx, streamID); err != nil {
			return SSFDelivery{}, errorsx.WithStack(ErrServerError.WithWrap(err).WithDebugError(err))
		}

		if endpoint == "" {
			return SSFDelivery{}, errorsx.WithStack(ErrServerError.WithDebug("The poll endpoint URL function returned an empty URL."))
		}

		return SSFDelivery{Method: SSFDeliveryMethodPoll, EndpointURL: endpoint}, nil
	}

	if err = validateSSFPushEndpoint(ctx, config, client, in.EndpointURL); err != nil {
		return SSFDelivery{}, err
	}

	// A header value with CR, LF or other control characters can never be sent.
	if !httpguts.ValidHeaderFieldValue(ptrString(in.AuthorizationHeader)) {
		return SSFDelivery{}, errorsx.WithStack(ErrInvalidRequest.WithHint("The delivery 'authorization_header' is not a valid header value."))
	}

	return SSFDelivery{Method: SSFDeliveryMethodPush, EndpointURL: in.EndpointURL, AuthorizationHeader: ptrString(in.AuthorizationHeader)}, nil
}

func validateSSFPushEndpoint(ctx context.Context, config *SSFConfig, client Client, raw string) (err error) {
	if config.EndpointValidator == nil {
		return errorsx.WithStack(ErrServerError.WithDebug("The Shared Signals Framework transmitter is not configured with an endpoint validator, so push streams cannot be used."))
	}

	var endpoint *url.URL

	if endpoint, err = url.Parse(raw); err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.User != nil || strings.Contains(raw, "#") {
		return errorsx.WithStack(ErrInvalidRequest.WithHint("The delivery 'endpoint_url' must be an absolute https URL."))
	}

	if err = config.EndpointValidator.ValidateSSFEndpoint(ctx, client, endpoint); err != nil {
		return errorsx.WithStack(ErrInvalidRequest.WithHint("The delivery 'endpoint_url' is not permitted.").WithWrap(err).WithDebugError(err))
	}

	return nil
}

func (f *Fosite) validateSSFStoredDelivery(ctx context.Context, config *SSFConfig, client Client, delivery SSFDelivery) (err error) {
	if delivery.Method == SSFDeliveryMethodPoll {
		return nil
	}

	return validateSSFPushEndpoint(ctx, config, client, delivery.EndpointURL)
}

// ssfIntersect returns the elements of supported that are in requested, without duplicates. It is never nil.
func ssfIntersect(supported, requested []string) (delivered []string) {
	delivered = []string{}

	for _, event := range supported {
		if slices.Contains(requested, event) && !slices.Contains(delivered, event) {
			delivered = append(delivered, event)
		}
	}

	return delivered
}

// generateSSFStreamID returns 128 bits of URL-safe random data.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1
func generateSSFStreamID() (id string, err error) {
	b := make([]byte, 16)

	if _, err = rand.Read(b); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}

// WriteSSFStreamResponse writes the stream configuration response with 'Cache-Control: no-store'. A 204 has no body.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1.5
func (f *Fosite) WriteSSFStreamResponse(ctx context.Context, rw http.ResponseWriter, requester SSFStreamRequester, responder SSFStreamResponder) {
	f.writeSSFResponse(ctx, rw, responder)
}

func (f *Fosite) writeSSFResponse(ctx context.Context, rw http.ResponseWriter, responder SSFStreamResponder) {
	rw.Header().Set(consts.HeaderCacheControl, consts.CacheControlNoStore)
	rw.Header().Set(consts.HeaderPragma, consts.PragmaNoCache)

	code := responder.GetStatusCode()

	if code == http.StatusNoContent || responder.GetBody() == nil {
		rw.WriteHeader(code)

		return
	}

	data, err := json.Marshal(responder.GetBody())
	if err != nil {
		f.writeFallbackJSONError(ctx, rw, err)

		return
	}

	rw.Header().Set(consts.HeaderContentType, consts.ContentTypeApplicationJSON)
	rw.WriteHeader(code)
	_, _ = rw.Write(data)
}

// WriteSSFError writes an SSF endpoint error with 'Cache-Control: no-store'. A rejected bearer credential is answered
// with the RFC 6750 and RFC 9449 challenge.
//
// See: https://www.rfc-editor.org/rfc/rfc6750#section-3
// See: https://www.rfc-editor.org/rfc/rfc9449#section-7.1
func (f *Fosite) WriteSSFError(ctx context.Context, rw http.ResponseWriter, r *http.Request, err error) {
	rw.Header().Set(consts.HeaderCacheControl, consts.CacheControlNoStore)
	rw.Header().Set(consts.HeaderPragma, consts.PragmaNoCache)
	rw.Header().Set(consts.HeaderContentType, consts.ContentTypeApplicationJSON)

	var rfc *RFC6749Error

	if IsBearerCredentialError(err) {
		rfc = f.WriteBearerAuthorizationChallenge(ctx, rw, r, err)
	} else {
		rfc = ErrorToRFC6749Error(err)
	}

	if rfc.CodeField == http.StatusMethodNotAllowed {
		allow := ssfStreamAllowedMethods

		var methodErr *ssfMethodNotAllowedError

		if errors.As(err, &methodErr) {
			allow = methodErr.allow
		}

		rw.Header().Set(consts.HeaderAllow, allow)
	}

	catalog := f.Config.GetMessageCatalog(ctx)

	rfc = rfc.WithLegacyFormat(f.Config.GetUseLegacyErrorFormat(ctx)).WithExposeDebug(f.Config.GetSendDebugMessagesToClients(ctx))

	if r != nil {
		rfc = rfc.WithLocalizer(catalog, i18n.GetLangFromRequest(catalog, r))
	}

	data, merr := json.Marshal(rfc)
	if merr != nil {
		f.writeFallbackJSONError(ctx, rw, merr)

		return
	}

	rw.WriteHeader(rfc.CodeField)
	_, _ = rw.Write(data)
}
