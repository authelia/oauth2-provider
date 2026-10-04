// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"

	"authelia.com/provider/oauth2/i18n"
	"authelia.com/provider/oauth2/x/errorsx"
)

// NewRFC7592ClientConfigurationRequest validates the request and produces a ClientConfigurationRequester that can be
// passed to NewRFC7592ClientConfigurationResponse. The HTTP method is not validated here:
// HandleRFC7592ClientConfigurationEndpointRequest (handler/rfc7591) rejects an unsupported method.
//
// See: https://datatracker.ietf.org/doc/html/rfc7592#section-2
func (f *Fosite) NewRFC7592ClientConfigurationRequest(ctx context.Context, r *http.Request) (requester ClientConfigurationRequester, err error) {
	request := NewClientConfigurationRequest()
	request.Lang = i18n.GetLangFromRequest(f.Config.GetMessageCatalog(ctx), r)
	request.Method = r.Method

	// The client_id is the unescaped final segment of the escaped path, the inverse of
	// handler/rfc7591.ClientConfigurationURL, so an id containing '/' round-trips. An empty segment MUST be rejected
	// before the auth strategy is consulted, which skips its subject check for an empty id.
	escapedID := lastPathSegment(r.URL.EscapedPath())
	if escapedID == "" {
		return request, errorsx.WithStack(ErrNotFound.WithHint("The request does not specify a client_id."))
	}

	var id string

	if id, err = url.PathUnescape(escapedID); err != nil {
		return request, errorsx.WithStack(ErrNotFound.WithHint("The request specifies a malformed client_id.").WithWrap(err).WithDebugError(err))
	}

	request.ClientID = id

	if r.Method == http.MethodPut {
		if !hasJSONContentType(r) {
			return request, errorsx.WithStack(ErrInvalidClientMetadata.WithHint("The Content-Type header must be 'application/json'."))
		}

		metadata := &ClientRegistrationMetadata{}

		if err = json.NewDecoder(io.LimitReader(r.Body, maxClientRegistrationRequestBodyBytes)).Decode(metadata); err != nil {
			return request, errorsx.WithStack(ErrInvalidClientMetadata.WithHint("Unable to parse HTTP body, make sure to send a properly formatted JSON request body.").WithWrap(err).WithDebugError(err))
		}

		request.Metadata = metadata
	}

	strategy := f.Config.GetRFC7591ClientRegistrationEndpointAuthStrategy(ctx)
	if strategy == nil {
		return request, errorsx.WithStack(ErrServerError.WithDebug(DebugRFC7591ConfigMissing))
	}

	if request.Authenticated, err = strategy.AuthenticateClientRegistrationRequest(ctx, r, id); err != nil {
		return request, err
	}

	// RFC 7592 Section 2 requires the registration access token on every call, so a nil requester with a nil error,
	// which the strategy returns for an open endpoint, fails closed here.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc7592#section-2
	if request.Authenticated == nil {
		return request, errorsx.WithStack(ErrRequestUnauthorized.
			WithHint("The Client Configuration Endpoint requires a Client Registration Token.").
			WithDebug("The configured ClientRegistrationEndpointAuthStrategy reported the endpoint is open by returning no requester and no error. That return is only valid for the client registration endpoint; every client configuration request must be authenticated."))
	}

	// The authenticated requester's ID carries the presented registration access token's signature (see
	// DefaultEndpointAuthStrategy.AuthenticateClientRegistrationRequest), so the PUT handler can delete the old
	// session when it rotates in a replacement token.
	request.Signature = request.Authenticated.GetID()

	return request, nil
}

// lastPathSegment returns the final '/'-delimited segment of p without unescaping it. A path ending in '/' yields an
// empty segment.
func lastPathSegment(p string) (segment string) {
	segments := strings.Split(p, "/")

	return segments[len(segments)-1]
}
