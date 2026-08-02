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
// passed to NewRFC7592ClientConfigurationResponse. The HTTP method itself is not validated here - GET, PUT, and
// DELETE are all accepted, a JSON body is decoded only for PUT, and any other method is recorded on the request as
// given. HandleRFC7592ClientConfigurationEndpointRequest (handler/rfc7591) is the one that rejects an unsupported
// method, with ErrInvalidRequest naming it; WriteRFC7592ClientConfigurationError maps that to 405.
//
// The following specs must be considered in any implementation of this method:
// * https://datatracker.ietf.org/doc/html/rfc7592#section-2
//
//	The client_id and, if issued, the client_secret, MUST NOT be included in the metadata returned in response to
//	this request, unless they are being rotated. All requests to the client configuration endpoint MUST be
//	authenticated using the registration access token issued to the client and MUST be rejected if the
//	registration access token has been revoked or is otherwise invalid.
func (f *Fosite) NewRFC7592ClientConfigurationRequest(ctx context.Context, r *http.Request) (requester ClientConfigurationRequester, err error) {
	request := NewClientConfigurationRequest()
	request.Lang = i18n.GetLangFromRequest(f.Config.GetMessageCatalog(ctx), r)
	request.Method = r.Method

	// The client_id is derived from the final path segment, e.g. 'https://auth.example.com/register/{client_id}'
	// (see handler/rfc7591.ClientConfigurationURL, which constructs that same shape by appending url.PathEscape(id)).
	// Deriving from r.URL.EscapedPath() rather than r.URL.Path - which net/http has already percent-decoded - and
	// unescaping only the final segment keeps derivation the exact inverse of that construction for any id, not just
	// the alphanumeric ids the shipped generator happens to produce: an id containing '/' round-trips correctly
	// because the '/' stays encoded as '%2F' in every segment but the one being unescaped, so it is never mistaken
	// for a path separator. An empty segment - for example a request to '.../register/' - MUST be rejected here,
	// before the auth strategy is consulted: the auth strategy's subject check (defence in depth on top of the
	// audience check) is skipped entirely when id is empty, since an empty id also means "no subject check" for the
	// client registration endpoint's initial access token, which this is not.
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

	// The authenticated requester's ID carries the presented registration access token's signature (see
	// DefaultEndpointAuthStrategy.AuthenticateClientRegistrationRequest), so the PUT handler can delete the old
	// session when it rotates in a replacement token.
	//
	// ClientRegistrationEndpointAuthStrategy is an extension point, and a nil requester with a nil error is a legal
	// return meaning the endpoint is unauthenticated, so it must not be dereferenced unguarded here. Every other
	// consumer of the authenticated requester guards it the same way; with no requester there is no signature to
	// derive, and the handler simply skips deleting a previous session.
	if request.Authenticated != nil {
		request.Signature = request.Authenticated.GetID()
	}

	return request, nil
}

// lastPathSegment returns the final '/'-delimited segment of p, without normalizing a trailing slash first and
// without unescaping any percent-encoding present in p. A path ending in '/' therefore yields an empty segment,
// which is deliberate: it is what lets NewRFC7592ClientConfigurationRequest detect and reject a request with no
// client_id. Callers that need the client_id itself, rather than just detecting its absence, must unescape the
// returned segment separately - see NewRFC7592ClientConfigurationRequest, which calls this with r.URL.EscapedPath()
// so that a '%2F' within the id is not mistaken for a path separator before it is unescaped.
func lastPathSegment(p string) (segment string) {
	segments := strings.Split(p, "/")

	return segments[len(segments)-1]
}
