// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"encoding/json"
	"io"
	"mime"
	"net/http"

	"authelia.com/provider/oauth2/i18n"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

const (
	// DebugRFC7591ConfigMissing is the debug message returned when no RFC 7591 client registration endpoint auth
	// strategy is configured, mirroring DebugPARConfigMissing's pattern for the pushed authorization request
	// endpoint (see pushed_authorize_request_handler.go).
	DebugRFC7591ConfigMissing = "'RFC7591ClientRegistrationConfigProvider' not implemented"
)

// maxClientRegistrationRequestBodyBytes bounds the size of the JSON request body read at the client registration
// (RFC 7591) and client configuration (RFC 7592) endpoints. The registration endpoint is always reachable by an
// unauthenticated client, and the configuration endpoint becomes reachable by one whenever the presented credential
// turns out to be invalid, so the body must be bounded before it is read to avoid an unbounded read becoming a
// denial of service vector.
const maxClientRegistrationRequestBodyBytes = 1 << 20 // 1 MiB

// NewRFC7591ClientRegistrationRequest validates the request and produces a ClientRegistrationRequester that can be
// passed to NewRFC7591ClientRegistrationResponse.
//
// The following specs must be considered in any implementation of this method:
// * https://datatracker.ietf.org/doc/html/rfc7591#section-3.1
//
//	This request MUST be authenticated using a valid Initial Access Token, if authorization is required. The
//	request body is a JSON document consisting of a JSON object.
func (f *Fosite) NewRFC7591ClientRegistrationRequest(ctx context.Context, r *http.Request) (requester ClientRegistrationRequester, err error) {
	request := NewClientRegistrationRequest()
	request.Lang = i18n.GetLangFromRequest(f.Config.GetMessageCatalog(ctx), r)

	if r.Method != http.MethodPost {
		return request, errorsx.WithStack(ErrInvalidRequest.WithHintf("HTTP method is '%s', expected 'POST'.", r.Method))
	}

	if !hasJSONContentType(r) {
		return request, errorsx.WithStack(ErrInvalidRequest.WithHint("The Content-Type header must be 'application/json'."))
	}

	metadata := &ClientRegistrationMetadata{}

	if err = json.NewDecoder(io.LimitReader(r.Body, maxClientRegistrationRequestBodyBytes)).Decode(metadata); err != nil {
		return request, errorsx.WithStack(ErrInvalidClientMetadata.WithHint("Unable to parse HTTP body, make sure to send a properly formatted JSON request body.").WithWrap(err).WithDebugError(err))
	}

	request.Metadata = metadata

	strategy := f.Config.GetRFC7591ClientRegistrationEndpointAuthStrategy(ctx)
	if strategy == nil {
		return request, errorsx.WithStack(ErrServerError.WithDebug(DebugRFC7591ConfigMissing))
	}

	if request.Authenticated, err = strategy.AuthenticateClientRegistrationRequest(ctx, r, ""); err != nil {
		return request, err
	}

	return request, nil
}

// hasJSONContentType returns true when r's Content-Type header names the "application/json" media type, ignoring
// any parameters such as a charset.
func hasJSONContentType(r *http.Request) (ok bool) {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get(consts.HeaderContentType))
	if err != nil {
		return false
	}

	return mediaType == consts.MediaTypeApplicationJSON
}
