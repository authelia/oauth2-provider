// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"

	"authelia.com/provider/oauth2/i18n"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

const (
	// DebugRFC7591ConfigMissing is the debug message returned when no RFC 7591 client registration endpoint auth
	// strategy is configured.
	DebugRFC7591ConfigMissing = "'RFC7591ClientRegistrationConfigProvider' not implemented"
)

// maxClientRegistrationRequestBodyBytes bounds the size of the JSON request body read at the client registration
// (RFC 7591) and client configuration (RFC 7592) endpoints, both of which read it before the caller is authenticated.
const maxClientRegistrationRequestBodyBytes = 1 << 20 // 1 MiB

// NewRFC7591ClientRegistrationRequest validates the request and produces a ClientRegistrationRequester that can be
// passed to NewRFC7591ClientRegistrationResponse.
//
// See: https://datatracker.ietf.org/doc/html/rfc7591#section-3.1
func (f *Fosite) NewRFC7591ClientRegistrationRequest(ctx context.Context, r *http.Request) (requester ClientRegistrationRequester, err error) {
	request := NewClientRegistrationRequest()
	request.Lang = i18n.GetLangFromRequest(f.Config.GetMessageCatalog(ctx), r)

	if r.Method != http.MethodPost {
		return request, errorsx.WithStack(ErrInvalidRequest.WithHintf("HTTP method is '%s', expected 'POST'.", r.Method))
	}

	if !hasJSONContentType(r) {
		return request, errorsx.WithStack(ErrInvalidRequest.WithHint("The Content-Type header must be 'application/json'."))
	}

	var metadata *ClientRegistrationMetadata

	decoder := json.NewDecoder(io.LimitReader(r.Body, maxClientRegistrationRequestBodyBytes))

	// Decoded into a pointer, not a value: RFC 7591 Section 2 requires the body be a JSON object, and a literal 'null'
	// decoded into a value would leave a zero-valued struct behind and register a client from a body that carried no
	// metadata at all. Into a pointer it leaves nil, which is distinguishable.
	if err = decoder.Decode(&metadata); err != nil {
		return request, errorsx.WithStack(ErrInvalidClientMetadata.WithHint("Unable to parse HTTP body, make sure to send a properly formatted JSON request body.").WithWrap(err).WithDebugError(err))
	}

	if metadata == nil {
		return request, errorsx.WithStack(ErrInvalidClientMetadata.WithHint("The request body must be a JSON object."))
	}

	// The body is one JSON object, not a stream of them: a decoder stops at the end of the first value and would
	// otherwise silently ignore whatever follows it, so anything but the end of the input here is a malformed body.
	if trailing := decoder.Decode(new(json.RawMessage)); !errors.Is(trailing, io.EOF) {
		return request, errorsx.WithStack(ErrInvalidClientMetadata.WithHint("The request body must contain a single JSON object.").WithWrap(trailing).WithDebugError(trailing))
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

func hasJSONContentType(r *http.Request) (ok bool) {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get(consts.HeaderContentType))
	if err != nil {
		return false
	}

	return mediaType == consts.MediaTypeApplicationJSON
}
