// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"encoding/json"
	"net/http"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
)

// WriteAuthorizeError writes an error response for the authorization endpoint. The configured ResponseModeHandlers are
// consulted first so the error can be delivered using the requested response_mode (query, fragment, form_post, etc.).
// If no handler matches, the error is written as JSON to rw using the configured AuthorizeErrorFieldResponseStrategy.
// An error the AuthorizeErrorRedirectPolicy does not trust the redirect URI for is written by the
// AuthorizeErrorFieldResponseStrategy without consulting the ResponseModeHandlers.
//
// See: https://www.rfc-editor.org/rfc/rfc9700#section-4.11.2
func (f *Fosite) WriteAuthorizeError(ctx context.Context, rw http.ResponseWriter, request AuthorizeRequester, err error) {
	rw.Header().Set(consts.HeaderCacheControl, consts.CacheControlNoStore)
	rw.Header().Set(consts.HeaderPragma, consts.PragmaNoCache)

	// RFC 9700 Section 4.11.2: the user agent is only redirected automatically to a trusted redirect URI.
	if request.IsRedirectURIValid() && !f.trustAuthorizeErrorRedirectURI(ctx, request, err) {
		f.handleWriteAuthorizeErrorFieldResponse(ctx, rw, request, ErrorToRFC6749Error(err).
			WithLegacyFormat(f.Config.GetUseLegacyErrorFormat(ctx)).
			WithExposeDebug(f.Config.GetSendDebugMessagesToClients(ctx)).
			WithLocalizer(f.Config.GetMessageCatalog(ctx), getLangFromRequester(request)))

		return
	}

	for _, handler := range f.Config.GetResponseModeHandlers(ctx) {
		if handler.ResponseModes().Has(request.GetResponseMode()) {
			handler.WriteAuthorizeError(ctx, rw, request, err)

			return
		}
	}

	f.handleWriteAuthorizeErrorFieldResponse(ctx, rw, request, ErrServerError.WithHint("The Authorization Server was unable to process the requested Response Mode."))
}

func (f *Fosite) trustAuthorizeErrorRedirectURI(ctx context.Context, request AuthorizeRequester, err error) bool {
	var policy AuthorizeErrorRedirectPolicy

	if p, ok := f.Config.(AuthorizeErrorRedirectPolicyProvider); ok {
		policy = p.GetAuthorizeErrorRedirectPolicy(ctx)
	}

	if policy == nil {
		policy = DefaultAuthorizeErrorRedirectPolicy{}
	}

	return policy.TrustAuthorizeErrorRedirectURI(ctx, request, err)
}

// AuthorizeErrorRedirectPolicy decides whether the user agent is redirected automatically to the redirect URI of an
// authorization request to deliver an error. An error which is not redirected is written by the configured
// AuthorizeErrorFieldResponseStrategy instead, so it is shown on the authorization server.
//
// An attacker can register a client with a redirect URI of their own, through dynamic client registration or a Client
// ID Metadata Document, and send the End-User an erroneous authorization request for it, so the authorization server
// redirects the End-User to the attacker. The authorization server must authenticate the End-User before redirecting,
// and should only redirect automatically to a redirect URI it trusts. An error is written before the End-User is
// authenticated when it is written for an error returned by NewAuthorizeRequest, so a policy should not trust the
// redirect URI of a client registered by a party that is not trusted, such as a dynamically registered client.
//
// See: https://www.rfc-editor.org/rfc/rfc9700#section-4.11.2
type AuthorizeErrorRedirectPolicy interface {
	// TrustAuthorizeErrorRedirectURI reports whether err may be delivered to the redirect URI of the request by
	// redirecting the user agent automatically.
	TrustAuthorizeErrorRedirectURI(ctx context.Context, request AuthorizeRequester, err error) (trusted bool)
}

// AuthorizeErrorRedirectPolicyProvider is implemented by a configuration which provides the
// AuthorizeErrorRedirectPolicy. A configuration which does not implement it, or which returns nil, uses the
// DefaultAuthorizeErrorRedirectPolicy.
type AuthorizeErrorRedirectPolicyProvider interface {
	// GetAuthorizeErrorRedirectPolicy returns the policy deciding whether an authorization error is redirected.
	GetAuthorizeErrorRedirectPolicy(ctx context.Context) (policy AuthorizeErrorRedirectPolicy)
}

// DefaultAuthorizeErrorRedirectPolicy trusts the redirect URI of every client except one resolved from a Client ID
// Metadata Document, whose redirect URIs anyone can publish without registering.
//
// See: https://www.rfc-editor.org/rfc/rfc9700#section-4.11.2
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03
type DefaultAuthorizeErrorRedirectPolicy struct{}

// TrustAuthorizeErrorRedirectURI implements AuthorizeErrorRedirectPolicy.
func (DefaultAuthorizeErrorRedirectPolicy) TrustAuthorizeErrorRedirectURI(_ context.Context, request AuthorizeRequester, _ error) (trusted bool) {
	return !jwt.IsClientIDMetadataDocumentClient(request.GetClient())
}

func (f *Fosite) handleWriteAuthorizeErrorFieldResponse(ctx context.Context, rw http.ResponseWriter, request AuthorizeRequester, rfc *RFC6749Error) {
	if strategy := f.Config.GetAuthorizeErrorFieldResponseStrategy(ctx); strategy != nil {
		strategy.WriteErrorFieldResponse(ctx, rw, request, rfc)
	} else {
		f.handleWriteAuthorizeErrorFieldResponseJSON(ctx, rw, rfc)
	}
}

func (f *Fosite) handleWriteAuthorizeErrorFieldResponseJSON(ctx context.Context, rw http.ResponseWriter, rfc *RFC6749Error) {
	rw.Header().Set(consts.HeaderContentType, consts.ContentTypeApplicationJSON)

	var (
		data []byte
		err  error
	)

	if data, err = json.Marshal(rfc); err != nil {
		f.writeFallbackJSONError(ctx, rw, err)

		return
	}

	rw.WriteHeader(rfc.CodeField)
	_, _ = rw.Write(data)
}

// AuthorizeErrorFieldResponseStrategy writes an authorization error as a field response.
type AuthorizeErrorFieldResponseStrategy interface {
	// WriteErrorFieldResponse writes the error to the response writer directly, for an authorization error which is not
	// returned to the client through a response mode.
	WriteErrorFieldResponse(ctx context.Context, rw http.ResponseWriter, request AuthorizeRequester, rfc *RFC6749Error)
}

// JSONAuthorizeErrorFieldResponseStrategy writes an authorization error as a JSON response body.
type JSONAuthorizeErrorFieldResponseStrategy struct {
	Config SendDebugMessagesToClientsProvider
}

// WriteErrorFieldResponse serializes the given RFC 6749 error as a JSON body and writes it to rw using the error's
// status code. This is the default strategy used by Fosite.WriteAuthorizeError when no response_mode handler matches.
func (s *JSONAuthorizeErrorFieldResponseStrategy) WriteErrorFieldResponse(ctx context.Context, rw http.ResponseWriter, request AuthorizeRequester, rfc *RFC6749Error) {
	rw.Header().Set(consts.HeaderContentType, consts.ContentTypeApplicationJSON)

	var (
		data []byte
		err  error
	)

	if data, err = json.Marshal(rfc); err != nil {
		writeFallbackJSONError(ctx, s.Config, rw, err)

		return
	}

	rw.WriteHeader(rfc.CodeField)
	_, _ = rw.Write(data)
}
