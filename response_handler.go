// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jarm"
	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

type DefaultResponseModeHandler struct {
	Config ResponseModeHandlerConfigurator
}

// ResponseModes returns the response modes this fosite.ResponseModeHandler is responsible for.
func (h *DefaultResponseModeHandler) ResponseModes() ResponseModeTypes {
	return ResponseModeTypes{
		ResponseModeDefault,
		ResponseModeQuery,
		ResponseModeFragment,
		ResponseModeFormPost,
		ResponseModeJWT,
		ResponseModeQueryJWT,
		ResponseModeFragmentJWT,
		ResponseModeFormPostJWT,
	}
}

// ResponseModesSupported returns the response modes ParseResponseMode accepts for this handler. The JWT Secured
// Authorization Response Mode values are omitted when no JARM strategy is configured.
//
// See: https://openid.net/specs/oauth-v2-jarm.html#section-2.3
func (h *DefaultResponseModeHandler) ResponseModesSupported(ctx context.Context) (modes ResponseModeTypes) {
	modes = h.ResponseModes()

	if h.Config != nil && h.Config.GetJWTSecuredAuthorizeResponseModeStrategy(ctx) != nil {
		return modes
	}

	return slices.DeleteFunc(modes, func(mode ResponseModeType) bool {
		switch mode {
		case ResponseModeJWT, ResponseModeQueryJWT, ResponseModeFragmentJWT, ResponseModeFormPostJWT:
			return true
		}

		return false
	})
}

// WriteAuthorizeResponse writes authorization responses.
func (h *DefaultResponseModeHandler) WriteAuthorizeResponse(ctx context.Context, rw http.ResponseWriter, request AuthorizeRequester, response AuthorizeResponder) {
	header := rw.Header()

	header.Set(consts.HeaderCacheControl, consts.CacheControlNoStore)
	header.Set(consts.HeaderPragma, consts.PragmaNoCache)

	rheader := response.GetHeader()

	for k := range rheader {
		header.Set(k, rheader.Get(k))
	}

	h.handleWriteAuthorizeResponse(ctx, rw, request, response.GetParameters())
}

// WriteAuthorizeError writes authorization errors.
func (h *DefaultResponseModeHandler) WriteAuthorizeError(ctx context.Context, rw http.ResponseWriter, request AuthorizeRequester, e error) {
	rfc := ErrorToRFC6749Error(e).
		WithLegacyFormat(h.Config.GetUseLegacyErrorFormat(ctx)).
		WithExposeDebug(h.Config.GetSendDebugMessagesToClients(ctx)).
		WithLocalizer(h.Config.GetMessageCatalog(ctx), getLangFromRequester(request))

	if !request.IsRedirectURIValid() {
		h.handleWriteAuthorizeErrorFieldResponse(ctx, rw, request, rfc)

		return
	}

	parameters := rfc.ToValues()

	if state := request.GetState(); len(state) != 0 {
		parameters.Set(consts.FormParameterState, state)
	}

	h.handleWriteAuthorizeResponse(ctx, rw, request, parameters)
}

func (h *DefaultResponseModeHandler) handleWriteAuthorizeResponse(ctx context.Context, rw http.ResponseWriter, request AuthorizeRequester, parameters url.Values) {
	uri := *request.GetRedirectURI()
	redirectURI := &uri
	redirectURI.Fragment = ""

	var (
		form     url.Values
		err      error
		location string
	)

	rm := request.GetResponseMode()

	if rm == ResponseModeJWT {
		if request.GetResponseTypes().ExactOne(consts.ResponseTypeAuthorizationCodeFlow) {
			rm = ResponseModeQueryJWT
		} else {
			rm = ResponseModeFragmentJWT
		}
	}

	for _, handler := range h.Config.GetResponseModeParameterHandlers(ctx) {
		if handler.ResponseModes().Has(rm) {
			handler.WriteParameters(ctx, request, parameters)
		}
	}

	setClientIDMetadataDocumentIssuer(ctx, h.Config, request, rm, parameters)

	switch rm {
	case ResponseModeFormPost, ResponseModeFormPostJWT:
		if form, err = h.EncodeResponseForm(ctx, rm, request, parameters); err != nil {
			h.handleWriteAuthorizeErrorFieldResponse(ctx, rw, request, ErrServerError.WithWrap(err).WithDebugError(err))

			return
		}

		rw.Header().Set(consts.HeaderContentType, consts.ContentTypeTextHTML)
		h.Config.GetFormPostResponseWriter(ctx)(rw, GetPostFormHTMLTemplate(ctx, h.Config), redirectURI.String(), form)

		return
	case ResponseModeQuery, ResponseModeDefault, ResponseModeQueryJWT, ResponseModeJWT:
		if rm == ResponseModeQueryJWT && redirectURI.Query().Has(consts.FormParameterResponse) {
			h.handleWriteAuthorizeErrorFieldResponse(ctx, rw, request, ErrInvalidRequest.WithHintf("The 'redirect_uri' must not contain the '%s' query parameter when using the '%s' response mode.", consts.FormParameterResponse, ResponseModeQueryJWT))

			return
		}

		if form, err = h.EncodeResponseForm(ctx, rm, request, parameters); err != nil {
			h.handleWriteAuthorizeErrorFieldResponse(ctx, rw, request, ErrServerError.WithWrap(err).WithDebugError(err))

			return
		}

		for key, values := range redirectURI.Query() {
			for _, value := range values {
				form.Add(key, value)
			}
		}

		redirectURI.RawQuery = form.Encode()

		location = h.guardRedirectFragment(ctx, redirectURI.String())
	case ResponseModeFragment, ResponseModeFragmentJWT:
		if form, err = h.EncodeResponseForm(ctx, rm, request, parameters); err != nil {
			h.handleWriteAuthorizeErrorFieldResponse(ctx, rw, request, ErrServerError.WithWrap(err).WithDebugError(err))

			return
		}

		location = redirectURI.String() + "#" + form.Encode()
	}

	rw.Header().Set(consts.HeaderLocation, location)
	rw.WriteHeader(http.StatusSeeOther)
}

func (h *DefaultResponseModeHandler) guardRedirectFragment(ctx context.Context, location string) string {
	if provider, ok := h.Config.(RedirectFragmentGuardProvider); ok && provider.GetEnableRedirectFragmentGuard(ctx) {
		return location + "#_"
	}

	return location
}

// EncodeResponseForm encodes the response form if necessary.
func (h *DefaultResponseModeHandler) EncodeResponseForm(ctx context.Context, rm ResponseModeType, request AuthorizeRequester, parameters url.Values) (form url.Values, err error) {
	switch rm {
	case ResponseModeFormPostJWT, ResponseModeQueryJWT, ResponseModeFragmentJWT:
		client := request.GetClient()

		jclient, ok := client.(JARMClient)
		if !ok {
			return nil, errorsx.WithStack(ErrServerError.WithDebug("The client is not capable of handling the JWT-Secured Authorization Response Mode."))
		}

		return jarm.EncodeParameters(jarm.Generate(ctx, h.Config, jclient, request.GetSession(), parameters))
	default:
		return parameters, nil
	}
}

func (h *DefaultResponseModeHandler) handleWriteAuthorizeErrorFieldResponse(ctx context.Context, rw http.ResponseWriter, request AuthorizeRequester, rfc *RFC6749Error) {
	if strategy := h.Config.GetAuthorizeErrorFieldResponseStrategy(ctx); strategy != nil {
		strategy.WriteErrorFieldResponse(ctx, rw, request, rfc)
	} else {
		h.handleWriteAuthorizeErrorFieldResponseJSON(ctx, rw, rfc)
	}
}

func (h *DefaultResponseModeHandler) handleWriteAuthorizeErrorFieldResponseJSON(ctx context.Context, rw http.ResponseWriter, rfc *RFC6749Error) {
	rw.Header().Set(consts.HeaderContentType, consts.ContentTypeApplicationJSON)

	var (
		data []byte
		err  error
	)

	if data, err = json.Marshal(rfc); err != nil {
		writeFallbackJSONError(ctx, h.Config, rw, err)

		return
	}

	rw.WriteHeader(rfc.CodeField)
	_, _ = rw.Write(data)
}

// setClientIDMetadataDocumentIssuer sets the RFC 9207 'iss' parameter of an authorization response to a client resolved
// from a Client ID Metadata Document when no ResponseModeParameterHandler set it. A JWT response mode carries the
// issuer in the response JWT instead.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03#section-7
func setClientIDMetadataDocumentIssuer(ctx context.Context, config ResponseModeHandlerConfigurator, request AuthorizeRequester, rm ResponseModeType, parameters url.Values) {
	switch rm {
	case ResponseModeQueryJWT, ResponseModeFragmentJWT, ResponseModeFormPostJWT:
		return
	}

	if parameters.Has(consts.FormParameterIssuer) {
		return
	}

	if cimd, ok := config.(ClientIDMetadataDocumentConfigProvider); !ok || cimd.GetClientIDMetadataDocumentResolver(ctx) == nil {
		return
	}

	if !config.GetAuthorizationServerIdentificationEnabled(ctx) {
		return
	}

	if issuer := config.GetIssuer(ctx); len(issuer) != 0 && jwt.IsClientIDMetadataDocumentClient(request.GetClient()) {
		parameters.Set(consts.FormParameterIssuer, issuer)
	}
}

// RFC9207ResponseModeParameterHandler adds the RFC 9207 'iss' parameter to the authorization response when
// GetAuthorizationServerIdentificationEnabled is true and GetIssuer is not empty.
//
// See: https://datatracker.ietf.org/doc/html/rfc9207#section-2
type RFC9207ResponseModeParameterHandler struct {
	Config interface {
		IssuerProvider
		AuthorizationServerIdentificationProvider
	}
}

// ResponseModes returns the set of response modes the RFC 9207 issuer identification parameter handler applies to:
// query, fragment, form_post, and the implicit default mode.
func (h *RFC9207ResponseModeParameterHandler) ResponseModes() ResponseModeTypes {
	return ResponseModeTypes{
		ResponseModeDefault,
		ResponseModeQuery,
		ResponseModeFragment,
		ResponseModeFormPost,
	}
}

// WriteParameters injects the RFC 9207 'iss' parameter into the authorization response when
// GetAuthorizationServerIdentificationEnabled is true and GetIssuer is not empty.
//
// See: https://datatracker.ietf.org/doc/html/rfc9207#section-2
func (h *RFC9207ResponseModeParameterHandler) WriteParameters(ctx context.Context, request AuthorizeRequester, parameters url.Values) {
	if !h.Config.GetAuthorizationServerIdentificationEnabled(ctx) {
		return
	}

	if issuer := h.Config.GetIssuer(ctx); len(issuer) != 0 {
		parameters.Set(consts.FormParameterIssuer, issuer)
	}
}

// ResponseModeHandler provides a contract for handling response modes.
type ResponseModeHandler interface {
	// ResponseModes returns a set of supported response modes handled
	// by the interface implementation.
	//
	// In an authorize request with any of the provide response modes
	// methods `WriteAuthorizeResponse` and `WriteAuthorizeError` will be
	// invoked to write the successful or error authorization responses respectively.
	ResponseModes() ResponseModeTypes

	// WriteAuthorizeResponse writes successful responses
	//
	// The following headers are expected to be set by implementations of this interface:
	// header.Set(consts.HeaderCacheControl, consts.CacheControlNoStore)
	// header.Set(consts.HeaderPragma, consts.PragmaNoCache)
	WriteAuthorizeResponse(ctx context.Context, rw http.ResponseWriter, request AuthorizeRequester, response AuthorizeResponder)

	// WriteAuthorizeError writes error responses
	//
	// The following headers are expected to be set by implementations of this interface:
	// header.Set(consts.HeaderCacheControl, consts.CacheControlNoStore)
	// header.Set(consts.HeaderPragma, consts.PragmaNoCache)
	WriteAuthorizeError(ctx context.Context, rw http.ResponseWriter, request AuthorizeRequester, err error)

	// ResponseModesSupported returns the response modes the handler currently accepts, which is the set the
	// 'response_mode' parameter is parsed against and the server metadata advertises. It may be narrower than
	// ResponseModes when an accepted mode depends on configuration.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc8414#section-2
	//
	// See: https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#ResponseModes
	ResponseModesSupported(ctx context.Context) (modes ResponseModeTypes)
}

type ResponseModeParameterHandler interface {
	// ResponseModes returns a set of supported response modes handled
	// by the interface implementation.
	//
	// In an authorize request with any of the provide response modes
	// methods `WriteAuthorizeResponse` and `WriteAuthorizeError` will be
	// invoked to write the successful or error authorization responses respectively.
	ResponseModes() ResponseModeTypes

	// WriteParameters is handed the parameters just before handing of to the response writer.
	WriteParameters(ctx context.Context, request AuthorizeRequester, parameters url.Values)
}

type ResponseModeTypes []ResponseModeType

// Has reports whether the slice contains the given response mode.
func (rs ResponseModeTypes) Has(item ResponseModeType) bool {
	return slices.Contains(rs, item)
}

type ResponseModeHandlerConfigurator interface {
	ResponseModeParameterHandlerProvider
	FormPostHTMLTemplateProvider
	FormPostResponseProvider
	IssuerProvider
	AuthorizationServerIdentificationProvider
	JWTSecuredAuthorizeResponseModeStrategyProvider
	JWTSecuredAuthorizeResponseModeLifespanProvider
	MessageCatalogProvider
	SendDebugMessagesToClientsProvider
	AuthorizeErrorFieldResponseStrategyProvider
	UseLegacyErrorFormatProvider
}

var (
	_ ResponseModeHandler = (*DefaultResponseModeHandler)(nil)
)
