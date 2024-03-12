// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/errorsx"
	"authelia.com/provider/oauth2/token/jarm"
)

type DefaultResponseModeHandler struct {
	Config ResponseModeHandlerConfigurator
}

var (
	_ ResponseModeHandler = (*DefaultResponseModeHandler)(nil)
)

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

// WriteAuthorizeResponse writes authorization responses.
func (h *DefaultResponseModeHandler) WriteAuthorizeResponse(ctx context.Context, rw http.ResponseWriter, requester AuthorizeRequester, responder AuthorizeResponder) {
	header := rw.Header()

	header.Set(consts.HeaderCacheControl, consts.CacheControlNoStore)
	header.Set(consts.HeaderPragma, consts.PragmaNoCache)

	rheader := responder.GetHeader()

	for k := range rheader {
		header.Set(k, rheader.Get(k))
	}

	h.handleWriteAuthorizeResponse(ctx, rw, requester, responder.GetParameters())
}

// WriteAuthorizeError writes authorization errors.
func (h *DefaultResponseModeHandler) WriteAuthorizeError(ctx context.Context, rw http.ResponseWriter, requester AuthorizeRequester, e error) {
	rfc := ErrorToRFC6749Error(e).
		WithLegacyFormat(h.Config.GetUseLegacyErrorFormat(ctx)).
		WithExposeDebug(h.Config.GetSendDebugMessagesToClients(ctx)).
		WithLocalizer(h.Config.GetMessageCatalog(ctx), getLangFromRequester(requester))

	if !requester.IsRedirectURIValid() {
		h.handleWriteAuthorizeErrorJSON(ctx, rw, rfc)

		return
	}

	parameters := rfc.ToValues()

	if state := requester.GetState(); len(state) != 0 {
		parameters.Set(consts.FormParameterState, state)
	}

	h.handleWriteAuthorizeResponse(ctx, rw, requester, parameters)
}

func (h *DefaultResponseModeHandler) handleWriteAuthorizeResponse(ctx context.Context, rw http.ResponseWriter, requester AuthorizeRequester, parameters url.Values) {
	redirectURI := requester.GetRedirectURI()
	redirectURI.Fragment = ""

	var (
		form     url.Values
		err      error
		location string
	)

	rm := requester.GetResponseMode()

	switch rm {
	case ResponseModeJWT:
		if requester.GetResponseTypes().ExactOne(consts.ResponseTypeAuthorizationCodeFlow) {
			rm = ResponseModeQueryJWT
		} else {
			rm = ResponseModeFragmentJWT
		}
	case ResponseModeFormPost, ResponseModeQuery, ResponseModeFragment, ResponseModeDefault:
		// RFC9207 OAuth 2.0 Authorization Server Issuer Identification.
		// See Also: https://datatracker.ietf.org/doc/html/rfc9207.
		if issuer := h.Config.GetAuthorizationServerIdentificationIssuer(ctx); len(issuer) != 0 {
			parameters.Set(consts.FormParameterIssuer, issuer)
		}
	}

	switch rm {
	case ResponseModeFormPost, ResponseModeFormPostJWT:
		if form, err = h.EncodeResponseForm(ctx, rm, requester, parameters); err != nil {
			h.handleWriteAuthorizeErrorJSON(ctx, rw, ErrServerError.WithWrap(err).WithDebugError(err))

			return
		}

		rw.Header().Set(consts.HeaderContentType, consts.ContentTypeTextHTML)
		h.Config.GetFormPostResponseWriter(ctx)(rw, GetPostFormHTMLTemplate(ctx, h.Config), redirectURI.String(), form)

		return
	case ResponseModeQuery, ResponseModeDefault, ResponseModeQueryJWT, ResponseModeJWT:
		for key, values := range redirectURI.Query() {
			for _, value := range values {
				parameters.Add(key, value)
			}
		}

		if form, err = h.EncodeResponseForm(ctx, rm, requester, parameters); err != nil {
			h.handleWriteAuthorizeErrorJSON(ctx, rw, ErrServerError.WithWrap(err).WithDebugError(err))

			return
		}

		redirectURI.RawQuery = form.Encode()

		location = redirectURI.String()
	case ResponseModeFragment, ResponseModeFragmentJWT:
		if form, err = h.EncodeResponseForm(ctx, rm, requester, parameters); err != nil {
			h.handleWriteAuthorizeErrorJSON(ctx, rw, ErrServerError.WithWrap(err).WithDebugError(err))

			return
		}

		location = redirectURI.String() + "#" + form.Encode()
	}

	rw.Header().Set(consts.HeaderLocation, location)
	rw.WriteHeader(http.StatusSeeOther)
}

// EncodeResponseForm encodes the response form if necessary.
func (h *DefaultResponseModeHandler) EncodeResponseForm(ctx context.Context, rm ResponseModeType, requester AuthorizeRequester, parameters url.Values) (form url.Values, err error) {
	switch rm {
	case ResponseModeFormPostJWT, ResponseModeQueryJWT, ResponseModeFragmentJWT:
		client := requester.GetClient()

		jclient, ok := client.(JARMClient)
		if !ok {
			return nil, errorsx.WithStack(ErrServerError.WithDebug("The client is not capable of handling the JWT-Secured Authorization Response Mode."))
		}

		return jarm.EncodeParameters(jarm.Generate(ctx, h.Config, jclient, requester.GetSession(), parameters))
	default:
		return parameters, nil
	}
}

func (h *DefaultResponseModeHandler) handleWriteAuthorizeErrorJSON(ctx context.Context, rw http.ResponseWriter, rfc *RFC6749Error) {
	rw.Header().Set(consts.HeaderContentType, consts.ContentTypeApplicationJSON)

	var (
		data []byte
		err  error
	)

	if data, err = json.Marshal(rfc); err != nil {
		if h.Config.GetSendDebugMessagesToClients(ctx) {
			errorMessage := EscapeJSONString(err.Error())
			http.Error(rw, fmt.Sprintf(`{"error":"server_error","error_description":"%s"}`, errorMessage), http.StatusInternalServerError)
		} else {
			http.Error(rw, `{"error":"server_error"}`, http.StatusInternalServerError)
		}

		return
	}

	rw.WriteHeader(rfc.CodeField)
	_, _ = rw.Write(data)
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
	WriteAuthorizeResponse(ctx context.Context, rw http.ResponseWriter, requester AuthorizeRequester, responder AuthorizeResponder)

	// WriteAuthorizeError writes error responses
	//
	// The following headers are expected to be set by implementations of this interface:
	// header.Set(consts.HeaderCacheControl, consts.CacheControlNoStore)
	// header.Set(consts.HeaderPragma, consts.PragmaNoCache)
	WriteAuthorizeError(ctx context.Context, rw http.ResponseWriter, requester AuthorizeRequester, err error)
}

type ResponseModeTypes []ResponseModeType

func (rs ResponseModeTypes) Has(item ResponseModeType) bool {
	for _, r := range rs {
		if r == item {
			return true
		}
	}
	return false
}

type ResponseModeHandlerConfigurator interface {
	FormPostHTMLTemplateProvider
	FormPostResponseProvider
	JWTSecuredAuthorizeResponseModeIssuerProvider
	JWTSecuredAuthorizeResponseModeSignerProvider
	JWTSecuredAuthorizeResponseModeLifespanProvider
	MessageCatalogProvider
	SendDebugMessagesToClientsProvider
	AuthorizationServerIssuerIdentificationProvider
	UseLegacyErrorFormatProvider
}
