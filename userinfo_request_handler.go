// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"net/http"
	"strings"

	"authelia.com/provider/oauth2/i18n"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

// NewUserinfoRequest parses and validates a request to the OpenID Connect UserInfo endpoint, resolving the Access Token
// presented and the current registration of the client it was issued to. The caller produces the claims and writes
// them with WriteUserinfoResponse, or writes the error with WriteUserinfoError. The returned requester is never nil.
//
// A request using a method other than GET or POST is answered with HTTP 405 and an 'Allow' header naming both.
//
// The Access Token is read as described by RFC 6750 Section 2, or using the DPoP scheme when DPoP is enabled. It is
// always resolved from storage, never by stateless introspection, so a revoked token is rejected. It must be an Access
// Token granted the 'openid' scope, any DPoP or mutual TLS binding it carries must be satisfied, and when it was
// granted RFC 8707 resource indicators one of them must be the UserInfo endpoint or the issuer. A DPoP proof is
// validated with the policy of the current registration. A token bound to
// neither a DPoP key nor a client certificate is rejected when sender-constrained access tokens are enforced by the
// configuration or for the client, as they are for a client held to the FAPI 2.0 Security Profile.
//
// The session passed in must implement DPoPBoundSession and MTLSBoundSession, otherwise a bound token looks unbound and
// its binding is not enforced.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#UserInfoRequest
// See: https://www.rfc-editor.org/rfc/rfc6750#section-2
// See: https://www.rfc-editor.org/rfc/rfc9449#section-7
// See: https://www.rfc-editor.org/rfc/rfc9110#section-15.5.6
// See: https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.3.4
func (f *Fosite) NewUserinfoRequest(ctx context.Context, r *http.Request, session Session) (requester UserinfoRequester, err error) {
	request := &UserinfoRequest{
		Lang:    i18n.GetLangFromRequest(f.Config.GetMessageCatalog(ctx), r),
		request: r,
	}

	ctx = context.WithValue(ctx, RequestContextKey, r)
	ctx = context.WithValue(ctx, SkipStatelessIntrospectionContextKey, true)

	switch r.Method {
	case http.MethodGet, http.MethodPost:
		break
	default:
		// See: https://www.rfc-editor.org/rfc/rfc9110#section-15.5.6
		return request, errorsx.WithStack(ErrInvalidRequest.WithHintf("HTTP method is '%s', expected 'GET' or 'POST'.", r.Method).WithCode(http.StatusMethodNotAllowed).withAllow(http.MethodGet, http.MethodPost))
	}

	if err = r.ParseForm(); err != nil {
		return request, errorsx.WithStack(ErrInvalidRequest.WithHint("Unable to parse HTTP body, make sure to send a properly formatted form request body.").WithWrap(err).WithDebugError(err))
	}

	var token string

	if token, _, err = f.accessTokenCredentialFromRequest(ctx, r); err != nil {
		return request, err
	}

	if token == "" {
		return request, errorsx.WithStack(ErrInvalidToken.WithHint("The request did not include an Access Token."))
	}

	var (
		use TokenUse
		ar  AccessRequester
	)

	if use, ar, err = f.IntrospectToken(ctx, token, AccessToken, session); err != nil {
		if failure, ok := requestServerFailure(err); ok {
			return request, failure
		}

		return request, errorsx.WithStack(ErrInvalidToken.WithHint("The Access Token is missing, malformed, or invalid.").WithWrap(err).WithDebugError(err))
	} else if use != "" && use != AccessToken {
		return request, errorsx.WithStack(ErrInvalidToken.WithHint("The Access Token is missing, malformed, or invalid.").WithDebugf("The credential was of type '%s' rather than 'access_token'.", use))
	}

	var client Client

	if client, err = f.userinfoClient(ctx, ar); err != nil {
		return request, err
	}

	urls := f.Config.GetEndpointURLs(ctx).URLs(EndpointUserInfo)

	if err = validateBearerProofOfPossession(ctx, f.Config, r, ar, client, token, urls); err != nil {
		return request, err
	}

	// See: https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
	if err = validateBearerScope(ar, []string{consts.ScopeOpenID}); err != nil {
		return request, err
	}

	if err = f.validateUserinfoResource(ctx, ar, urls); err != nil {
		return request, err
	}

	request.AccessRequester = ar
	request.Client = client

	return request, nil
}

// userinfoClient returns the current registration of the client the Access Token was issued to.
func (f *Fosite) userinfoClient(ctx context.Context, requester AccessRequester) (client Client, err error) {
	if client, err = resolveBearerClient(ctx, f.Config, f.Store, requester); err != nil {
		return nil, err
	}

	if client == nil {
		return nil, errorsx.WithStack(ErrInvalidToken.WithHint("The Access Token is missing, malformed, or invalid.").WithDebug("The credential does not identify a client."))
	}

	return client, nil
}

// requestServerFailure reports whether err is a failure of the server rather than a rejection of the request, so it is
// not answered as an invalid credential. An error that is not an RFC6749Error is reported as ErrServerError.
func requestServerFailure(err error) (failure error, ok bool) {
	rfc := ErrorToRFC6749Error(err)

	switch {
	case rfc.ErrorField == errUnknownErrorName:
		return errorsx.WithStack(ErrServerError.WithWrap(err).WithDebugError(err)), true
	case rfc.StatusCode() >= http.StatusInternalServerError:
		return err, true
	default:
		return nil, false
	}
}

// validateUserinfoResource rejects an Access Token whose granted RFC 8707 resource indicators do not include the
// UserInfo endpoint or the issuer. An Access Token granted no resource indicators is accepted, as OpenID Connect does
// not define the audience of the Access Token presented to the UserInfo endpoint.
//
// See: https://www.rfc-editor.org/rfc/rfc8707#section-2
func (f *Fosite) validateUserinfoResource(ctx context.Context, requester AccessRequester, urls []string) (err error) {
	granted := requester.GetGrantedResource()

	if len(granted) == 0 {
		return nil
	}

	permitted := urls

	if issuer := f.Config.GetIssuer(ctx); issuer != "" {
		permitted = append(permitted, issuer)
	}

	if granted.HasOneOf(permitted...) {
		return nil
	}

	return errorsx.WithStack(ErrInvalidToken.
		WithHint("The credential used to authenticate the request does not have an audience which is permitted at this endpoint.").
		WithDebugf("The credential was expected to have a resource matching one of the values '%s' but the resource had the values '%s'.", strings.Join(permitted, "', '"), strings.Join(granted, "', '")))
}
