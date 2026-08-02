// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

// NewRPInitiatedLogoutRequest parses and validates a request to the OpenID Connect end session endpoint.
//
// It resolves the client from the 'client_id' parameter, the 'id_token_hint' parameter, or both; validates the
// 'id_token_hint' when present, permitting it to be expired; and validates 'post_logout_redirect_uri' against the
// client's registered post logout redirect URIs.
//
// It does not authenticate the client: the end session endpoint is a front channel endpoint reached via the user
// agent. It does not end any session and does not write a response; the caller decides whether to confirm the logout
// with the End-User, terminates its own session, and redirects.
//
// On any error the returned requester's post logout redirect URI is nil, so an error can never be redirected to an
// unvalidated URI.
//
// See: https://openid.net/specs/openid-connect-rpinitiated-1_0.html
func (f *Fosite) NewRPInitiatedLogoutRequest(ctx context.Context, r *http.Request) (requester RPInitiatedLogoutRequester, err error) {
	request := NewRPInitiatedLogoutRequest()

	switch r.Method {
	case http.MethodGet, http.MethodPost:
		break
	default:
		return request, errorsx.WithStack(ErrInvalidRequest.WithHintf("HTTP method is '%s', expected 'GET' or 'POST'.", r.Method))
	}

	ctx = context.WithValue(ctx, RequestContextKey, r)

	if err = r.ParseMultipartForm(1 << 20); err != nil && err != http.ErrNotMultipart {
		return request, errorsx.WithStack(ErrInvalidRequest.WithHint("Unable to parse HTTP body, make sure to send a properly formatted form request body.").WithWrap(err).WithDebugError(err))
	}

	request.Form = r.Form
	request.IDTokenHint = r.Form.Get(consts.FormParameterIDTokenHint)
	request.LogoutHint = r.Form.Get(consts.FormParameterLogoutHint)
	request.State = r.Form.Get(consts.FormParameterState)
	request.UILocales = RemoveEmpty(strings.Split(r.Form.Get(consts.FormParameterUILocales), " "))

	if err = f.resolveRPInitiatedLogoutClient(ctx, request); err != nil {
		return NewRPInitiatedLogoutRequest(), err
	}

	if err = f.validateRPInitiatedLogoutIDTokenHint(ctx, request); err != nil {
		return NewRPInitiatedLogoutRequest(), err
	}

	if err = f.validateRPInitiatedLogoutRedirectURI(request); err != nil {
		return NewRPInitiatedLogoutRequest(), err
	}

	return request, nil
}

// resolveRPInitiatedLogoutClient resolves the client from the 'client_id' parameter or, failing that, from the
// unverified 'id_token_hint'. A request with neither resolves to no client, which is not an error.
func (f *Fosite) resolveRPInitiatedLogoutClient(ctx context.Context, request *RPInitiatedLogoutRequest) (err error) {
	clientID := request.Form.Get(consts.FormParameterClientID)

	if clientID == "" {
		if request.IDTokenHint == "" {
			return nil
		}

		// As no client_id was provided derive one from the hint. This parse is UNVERIFIED and its claims are discarded;
		// they exist only to discover which client's keys to verify against below.
		if clientID, err = f.unsafeRPInitiatedLogoutClientID(ctx, request.IDTokenHint); err != nil {
			return err
		}
	}

	var client Client

	if client, err = f.Store.GetClient(ctx, clientID); err != nil {
		return errorsx.WithStack(ErrInvalidClient.WithHint("The provided 'client_id' is unknown.").WithWrap(err).WithDebugError(err))
	}

	request.Client = client

	return nil
}

// unsafeRPInitiatedLogoutClientID reads a client identifier from an unverified ID Token, preferring 'azp' and falling
// back to 'aud' when it holds exactly one value.
func (f *Fosite) unsafeRPInitiatedLogoutClientID(ctx context.Context, hint string) (clientID string, err error) {
	strategy := f.Config.GetIDTokenValidationStrategy(ctx)

	if strategy == nil {
		return "", errorsx.WithStack(ErrServerError.WithDebug("Failed to validate the 'id_token_hint' because the ID Token validation strategy is not configured."))
	}

	var claims jwt.MapClaims

	if claims, err = strategy.ValidateIDToken(ctx, nil, hint, WithAllowUnverified()); err != nil {
		return "", errorsx.WithStack(ErrInvalidRequest.WithHint("The 'id_token_hint' could not be decoded.").WithWrap(err).WithDebugError(err))
	}

	if azp, ok := claims[consts.ClaimAuthorizedParty].(string); ok && azp != "" {
		return azp, nil
	}

	var aud jwt.ClaimStrings

	if aud, err = claims.GetAudience(); err != nil || len(aud) != 1 {
		return "", errorsx.WithStack(ErrInvalidRequest.WithHint("The 'id_token_hint' does not identify a single client. Provide the 'client_id' parameter."))
	}

	return aud[0], nil
}

// validateRPInitiatedLogoutIDTokenHint verifies the 'id_token_hint' signature and applies the claim policy. The
// expiration check is deliberately disabled: the hint identifies the session the Relying Party is asking to end and
// is expected to be expired.
func (f *Fosite) validateRPInitiatedLogoutIDTokenHint(ctx context.Context, request *RPInitiatedLogoutRequest) (err error) {
	if request.IDTokenHint == "" {
		return nil
	}

	strategy := f.Config.GetIDTokenValidationStrategy(ctx)

	if strategy == nil {
		return errorsx.WithStack(ErrServerError.WithDebug("Failed to validate the 'id_token_hint' because the ID Token validation strategy is not configured."))
	}

	var claims jwt.MapClaims

	if claims, err = strategy.ValidateIDToken(ctx, &Request{Client: request.Client}, request.IDTokenHint, WithAllowExpired()); err != nil {
		return errorsx.WithStack(ErrInvalidRequest.WithHint("The 'id_token_hint' could not be validated.").WithWrap(err).WithDebugError(err))
	}

	issuer := ""

	if config, ok := f.Config.(IDTokenIssuerProvider); ok {
		issuer = config.GetIDTokenIssuer(ctx)
	}

	clientID := request.Client.GetID()

	if err = claims.Valid(
		jwt.ValidateIgnoreExpiration(),
		jwt.ValidateIssuer(issuer),
		jwt.ValidateAudienceAny(clientID),
	); err != nil {
		return errorsx.WithStack(ErrInvalidRequest.WithHint("The 'id_token_hint' claims could not be validated.").WithWrap(err).WithDebugError(err))
	}

	if azp, ok := claims[consts.ClaimAuthorizedParty].(string); ok && azp != "" && azp != clientID {
		return errorsx.WithStack(ErrInvalidRequest.WithHint("The 'id_token_hint' was not issued to the requesting client."))
	}

	if sub, ok := claims[consts.ClaimSubject].(string); !ok || sub == "" {
		return errorsx.WithStack(ErrInvalidRequest.WithHint("The 'id_token_hint' is missing the 'sub' claim."))
	}

	request.IDTokenHintClaims = claims

	return nil
}

// validateRPInitiatedLogoutRedirectURI matches the 'post_logout_redirect_uri' parameter against the client's
// registered post logout redirect URIs, using the exact string comparison the authorization endpoint uses for
// 'redirect_uri'.
func (f *Fosite) validateRPInitiatedLogoutRedirectURI(request *RPInitiatedLogoutRequest) (err error) {
	raw := request.Form.Get(consts.FormParameterPostLogoutRedirectURI)

	if raw == "" {
		return nil
	}

	if request.Client == nil {
		return errorsx.WithStack(ErrInvalidRequest.WithHint("The 'post_logout_redirect_uri' parameter requires either the 'client_id' or 'id_token_hint' parameter."))
	}

	client, ok := request.Client.(RPInitiatedLogoutClient)
	if !ok {
		return errorsx.WithStack(ErrInvalidRequest.WithHint("The OAuth 2.0 Client does not have any registered post logout redirect URIs."))
	}

	if !StringInSlice(raw, client.GetPostLogoutRedirectURIs()) {
		return errorsx.WithStack(ErrInvalidRequest.WithHint("The 'post_logout_redirect_uri' parameter does not match any registered post logout redirect URI."))
	}

	var uri *url.URL

	if uri, err = url.Parse(raw); err != nil {
		return errorsx.WithStack(ErrInvalidRequest.WithHint("The 'post_logout_redirect_uri' parameter is not a valid URI.").WithWrap(err).WithDebugError(err))
	}

	request.PostLogoutRedirectURI = uri

	return nil
}
