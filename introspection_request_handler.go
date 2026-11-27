// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/text/language"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

// NewIntrospectionRequest initiates token introspection.
//
// See: https://datatracker.ietf.org/doc/html/rfc7662#section-2.1
//
//nolint:gocyclo
func (f *Fosite) NewIntrospectionRequest(ctx context.Context, r *http.Request, session Session) (responder IntrospectionResponder, err error) {
	ctx = context.WithValue(ctx, RequestContextKey, r)

	if r.Method != http.MethodPost {
		return &IntrospectionResponse{Active: false}, errorsx.WithStack(ErrInvalidRequest.WithHintf("HTTP method is '%s' but expected 'POST'.", r.Method))
	} else if err := r.ParseForm(); err != nil {
		return &IntrospectionResponse{Active: false}, errorsx.WithStack(ErrInvalidRequest.WithHint("Unable to parse HTTP body, make sure to send a properly formatted form request body.").WithWrap(err).WithDebugError(err))
	} else if len(r.PostForm) == 0 {
		return &IntrospectionResponse{Active: false}, errorsx.WithStack(ErrInvalidRequest.WithHint("The POST body can not be empty."))
	} else if err = ValidateRequestParametersNotRepeated(r.PostForm); err != nil {
		return &IntrospectionResponse{Active: false}, err
	}

	token := r.PostForm.Get(consts.FormParameterToken)
	tokenTypeHint := r.PostForm.Get(consts.FormParameterTokenTypeHint)

	var (
		client Client
		bearer bool
	)

	if client, bearer, err = f.handleNewIntrospectionRequestClientAuthentication(ctx, r, session, token); err != nil {
		return &IntrospectionResponse{Active: false}, err
	}

	// FAPI 2.0 Message Signing Section 6.2: only a resource server may call the introspection endpoint.
	if f.enforcesIntrospectionPermission(ctx) && !isIntrospectionPermitted(client) {
		// RFC 9110 Section 15.5.4: a caller whose valid client credentials are insufficient is answered with 403.
		rfc := ErrAccessDenied

		// RFC 7662 Section 2.3: a bearer token which "does not contain sufficient privileges" is answered as described
		// in RFC 6750 Section 3.
		if bearer {
			rfc = ErrInvalidToken
		}

		return &IntrospectionResponse{Active: false}, errorsx.WithStack(rfc.WithHint("The client is not permitted to call the introspection endpoint.").WithDebugf("The client with id '%s' is not registered as permitted to introspect tokens.", clientID(client)))
	}

	// RFC 7662 Section 2.1 makes 'token' REQUIRED, and RFC 6749 Section 3.1 treats an empty value as omitted. A request
	// without it is not "a properly formed and authorized query" (RFC 7662 Section 2.3), so it is answered with the
	// RFC 6749 Section 5.2 'invalid_request' error rather than an inactive introspection response.
	if token == "" {
		return &IntrospectionResponse{Active: false}, errorsx.WithStack(ErrInvalidRequest.WithHint("The 'token' parameter is required."))
	}

	jwtRequested := acceptsIntrospectionJWT(r)

	use, ar, err := f.IntrospectToken(ctx, token, TokenUse(tokenTypeHint), session, RemoveEmpty(strings.Split(r.PostForm.Get(consts.FormParameterScope), " "))...)
	if err != nil {
		// A failure of the server says nothing about the token, so it is not answered as an inactive token.
		if errors.Is(err, ErrServerError) || isIntrospectorServerFailure(err) {
			return &IntrospectionResponse{Client: client, Active: false, JWTRequested: jwtRequested}, errorsx.WithStack(err)
		}

		inactive := &IntrospectionResponse{Client: client, Active: false, JWTRequested: jwtRequested}

		return inactive, errorsx.WithStack(&inactiveIntrospectionError{responder: inactive, error: ErrInactiveToken.WithHint("An introspection strategy indicated that the token is inactive.").WithWrap(err).WithDebugError(err)})
	}

	// RFC 7662 Sections 2.3 and 4: a client learns only about the tokens issued to it, and a resource server only about
	// those it is an audience of.
	if !isIntrospectionTokenVisible(client, ar) {
		inactive := &IntrospectionResponse{Client: client, Active: false, JWTRequested: jwtRequested}

		return inactive, errorsx.WithStack(&inactiveIntrospectionError{responder: inactive, error: ErrInactiveToken.WithHint("The token was neither issued to nor intended for the client making the introspection request.")})
	}

	accessTokenType := ""

	if use == AccessToken {
		// RFC 9449 Section 6.2: 'token_type' is DPoP for a DPoP-bound token. It is derived from the same session
		// ApplyConfirmation reads for 'cnf' (see WriteIntrospectionResponse) and gated on DPoP being enabled, so the
		// two agree. A certificate-bound token remains 'bearer'.
		accessTokenType = BearerAccessToken

		if bound, ok := ar.GetSession().(DPoPBoundSession); ok && bound.GetDPoPJWKThumbprint() != "" && f.Config.GetDPoPEnabled(ctx) {
			accessTokenType = DPoPAccessToken
		}
	}

	return &IntrospectionResponse{
		Client:          client,
		Active:          true,
		AccessRequester: ar,
		TokenUse:        use,
		AccessTokenType: accessTokenType,
		JWTRequested:    jwtRequested,
	}, nil
}

func (f *Fosite) enforcesIntrospectionPermission(ctx context.Context) bool {
	provider, ok := f.Config.(IntrospectionPermissionProvider)

	return ok && provider.GetEnforceIntrospectionPermission(ctx)
}

func isIntrospectionPermitted(client Client) bool {
	c, ok := client.(IntrospectionClient)

	return ok && c.GetIntrospectionPermitted()
}

func isIntrospectionTokenVisible(client Client, token Requester) bool {
	c, ok := client.(IntrospectionClient)
	if !ok {
		return true
	}

	if !c.GetIntrospectionPermitted() {
		owner := token.GetClient()

		return owner != nil && owner.GetID() != "" && owner.GetID() == c.GetID()
	}

	served := c.GetIntrospectionAudience()
	if served == nil {
		served = []string{c.GetID()}
	}

	return slices.ContainsFunc(JoinGrantedAudienceAndResource(token.GetGrantedAudience(), token.GetGrantedResource()), func(value string) bool { return slices.Contains(served, value) })
}

func isIntrospectorServerFailure(err error) bool {
	rfc, ok := errors.AsType[*RFC6749Error](err)

	return ok && rfc.ErrorField != errUnknownErrorName && rfc.CodeField >= http.StatusInternalServerError
}

func clientID(client Client) string {
	if client == nil {
		return ""
	}

	return client.GetID()
}

type inactiveIntrospectionError struct {
	error

	responder IntrospectionResponder
}

func (e *inactiveIntrospectionError) Unwrap() error {
	return e.error
}

func acceptsIntrospectionJWT(r *http.Request) bool {
	for _, header := range r.Header.Values(consts.HeaderAccept) {
		for value := range strings.SplitSeq(header, ",") {
			mediaType, parameters, err := mime.ParseMediaType(value)
			if err == nil && mediaType == "application/"+consts.JSONWebTokenTypeTokenIntrospection && !isZeroQuality(parameters["q"]) {
				return true
			}
		}
	}

	return false
}

func isZeroQuality(value string) bool {
	quality, err := strconv.ParseFloat(value, 64)

	return err == nil && quality == 0
}

// handleNewIntrospectionRequestClientAuthentication authenticates the caller, by the bearer credential in the
// Authorization header when one is present and by client authentication otherwise. Client authentication is never
// attempted once a credential is found, and a request presenting none is rejected when
// GetIntrospectionEndpointClientAuthDisabled is set. A token presented using the DPoP scheme while DPoP is disabled is
// not a credential.
//
// The binding, scope and audience checks of ValidateBearerAuthorization apply to the credential in the Authorization
// header only, never to the token being introspected.
//
// See: https://www.rfc-editor.org/rfc/rfc7662#section-2.1
// See: https://www.rfc-editor.org/rfc/rfc9449#section-6.2
//
//nolint:gocyclo
func (f *Fosite) handleNewIntrospectionRequestClientAuthentication(ctx context.Context, r *http.Request, session Session, token string) (client Client, bearer bool, err error) {
	var clientToken, method string

	if clientToken, method, err = f.accessTokenCredentialFromRequest(ctx, r); err != nil {
		return nil, false, err
	}

	if clientToken != "" {
		if types := f.Config.GetIntrospectionEndpointAuthMethods(ctx); len(types) != 0 {
			// RFC 7662 Section 2.3: a bearer token which is "otherwise invalid for this request" is answered as
			// described in RFC 6750 Section 3.
			//
			// See: https://www.rfc-editor.org/rfc/rfc8414#section-2
			if !slices.Contains(types, method) {
				return nil, true, errorsx.WithStack(ErrInvalidToken.WithHint(fmt.Sprintf("The introspection endpoint does not permit authentication using the access token type '%s'.", method)))
			}
		}

		if token == clientToken {
			return nil, true, errorsx.WithStack(ErrInvalidToken.WithHint("Bearer and introspection token are identical."))
		}

		var (
			ar  AccessRequester
			use TokenUse
		)

		// Both failures below report the same code and hint. RFC 6750 Section 3.1 defines 'invalid_token' as
		// covering "expired, revoked, malformed, or invalid for other reasons", so an unresolvable credential and
		// one of the wrong kind stay indistinguishable on the wire; the distinction goes in the debug field, which
		// only a deployment that opts in surfaces.
		switch use, ar, err = f.IntrospectToken(ctx, clientToken, AccessToken, session.Clone()); {
		case errors.Is(err, ErrServerError), isIntrospectorServerFailure(err):
			return nil, true, err
		case err != nil:
			return nil, true, errorsx.WithStack(ErrInvalidToken.WithHint("HTTP Authorization header missing, malformed, or credentials used are invalid.").WithWrap(err).WithDebugError(err))
		case use != "" && use != AccessToken:
			return nil, true, errorsx.WithStack(ErrInvalidToken.WithHint("HTTP Authorization header missing, malformed, or credentials used are invalid.").WithDebugf("The HTTP Authorization header did not provide a token of type 'access_token', got type '%s'.", use))
		}

		urls := f.Config.GetEndpointURLs(ctx)

		// The audience falls back from the configured list to the introspection endpoint URL and its mutual TLS alias,
		// then to RequestURL. GetIssuer is the 'iss' claim of JWT introspection responses, not this endpoint's URL.
		if err = ValidateBearerAuthorization(ctx, f.Config, r, ar, clientToken, BearerAuthorization{
			Audiences: f.Config.GetAllowedIntrospectionAudiences(ctx),
			Endpoints: urls.URLs(EndpointIntrospection),
			Scopes:    f.Config.GetAllowedIntrospectionScopes(ctx),
		}); err != nil {
			return nil, true, err
		}

		// The permission and audience checks apply to the caller's current registration, not the one recorded when the
		// credential was issued. A credential issued without client authentication has no registration.
		if client = ar.GetClient(); client != nil && client.GetID() != "" {
			id := client.GetID()

			// RFC 7662 Section 2.3: a bearer token which is "otherwise invalid for this request" is answered as
			// described in RFC 6750 Section 3.
			if client, err = GetClient(ctx, f.Config, f.Store, id); err != nil {
				if failure, ok := requestServerFailure(err); ok {
					return nil, true, failure
				}

				return nil, true, errorsx.WithStack(ErrInvalidToken.WithHint("The client which the credential was issued to is not registered.").WithWrap(err).WithDebugf("The client with id '%s' could not be found.", id))
			}
		}

		return client, true, nil
	} else if f.Config.GetIntrospectionEndpointClientAuthDisabled(ctx) {
		// ErrInvalidToken rather than ErrRequestUnauthorized, so that WriteIntrospectionError answers with the RFC 6750
		// Section 3 'WWW-Authenticate' challenge.
		return nil, false, errorsx.WithStack(ErrInvalidToken.WithHint("The request did not include an Access Token to authorize the call, and client authentication is disabled at this endpoint."))
	} else if client, _, err = f.AuthenticateClientWithAuthHandler(ctx, r, r.PostForm, f.Config.GetIntrospectionEndpointClientAuthStrategy(ctx)); err != nil {
		return nil, false, f.introspectionClientAuthenticationError(ctx, r, err)
	}

	return client, false, nil
}

func (f *Fosite) introspectionClientAuthenticationError(ctx context.Context, r *http.Request, err error) error {
	if errors.Is(err, ErrInvalidClient) {
		return err
	}

	if failure, ok := requestServerFailure(err); ok {
		return failure
	}

	if rfc := ErrorToRFC6749Error(err); rfc.ErrorField == errInvalidRequestName {
		return err
	}

	// RFC 7662 Section 2.3: invalid client credentials are answered as described in RFC 6749 Section 5.2, which is
	// 'invalid_client' with a 'WWW-Authenticate' challenge when the client used the Authorization header.
	return withClientAuthenticationChallenge(r, errorsx.WithStack(ErrInvalidClient.WithHint("The request either did not include a known client authentication method, or contained invalid authentication details.").WithWrap(err).WithDebugError(err)), f.Config.GetClientAuthenticationRealm(ctx))
}

func (f *Fosite) accessTokenCredentialFromRequest(ctx context.Context, r *http.Request) (token, method string, err error) {
	return introspectionCredentialFromRequest(r, f.Config.GetAccessTokenURIQueryParameterEnabled(ctx), f.Config.GetDPoPEnabled(ctx))
}

// introspectionCredentialFromRequest extracts the access token presented to authenticate a request to the introspection
// endpoint, accepting the RFC 9449 DPoP scheme in addition to the schemes AccessTokenFromRequest understands when dpop
// is set. Otherwise a DPoP scheme header is not a token transport, and is treated as any other unrecognized scheme. The
// proof is checked by ValidateBearerAuthorization.
//
// The method is the authentication scheme which carried the token: DPoP for the DPoP scheme, and Bearer for the Bearer
// scheme and the 'access_token' parameter. It is empty when no token was presented.
//
// See: https://www.rfc-editor.org/rfc/rfc6750#section-2
// See: https://www.rfc-editor.org/rfc/rfc9449#section-7.1
func introspectionCredentialFromRequest(r *http.Request, query, dpop bool) (token, method string, err error) {
	var scheme, value string

	// See: https://www.rfc-editor.org/rfc/rfc6749#section-3.1
	if len(r.Form[consts.FormParameterAccessToken]) > 1 {
		return "", "", errorsx.WithStack(ErrInvalidRequest.WithHint("The 'access_token' parameter was included more than once."))
	}

	if scheme, value, err = AuthorizationCredentialFromRequest(r); err != nil {
		return "", "", err
	}

	// RFC 6750 Section 2 and Section 3.1: a token in both the header and the 'access_token' parameter is
	// 'invalid_request'. A 'Basic' header is client authentication rather than a token transport, so it may accompany
	// the parameter. The parameter is read off r.Form, which carries the URI query alongside the form body, so a token in
	// the URI query is rejected alongside one in the header even when it would otherwise be ignored.
	if len(value) != 0 && (strings.EqualFold(scheme, BearerAccessToken) || dpop && strings.EqualFold(scheme, DPoPAccessToken)) && r.Form.Get(consts.FormParameterAccessToken) != "" {
		return "", "", errorsx.WithStack(ErrInvalidRequest.WithHint("Multiple methods used to include access token."))
	}

	if dpop && strings.EqualFold(scheme, DPoPAccessToken) {
		if value == "" {
			return "", "", nil
		}

		return value, consts.AuthSchemeDPoP, nil
	}

	if token = AccessTokenFromRequest(r, WithAccessTokenURIQueryParameter(query)); token == "" {
		return "", "", nil
	}

	return token, consts.AuthSchemeBearer, nil
}

// IntrospectionResponse is the result of introspecting a token.
type IntrospectionResponse struct {
	Client          Client          `json:"-"`
	Active          bool            `json:"active"`
	AccessRequester AccessRequester `json:"extra"`
	TokenUse        TokenUse        `json:"token_use,omitempty"`
	AccessTokenType string          `json:"token_type,omitempty"`
	Lang            language.Tag    `json:"-"`

	// JWTRequested records that the caller asked for a JWT response with the 'Accept' header.
	//
	// See: https://www.rfc-editor.org/rfc/rfc9701#section-4
	JWTRequested bool `json:"-"`
}

// IsJWTRequested returns whether the caller asked for a JWT response with the 'Accept' header.
func (r *IntrospectionResponse) IsJWTRequested() bool {
	return r.JWTRequested
}

// IsActive returns whether the introspected token is currently active per RFC 7662 section 2.2.
func (r *IntrospectionResponse) IsActive() bool {
	return r.Active
}

// GetClient returns the client related to the introspected token.
func (r *IntrospectionResponse) GetClient() Client {
	return r.Client
}

// GetAccessRequester returns the AccessRequester reconstituted from the introspected token, including its session,
// client, scopes, and audience.
func (r *IntrospectionResponse) GetAccessRequester() AccessRequester {
	return r.AccessRequester
}

// GetTokenUse returns the kind of token that was introspected (access, refresh, etc.).
func (r *IntrospectionResponse) GetTokenUse() TokenUse {
	return r.TokenUse
}

// GetAccessTokenType returns the token_type value of the introspected token, where applicable.
func (r *IntrospectionResponse) GetAccessTokenType() string {
	return r.AccessTokenType
}

// ToMap returns the RFC 7662 introspection response as a map alongside the token's audience. When the token is inactive
// or the receiver is nil, only the 'active' claim is populated.
func (r *IntrospectionResponse) ToMap() (audience []string, introspection map[string]any) {
	introspection = map[string]any{
		consts.ClaimActive: false,
	}

	if r == nil {
		return nil, introspection
	}

	if r.IsActive() {
		introspection[consts.ClaimActive] = true

		ar := r.GetAccessRequester()

		if ar == nil {
			return
		}

		var (
			ok  bool
			aud Arguments
		)

		if client := ar.GetClient(); client != nil {
			if id := client.GetID(); id != "" {
				introspection[consts.ClaimClientIdentifier] = id
			}
		}

		if scope := ar.GetGrantedScopes(); len(scope) > 0 {
			introspection[consts.ClaimScope] = strings.Join(scope, " ")
		}

		if _, ok = introspection[consts.ClaimIssuedAt]; !ok {
			if rat := ar.GetRequestedAt(); !rat.IsZero() {
				introspection[consts.ClaimIssuedAt] = rat.Unix()
			}
		}

		if aud = JoinGrantedAudienceAndResource(ar.GetGrantedAudience(), ar.GetGrantedResource()); len(aud) > 0 {
			introspection[consts.ClaimAudience] = []string(aud)
		}
	}

	if r.GetClient() == nil {
		return nil, introspection
	}

	return []string{r.GetClient().GetID()}, introspection
}
