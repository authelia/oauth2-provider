// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"net/http"
	"strings"

	"golang.org/x/text/language"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

// NewIntrospectionRequest initiates token introspection as defined in
// https://datatracker.ietf.org/doc/html/rfc7662#section-2.1
//
// The protected resource calls the introspection endpoint using an HTTP
// POST [RFC7231] request with parameters sent as
// "application/x-www-form-urlencoded" data as defined in
// [W3C.REC-html5-20141028].  The protected resource sends a parameter
// representing the token along with optional parameters representing
// additional context that is known by the protected resource to aid the
// authorization server in its response.
//
// * token
// REQUIRED.  The string value of the token.  For access tokens, this
// is the "access_token" value returned from the token endpoint
// defined in OAuth 2.0 [RFC6749], Section 5.1.  For refresh tokens,
// this is the "refresh_token" value returned from the token endpoint
// as defined in OAuth 2.0 [RFC6749], Section 5.1.  Other token types
// are outside the scope of this specification.
//
// * token_type_hint
// OPTIONAL.  A hint about the type of the token submitted for
// introspection.  The protected resource MAY pass this parameter to
// help the authorization server optimize the token lookup.  If the
// server is unable to locate the token using the given hint, it MUST
// extend its search across all of its supported token types.  An
// authorization server MAY ignore this parameter, particularly if it
// is able to detect the token type automatically.  Values for this
// field are defined in the "OAuth Token Type Hints" registry defined
// in OAuth Token Revocation [RFC7009].
//
// The introspection endpoint MAY accept other OPTIONAL parameters to
// provide further context to the query.  For instance, an authorization
// server may desire to know the IP address of the client accessing the
// protected resource to determine if the correct client is likely to be
// presenting the token.  The definition of this or any other parameters
// are outside the scope of this specification, to be defined by service
// documentation or extensions to this specification.  If the
// authorization server is unable to determine the state of the token
// without additional information, it SHOULD return an introspection
// response indicating the token is not active as described in
// Section 2.2.
//
// To prevent token scanning attacks, the endpoint MUST also require
// some form of authorization to access this endpoint, such as client
// authentication as described in OAuth 2.0 [RFC6749] or a separate
// OAuth 2.0 access token such as the bearer token described in OAuth
// 2.0 Bearer Token Usage [RFC6750].  The methods of managing and
// validating these authentication credentials are out of scope of this
// specification.
//
// For example, the following shows a protected resource calling the
// token introspection endpoint to query about an OAuth 2.0 bearer
// token.  The protected resource is using a separate OAuth 2.0 bearer
// token to authorize this call.
//
// The following is a non-normative example request:
//
//	POST /introspect HTTP/1.1
//	Host: server.example.com
//	Accept: application/json
//	Content-Type: application/x-www-form-urlencoded
//	Authorization: Bearer 23410913-abewfq.123483
//
//	token=2YotnFZFEjr1zCsicMWpAA
//
// In this example, the protected resource uses a client identifier and
// client secret to authenticate itself to the introspection endpoint.
// The protected resource also sends a token type hint indicating that
// it is inquiring about an access token.
//
// The following is a non-normative example request:
//
//	POST /introspect HTTP/1.1
//	Host: server.example.com
//	Accept: application/json
//	Content-Type: application/x-www-form-urlencoded
//	Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
//
//	token=mF_9.B5f-4.1JqM&token_type_hint=access_token
func (f *Fosite) NewIntrospectionRequest(ctx context.Context, r *http.Request, session Session) (responder IntrospectionResponder, err error) {
	ctx = context.WithValue(ctx, RequestContextKey, r)

	if r.Method != http.MethodPost {
		return &IntrospectionResponse{Active: false}, errorsx.WithStack(ErrInvalidRequest.WithHintf("HTTP method is '%s' but expected 'POST'.", r.Method))
	} else if err := r.ParseMultipartForm(1 << 20); err != nil && err != http.ErrNotMultipart {
		return &IntrospectionResponse{Active: false}, errorsx.WithStack(ErrInvalidRequest.WithHint("Unable to parse HTTP body, make sure to send a properly formatted form request body.").WithWrap(err).WithDebugError(err))
	} else if len(r.PostForm) == 0 {
		return &IntrospectionResponse{Active: false}, errorsx.WithStack(ErrInvalidRequest.WithHint("The POST body can not be empty."))
	}

	token := r.PostForm.Get(consts.FormParameterToken)
	tokenTypeHint := r.PostForm.Get(consts.FormParameterTokenTypeHint)

	var client Client

	if client, err = f.handleNewIntrospectionRequestClientAuthentication(ctx, r, session, token); err != nil {
		return &IntrospectionResponse{Active: false}, err
	}

	use, ar, err := f.IntrospectToken(ctx, token, TokenUse(tokenTypeHint), session, RemoveEmpty(strings.Split(r.PostForm.Get(consts.FormParameterScope), " "))...)
	if err != nil {
		return &IntrospectionResponse{Active: false}, errorsx.WithStack(ErrInactiveToken.WithHint("An introspection strategy indicated that the token is inactive.").WithWrap(err).WithDebugError(err))
	}

	accessTokenType := ""

	if use == AccessToken {
		// RFC 9449 Section 6.2: "If the token_type member is included in the introspection response, it MUST contain
		// the value DPoP." This describes the token being introspected, not the credential authorizing the call, so
		// it is derived from that token's own session, which is also the session ApplyConfirmation reads for 'cnf'.
		//
		// RFC 8705 defines no token type of its own, so a certificate-bound token remains 'bearer'.
		accessTokenType = BearerAccessToken

		if bound, ok := ar.GetSession().(DPoPBoundSession); ok && bound.GetDPoPJWKThumbprint() != "" {
			accessTokenType = DPoPAccessToken
		}
	}

	return &IntrospectionResponse{
		Client:          client,
		Active:          true,
		AccessRequester: ar,
		TokenUse:        use,
		AccessTokenType: accessTokenType,
	}, nil
}

// handleNewIntrospectionRequestClientAuthentication authenticates the caller, by the bearer credential in the
// Authorization header when one is present and by client authentication otherwise. Presenting a credential takes
// precedence: client authentication is never attempted once one is found.
//
// RFC 7662 Section 2.1 requires "some form of authorization" and names those two as its examples without choosing
// between them, so both are offered. A deployment that wants only the first sets
// GetIntrospectionEndpointClientAuthDisabled, after which a request presenting no credential is rejected here rather
// than falling through. The credential branch is tried first either way, so turning that option on removes the
// fallback and alters nothing about a request already presenting a credential.
//
// Authorising the bearer credential (its RFC 9449 and RFC 8705 bindings, then scope, then audience) is delegated to
// ValidateBearerAuthorization, which the RFC 7591 client registration endpoint also calls with its own configuration
// values.
//
// Those checks apply to the credential in the Authorization header only, never to the token being introspected. The
// introspected token is the subject of the request rather than a credential the caller claims to hold the key for,
// and RFC 9449 Section 6.2 states that "the authorization server does not validate an access token's DPoP binding at
// the introspection endpoint". The same asymmetry governs enforcement: GetDPoPEnforce and GetMTLSEnforce require the
// credential in the Authorization header to be bound and still require nothing of the introspected token, since a
// resource server introspects whatever token it was handed, including an unbound one it intends to reject.
//
// Without the check on the credential a DPoP-bound access token presented as a bearer credential would authenticate
// its client here, so a token lifted from a proxy log would replay at this endpoint with no key.
func (f *Fosite) handleNewIntrospectionRequestClientAuthentication(ctx context.Context, r *http.Request, session Session, token string) (client Client, err error) {
	var clientToken string

	if clientToken, err = introspectionCredentialFromRequest(r); err != nil {
		return nil, err
	}

	if clientToken != "" {
		if token == clientToken {
			return nil, errorsx.WithStack(ErrInvalidToken.WithHint("Bearer and introspection token are identical."))
		}

		var (
			ar  AccessRequester
			use TokenUse
		)

		// Both failures below report the same code and hint. RFC 6750 Section 3.1 defines 'invalid_token' as
		// covering "expired, revoked, malformed, or invalid for other reasons", so an unresolvable credential and
		// one of the wrong kind stay indistinguishable on the wire; the distinction goes in the debug field, which
		// only a deployment that opts in surfaces.
		if use, ar, err = f.IntrospectToken(ctx, clientToken, AccessToken, session.Clone()); err != nil {
			return nil, errorsx.WithStack(ErrInvalidToken.WithHint("HTTP Authorization header missing, malformed, or credentials used are invalid.").WithWrap(err).WithDebugError(err))
		} else if use != "" && use != AccessToken {
			return nil, errorsx.WithStack(ErrInvalidToken.WithHint("HTTP Authorization header missing, malformed, or credentials used are invalid.").WithDebugf("The HTTP Authorization header did not provide a token of type 'access_token', got type '%s'.", use))
		}

		// Endpoint is left empty: GetIntrospectionIssuer returns the 'iss' claim used in JWT introspection
		// responses, not this endpoint's own URL, so it is not a valid audience to fall back to. The chain therefore
		// runs from the configured list straight to RequestURL, which is why configuring the list is recommended.
		if err = ValidateBearerAuthorization(ctx, f.Config, r, ar, clientToken, BearerAuthorization{
			Audiences: f.Config.GetAllowedIntrospectionAudiences(ctx),
			Scopes:    f.Config.GetAllowedIntrospectionScopes(ctx),
		}); err != nil {
			return nil, err
		}

		client = ar.GetClient()
	} else if f.Config.GetIntrospectionEndpointClientAuthDisabled(ctx) {
		// No credential was presented and client authentication is off, so there is no method left to try. The code
		// is ErrInvalidToken rather than the ErrRequestUnauthorized the client authentication branch reports because
		// IsBearerCredentialError admits the former and excludes the latter, which is what makes
		// WriteIntrospectionError answer with the RFC 6750 Section 3.1 parameterless 'WWW-Authenticate' challenge
		// naming the one scheme this endpoint now accepts.
		return nil, errorsx.WithStack(ErrInvalidToken.WithHint("The request did not include an Access Token to authorize the call, and client authentication is disabled at this endpoint."))
	} else if client, _, err = f.AuthenticateClientWithAuthHandler(ctx, r, r.PostForm, f.Config.GetIntrospectionEndpointClientAuthStrategy(ctx)); err != nil {
		return nil, errorsx.WithStack(ErrRequestUnauthorized.WithHint("The request either did not include a known client authentication method, or contained invalid authentication details.").WithWrap(err).WithDebugError(err))
	}

	return client, nil
}

// introspectionCredentialFromRequest extracts the access token presented to authenticate a request to the
// introspection endpoint, accepting the RFC 9449 DPoP scheme in addition to the schemes AccessTokenFromRequest
// understands.
//
// AccessTokenFromRequest is not widened to do this. It implements RFC 6750, and every other caller of it is a place
// where accepting a DPoP-presented token would mean accepting it without the proof that makes the presentation
// meaningful. Here the proof is checked, by ValidateBearerAuthorization.
func introspectionCredentialFromRequest(r *http.Request) (token string, err error) {
	// RFC 9449 Section 7.2 Figure 19: using more than one method to include an access token is a malformed request,
	// reported with HTTP 400 and 'invalid_request'. Without this check Header.Get would silently take the first.
	// The detection is independent of any token, so distinguishing it discloses nothing.
	if len(r.Header.Values(consts.HeaderAuthorization)) > 1 {
		return "", errorsx.WithStack(ErrInvalidRequest.WithHint("Multiple methods used to include access token."))
	}

	scheme, value, found := strings.Cut(r.Header.Get(consts.HeaderAuthorization), " ")

	// RFC 6750 Section 2 forbids a client using more than one of its transports in a single request, and Section 3.1
	// makes doing so 'invalid_request' with HTTP 400, the same condition and code as the duplicate header above.
	// AccessTokenFromRequest cannot detect this itself: it falls back to the 'access_token' parameter whenever the
	// header is not Bearer, so a header and a parameter arriving together resolve to the header.
	//
	// Only a header actually carrying an access token counts. A 'Basic' header is client authentication rather than a
	// second copy of the token, which RFC 7662 Section 2.1 names as an alternative to a bearer credential, so a
	// request combining it with the parameter still uses exactly one transport.
	//
	// The parameter is read off r.Form, which NewIntrospectionRequest has already populated and which carries the URI
	// query alongside the form body, so both transports AccessTokenFromRequest can return are covered.
	if found && len(value) != 0 && (strings.EqualFold(scheme, BearerAccessToken) || strings.EqualFold(scheme, DPoPAccessToken)) && r.Form.Get(consts.FormParameterAccessToken) != "" {
		return "", errorsx.WithStack(ErrInvalidRequest.WithHint("Multiple methods used to include access token."))
	}

	if found && strings.EqualFold(scheme, DPoPAccessToken) {
		return value, nil
	}

	return AccessTokenFromRequest(r), nil
}

type IntrospectionResponse struct {
	Client          Client          `json:"-"`
	Active          bool            `json:"active"`
	AccessRequester AccessRequester `json:"extra"`
	TokenUse        TokenUse        `json:"token_use,omitempty"`
	AccessTokenType string          `json:"token_type,omitempty"`
	Lang            language.Tag    `json:"-"`
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
