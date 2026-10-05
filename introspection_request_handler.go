// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"golang.org/x/text/language"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

// NewIntrospectionRequest initiates token introspection.
//
// See: https://datatracker.ietf.org/doc/html/rfc7662#section-2.1
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

	// RFC 7662 Section 2.1 makes 'token' REQUIRED, and RFC 6749 Section 3.1 treats an empty value as omitted. A request
	// without it is not "a properly formed and authorized query" (RFC 7662 Section 2.3), so it is answered with the
	// RFC 6749 Section 5.2 'invalid_request' error rather than an inactive introspection response.
	if token == "" {
		return &IntrospectionResponse{Active: false}, errorsx.WithStack(ErrInvalidRequest.WithHint("The 'token' parameter is required."))
	}

	use, ar, err := f.IntrospectToken(ctx, token, TokenUse(tokenTypeHint), session, RemoveEmpty(strings.Split(r.PostForm.Get(consts.FormParameterScope), " "))...)
	if err != nil {
		return &IntrospectionResponse{Active: false}, errorsx.WithStack(ErrInactiveToken.WithHint("An introspection strategy indicated that the token is inactive.").WithWrap(err).WithDebugError(err))
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
	}, nil
}

// handleNewIntrospectionRequestClientAuthentication authenticates the caller, by the bearer credential in the
// Authorization header when one is present and by client authentication otherwise. Client authentication is never
// attempted once a credential is found, and a request presenting none is rejected when
// GetIntrospectionEndpointClientAuthDisabled is set.
//
// The binding, scope and audience checks of ValidateBearerAuthorization apply to the credential in the Authorization
// header only, never to the token being introspected.
//
// See: https://www.rfc-editor.org/rfc/rfc7662#section-2.1
// See: https://www.rfc-editor.org/rfc/rfc9449#section-6.2
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

		// Endpoint is left empty: GetIntrospectionIssuer is the 'iss' claim of JWT introspection responses, not this
		// endpoint's URL, so the audience falls back from the configured list to RequestURL.
		if err = ValidateBearerAuthorization(ctx, f.Config, r, ar, clientToken, BearerAuthorization{
			Audiences: f.Config.GetAllowedIntrospectionAudiences(ctx),
			Scopes:    f.Config.GetAllowedIntrospectionScopes(ctx),
		}); err != nil {
			return nil, err
		}

		client = ar.GetClient()
	} else if f.Config.GetIntrospectionEndpointClientAuthDisabled(ctx) {
		// ErrInvalidToken rather than ErrRequestUnauthorized, so that WriteIntrospectionError answers with the RFC 6750
		// Section 3 'WWW-Authenticate' challenge.
		return nil, errorsx.WithStack(ErrInvalidToken.WithHint("The request did not include an Access Token to authorize the call, and client authentication is disabled at this endpoint."))
	} else if client, _, err = f.AuthenticateClientWithAuthHandler(ctx, r, r.PostForm, f.Config.GetIntrospectionEndpointClientAuthStrategy(ctx)); err != nil {
		// See: https://www.rfc-editor.org/rfc/rfc7662#section-2.3
		if errors.Is(err, ErrInvalidClient) {
			return nil, err
		}

		return nil, errorsx.WithStack(ErrRequestUnauthorized.WithHint("The request either did not include a known client authentication method, or contained invalid authentication details.").WithWrap(err).WithDebugError(err))
	}

	return client, nil
}

// introspectionCredentialFromRequest extracts the access token presented to authenticate a request to the introspection
// endpoint, accepting the RFC 9449 DPoP scheme in addition to the schemes AccessTokenFromRequest understands. The proof
// is checked by ValidateBearerAuthorization.
func introspectionCredentialFromRequest(r *http.Request) (token string, err error) {
	// RFC 9449 Section 7.2 Figure 19: using more than one method to include an access token is a malformed request,
	// reported with HTTP 400 and 'invalid_request'. Without this check Header.Get would silently take the first.
	// The detection is independent of any token, so distinguishing it discloses nothing.
	if len(r.Header.Values(consts.HeaderAuthorization)) > 1 {
		return "", errorsx.WithStack(ErrInvalidRequest.WithHint("Multiple methods used to include access token."))
	}

	scheme, value, found := strings.Cut(r.Header.Get(consts.HeaderAuthorization), " ")

	// RFC 9110 Section 11.4: one or more spaces separate the scheme from the token.
	value = strings.TrimLeft(value, " ")

	// RFC 6750 Section 2 and Section 3.1: a token in both the header and the 'access_token' parameter is
	// 'invalid_request'. A 'Basic' header is client authentication rather than a token transport, so it may accompany
	// the parameter. The parameter is read off r.Form, which carries the URI query alongside the form body.
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
