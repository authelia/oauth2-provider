// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/txntoken"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

// maxUnsignedExpiry is the last second of the year 9999, well inside the range of a time.Time.
const maxUnsignedExpiry = 253402300799

var txnTokenProtectedClaims = []string{
	consts.ClaimTransaction,
	consts.ClaimAudience,
	consts.ClaimIssuedAt,
	consts.ClaimExpirationTime,
	consts.ClaimRequestingWorkload,
	consts.ClaimRequestingWorkloadChain,
	consts.ClaimIssuer,
	consts.ClaimActor,
	consts.ClaimConfirmation,
	consts.ClaimAuthorizedActor,
}

// TxnTokenTypeHandler validates the self-signed and unsigned JSON subject tokens of a request for a Transaction Token,
// which name a subject on the requesting workload's own assertion, limits the requested scopes to what the subject token
// supports, and issues the token. It is registered after all other token type handlers and before
// ActorTokenValidationHandler. Neither token type is accepted as an 'actor_token' or for any other
// 'requested_token_type'. It also validates a Transaction Token presented for replacement when
// TxnTokenType.Replacement permits it.
//
// The issued token never outlives the 'subject_token', carries no 'cnf' claim, and is not stored. A DPoP or mutual-TLS
// bound 'subject_token' still requires the requester to prove that key.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-11#section-11.2
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-11#section-9
type TxnTokenTypeHandler struct {
	// Config is also required to implement oauth2.RFC8693ConfigProvider.
	Config oauth2.Configurator

	// Strategy signs issued Transaction Tokens.
	Strategy jwt.Strategy

	// Storage resolves the scopes of a subject token that carries none, and may be nil.
	Storage TxnTokenStorage

	// JTIStorage marks a custom or self-signed JWT presented as a subject or actor token as used, once the token is
	// signed, so a request refused before then can be retried. It is required when a *JWTType or *SelfSignedTokenType
	// sets ValidateJTI.
	JTIStorage CustomJWTStorage
}

// HandleTokenEndpointRequest implements https://tools.ietf.org/html/rfc6749#section-4.3.2
func (c *TxnTokenTypeHandler) HandleTokenEndpointRequest(ctx context.Context, request oauth2.AccessRequester) (err error) {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(oauth2.ErrUnknownRequest)
	}

	config, ok := c.Config.(oauth2.RFC8693ConfigProvider)
	if !ok {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to perform token exchange because the configuration does not implement 'oauth2.RFC8693ConfigProvider'."))
	}

	if !isTxnTokenRequest(ctx, request, config) {
		return nil
	}

	session, ok := request.GetSession().(Session)
	if !ok || session == nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to perform token exchange because the session is not of the right type."))
	}

	if err = c.validateJTIStorage(ctx, request, config); err != nil {
		return err
	}

	if err = c.validateAssertedSubjectToken(ctx, request, session, config); err != nil {
		return err
	}

	if err = requireSubjectToken(request); err != nil {
		return err
	}

	var ceiling []string

	if ceiling, err = c.scopeCeiling(ctx, request, session, config); err != nil {
		return err
	}

	return validateRequestedScopes(request, oauth2.GetScopeStrategy(ctx, c.Config, request.GetClient()), ceiling)
}

// PopulateTokenEndpointResponse implements https://tools.ietf.org/html/rfc6749#section-4.3.3
func (c *TxnTokenTypeHandler) PopulateTokenEndpointResponse(ctx context.Context, request oauth2.AccessRequester, response oauth2.AccessResponder) (err error) {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(oauth2.ErrUnknownRequest)
	}

	tokenType, ok := resolveRequestedTokenType(ctx, request, c.Config).(*TxnTokenType)
	if !ok || tokenType == nil {
		return nil
	}

	return c.issue(ctx, request, tokenType, response)
}

// CanSkipClientAuth indicates if client auth can be skipped
func (c *TxnTokenTypeHandler) CanSkipClientAuth(_ context.Context, _ oauth2.AccessRequester) bool {
	return false
}

// CanHandleTokenEndpointRequest indicates if the token endpoint request can be handled
func (c *TxnTokenTypeHandler) CanHandleTokenEndpointRequest(_ context.Context, request oauth2.AccessRequester) bool {
	return request.GetGrantTypes().ExactOne(consts.GrantTypeOAuthTokenExchange)
}

// validateJTIStorage finds a server that cannot mark a 'jti' before the hook runs and a token is signed.
func (c *TxnTokenTypeHandler) validateJTIStorage(ctx context.Context, request oauth2.AccessRequester, config oauth2.RFC8693ConfigProvider) error {
	form := request.GetRequestForm()
	types := config.GetRFC8693TokenTypes(ctx)

	if c.JTIStorage == nil && (validatesJTI(types[form.Get(consts.FormParameterSubjectTokenType)]) || validatesJTI(types[form.Get(consts.FormParameterActorTokenType)])) {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to perform token exchange because the storage required to validate the 'jti' claim of a JSON Web Token is not configured."))
	}

	return nil
}

func (c *TxnTokenTypeHandler) validateAssertedSubjectToken(ctx context.Context, request oauth2.AccessRequester, session Session, config oauth2.RFC8693ConfigProvider) (err error) {
	form := request.GetRequestForm()
	value := form.Get(consts.FormParameterSubjectToken)

	var claims map[string]any

	switch tokenType := config.GetRFC8693TokenTypes(ctx)[form.Get(consts.FormParameterSubjectTokenType)].(type) {
	case *TxnTokenType:
		if tokenType == nil {
			return nil
		}

		return c.validateReplacedToken(ctx, request, session, tokenType, value)
	case *SelfSignedTokenType:
		if tokenType == nil {
			return nil
		}

		if claims, err = c.validateSelfSigned(ctx, request.GetClient(), tokenType, value); err != nil {
			return err
		}
	case *UnsignedJSONTokenType:
		if tokenType == nil {
			return nil
		}

		if claims, err = validateUnsignedJSON(request.GetClient(), value); err != nil {
			return err
		}
	default:
		return nil
	}

	subject, err := validateAssertedSubject(claims)
	if err != nil {
		return err
	}

	clearInheritedKeyBinding(request.GetSession())

	session.SetSubjectToken(claims)
	session.SetSubject(subject)

	return nil
}

// validateReplacedToken validates a Transaction Token presented for replacement. The grant handler refuses a client or
// token type that does not permit it, which is repeated here as this places the claims on the session.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-11#section-13.15
func (c *TxnTokenTypeHandler) validateReplacedToken(ctx context.Context, request oauth2.AccessRequester, session Session, tokenType *TxnTokenType, value string) error {
	if resolveRequestedTokenType(ctx, request, c.Config) != oauth2.RFC8693TokenType(tokenType) || !allowsTxnTokenReplacement(request.GetClient(), tokenType) {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("The OAuth 2.0 Client is not permitted to present a '%s' as a '%s'.", consts.TokenTypeRFC8693TxnToken, consts.FormParameterSubjectTokenType))
	}

	if tokenType.Replacement.KeyFunc == nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebugf("The '%s' token type permits replacement with no key function configured.", tokenType.Name))
	}

	validated, err := txntoken.Validate(value, txntoken.Config{
		TrustDomain: tokenType.TrustDomain,
		KeyFunc:     tokenType.Replacement.KeyFunc,
		ClockSkew:   c.Config.GetJWTClockSkew(ctx),
	})
	if err != nil {
		return errInvalidSelfSigned("The presented Transaction Token could not be validated.", err)
	}

	if tokenType.Issuer != "" && validated.Issuer != tokenType.Issuer {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("Claim '%s' from the presented Transaction Token is not this service.", consts.ClaimIssuer))
	}

	if len(validated.RequestingWorkloadChain) >= tokenType.Replacement.maxChainLength() {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("The presented Transaction Token has been replaced the permitted number of times."))
	}

	claims, err := decodeVerifiedTokenClaims(value)
	if err != nil {
		return errInvalidSelfSigned("The presented Transaction Token could not be validated.", err)
	}

	for _, name := range []string{consts.ClaimConfirmation, consts.ClaimAuthorizedActor} {
		if _, present := claims[name]; present {
			return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("The '%s' must not contain a '%s' claim.", consts.FormParameterSubjectToken, name))
		}
	}

	clearInheritedKeyBinding(request.GetSession())

	session.SetSubjectToken(claims)
	session.SetSubject(validated.Subject)

	return nil
}

// decodeVerifiedTokenClaims decodes the payload again so a number is carried as it was signed rather than as a float.
func decodeVerifiedTokenClaims(value string) (claims map[string]any, err error) {
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return nil, errors.New("the token is not a compact JWS")
	}

	var payload []byte

	if payload, err = base64.RawURLEncoding.DecodeString(parts[1]); err != nil {
		return nil, err
	}

	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()

	if err = decoder.Decode(&claims); err != nil {
		return nil, err
	}

	return claims, nil
}

// carriedTxnTokenClaims encodes the claims a replacement keeps, so they are signed as presented whatever a hook does to
// the copy it is given.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-11#section-13.15
func carriedTxnTokenClaims(claims map[string]any) (carried map[string]json.RawMessage, err error) {
	carried = make(map[string]json.RawMessage, len(claims))

	for name, value := range claims {
		switch name {
		case consts.ClaimExpirationTime, consts.ClaimIssuedAt, consts.ClaimJWTID, consts.ClaimIssuer, consts.ClaimScope, consts.ClaimRequestingWorkload, consts.ClaimRequestingWorkloadChain:
			continue
		}

		if carried[name], err = json.Marshal(value); err != nil {
			return nil, errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
		}
	}

	var chain []any

	if value, present := claims[consts.ClaimRequestingWorkloadChain]; present {
		chain, _ = value.([]any)
	}

	if carried[consts.ClaimRequestingWorkloadChain], err = json.Marshal(append(chain, claims[consts.ClaimRequestingWorkload])); err != nil {
		return nil, errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	return carried, nil
}

// applyCarriedTxnTokenClaims places a fresh copy of each carried claim on the claims.
func applyCarriedTxnTokenClaims(claims map[string]any, carried map[string]json.RawMessage) error {
	for name, raw := range carried {
		var value any

		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()

		if err := decoder.Decode(&value); err != nil {
			return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
		}

		claims[name] = value
	}

	return nil
}

// scopeCeiling returns the scopes the subject token supports. A 'scope' claim of a self-signed or unsigned subject token
// is the workload's own assertion and so is never a ceiling, and a request whose scope cannot be determined is refused.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-11#section-13.6
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-11#section-13.14
func (c *TxnTokenTypeHandler) scopeCeiling(ctx context.Context, request oauth2.AccessRequester, session Session, config oauth2.RFC8693ConfigProvider) (ceiling []string, err error) {
	subjectTokenType := request.GetRequestForm().Get(consts.FormParameterSubjectTokenType)
	claims := session.GetSubjectToken()

	switch subjectTokenType {
	case consts.TokenTypeRFC8693AccessToken:
		scopes, _ := claims[consts.ClaimScope].(oauth2.Arguments)

		return scopes, nil
	case consts.TokenTypeRFC8693IDToken:
		return c.storedScopes(ctx, request, session, subjectTokenType)
	}

	switch config.GetRFC8693TokenTypes(ctx)[subjectTokenType].(type) {
	case *JWTType:
		if _, present := claims[consts.ClaimScope]; present {
			return scopeClaim(claims), nil
		}

		return c.storedScopes(ctx, request, session, subjectTokenType)
	case *TxnTokenType:
		return scopeClaim(claims), nil
	case *SelfSignedTokenType, *UnsignedJSONTokenType:
		return c.storedScopes(ctx, request, session, subjectTokenType)
	default:
		return nil, errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("The scope of the '%s' token type cannot be determined.", subjectTokenType))
	}
}

func (c *TxnTokenTypeHandler) storedScopes(ctx context.Context, request oauth2.AccessRequester, session Session, subjectTokenType string) (scopes []string, err error) {
	if c.Storage == nil {
		return nil, errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("The scope of the '%s' cannot be determined.", consts.FormParameterSubjectToken))
	}

	if scopes, err = c.Storage.GetTxnTokenSubjectScopes(ctx, request.GetClient(), subjectTokenType, request.GetSession().GetSubject(), copyClaimMap(session.GetSubjectToken())); err != nil {
		return nil, errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	if len(scopes) == 0 {
		return nil, errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("The scope of the '%s' cannot be determined.", consts.FormParameterSubjectToken))
	}

	return scopes, nil
}

// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-11#section-9
func (c *TxnTokenTypeHandler) issue(ctx context.Context, request oauth2.AccessRequester, tokenType *TxnTokenType, response oauth2.AccessResponder) (err error) {
	session, ok := request.GetSession().(Session)
	if !ok || session == nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to perform token exchange because the session is not of the right type."))
	}

	if err = requireSubjectToken(request); err != nil {
		return err
	}

	if err = requireActorToken(request); err != nil {
		return err
	}

	if err = c.validateIssuable(ctx, tokenType); err != nil {
		return err
	}

	var (
		draft   map[string]any
		expires time.Time
	)

	if draft, expires, err = draftTxnTokenClaims(request, session, tokenType); err != nil {
		return err
	}

	var carried map[string]json.RawMessage

	if isTxnTokenReplacement(ctx, request, c.Config) {
		if carried, err = carriedTxnTokenClaims(session.GetSubjectToken()); err != nil {
			return err
		}

		if err = applyCarriedTxnTokenClaims(draft, carried); err != nil {
			return err
		}
	} else if err = mapTxnTokenScopes(ctx, request, tokenType, draft); err != nil {
		return err
	}

	if draft, err = transcribeTxnTokenClaims(ctx, request, session, tokenType, draft, carried); err != nil {
		return err
	}

	for name, raw := range carried {
		draft[name] = raw
	}

	var token string

	if token, err = c.signTxnToken(ctx, tokenType, draft); err != nil {
		return err
	}

	if err = consumeTokenJTIs(ctx, c.Config, c.JTIStorage, request, session); err != nil {
		return err
	}

	response.SetAccessToken(token)
	response.SetTokenType(oauth2.RFC8693NAToken)
	response.SetExpiresIn(time.Until(expires))
	response.SetScopes(scopeClaim(draft))
	response.SetExtra(consts.FormParameterIssuedTokenType, tokenType.GetType(ctx))

	return nil
}

// The token is signed with the issuer key, so an ID Token issuer would leave only the 'typ' header to tell it from an ID
// Token. RFC 8725 Section 3.12 requires mutually exclusive validation rules for JWTs from one issuer.
//
// See: https://datatracker.ietf.org/doc/html/rfc8725#section-3.12
func (c *TxnTokenTypeHandler) validateIssuable(ctx context.Context, tokenType *TxnTokenType) error {
	if c.Strategy == nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("The JSON Web Token strategy required to issue a Transaction Token is not configured."))
	}

	if issuer := c.Config.GetIDTokenIssuer(ctx); tokenType.Issuer != "" && tokenType.Issuer == issuer {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebugf("The '%s' token type has the issuer '%s' which is the ID Token issuer.", tokenType.Name, issuer))
	}

	return nil
}

// draftTxnTokenClaims builds the claims from the validated request alone, as no claim of the session or credential from
// the request belongs in the token.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-11#section-9.2
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-11#section-13.4
func draftTxnTokenClaims(request oauth2.AccessRequester, session Session, tokenType *TxnTokenType) (claims map[string]any, expires time.Time, err error) {
	subject := request.GetSession().GetSubject()
	if subject == "" {
		return nil, time.Time{}, errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("The '%s' does not identify a subject.", consts.FormParameterSubjectToken))
	}

	scopes := grantedRequestedScopes(request)
	if len(scopes) == 0 {
		return nil, time.Time{}, errorsx.WithStack(oauth2.ErrInvalidScope.WithHintf("No requested scope was granted for the '%s'.", consts.FormParameterSubjectToken))
	}

	now := time.Now().UTC()
	expires = capToSubjectTokenExpiry(request, now.Add(tokenType.expiry()))

	if expires.Unix() <= now.Unix() {
		return nil, time.Time{}, errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("The '%s' expires too soon to issue a Transaction Token.", consts.FormParameterSubjectToken))
	}

	var act map[string]any

	if act, err = buildActClaim(session); err != nil {
		return nil, time.Time{}, err
	}

	claims = map[string]any{
		consts.ClaimIssuedAt:           now.Unix(),
		consts.ClaimAudience:           tokenType.TrustDomain,
		consts.ClaimExpirationTime:     expires.Unix(),
		consts.ClaimTransaction:        uuid.New().String(),
		consts.ClaimSubject:            subject,
		consts.ClaimScope:              strings.Join(scopes, " "),
		consts.ClaimRequestingWorkload: request.GetClient().GetID(),
	}

	if tokenType.Issuer != "" {
		claims[consts.ClaimIssuer] = tokenType.Issuer
	}

	if len(act) > 0 {
		claims[consts.ClaimActor] = act
	}

	return claims, expires, nil
}

// mapTxnTokenScopes replaces the 'scope' of the draft with the result of TxnTokenType.MapScopes.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-11#section-9.2.1
func mapTxnTokenScopes(ctx context.Context, request oauth2.AccessRequester, tokenType *TxnTokenType, draft map[string]any) error {
	if tokenType.MapScopes == nil {
		return nil
	}

	mapped, err := tokenType.MapScopes(ctx, request, scopeClaim(draft))
	if err != nil {
		return err
	}

	var scopes []string

	for _, scope := range mapped {
		if !isScopeToken(scope) {
			return errorsx.WithStack(oauth2.ErrServerError.WithDebugf("The '%s' token type scope mapping returned the invalid scope '%s'.", tokenType.Name, scope))
		}

		if !slices.Contains(scopes, scope) {
			scopes = append(scopes, scope)
		}
	}

	if len(scopes) == 0 {
		return errorsx.WithStack(oauth2.ErrInvalidScope.WithHintf("No requested scope is available for the '%s' token type.", tokenType.Name))
	}

	draft[consts.ClaimScope] = strings.Join(scopes, " ")

	return nil
}

// See: https://datatracker.ietf.org/doc/html/rfc6749#appendix-A.4
func isScopeToken(scope string) bool {
	if scope == "" {
		return false
	}

	for i := range len(scope) {
		if c := scope[i]; c < 0x21 || c > 0x7e || c == '"' || c == '\\' {
			return false
		}
	}

	return true
}

// transcribeTxnTokenClaims runs the hook and then applies the limits on what it may change: the protected claims are
// restored from a copy taken beforehand, the 'scope' may only narrow, the 'sub' must remain a non-empty string, and
// 'rctx' and 'tctx' must be JSON objects, omitted when empty.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-11#section-11.3
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-11#section-9.2
func transcribeTxnTokenClaims(ctx context.Context, request oauth2.AccessRequester, session Session, tokenType *TxnTokenType, draft map[string]any, carried map[string]json.RawMessage) (claims map[string]any, err error) {
	if tokenType.TranscribeClaims == nil {
		return draft, nil
	}

	input := &TxnTokenClaimsInput{SubjectClaims: copyClaimMap(session.GetSubjectToken()), Claims: draft, Replacement: carried != nil}

	if input.RequestContext, err = parseTxnTokenParameter(request.GetRequestForm(), consts.FormParameterRequestContext); err != nil {
		return nil, err
	}

	if input.RequestDetails, err = parseTxnTokenParameter(request.GetRequestForm(), consts.FormParameterRequestDetails); err != nil {
		return nil, err
	}

	protected := make(map[string]any, len(txnTokenProtectedClaims))

	for _, name := range txnTokenProtectedClaims {
		if value, present := draft[name]; present {
			protected[name] = value
		}
	}

	protected = copyClaimMap(protected)
	ceiling := scopeClaim(draft)

	if err = tokenType.TranscribeClaims(ctx, request, input); err != nil {
		return nil, err
	}

	if claims = input.Claims; claims == nil {
		return nil, errInvalidTxnTokenHook("The '%s' token type hook removed the claims.", tokenType.Name)
	}

	if err = restoreTxnTokenClaims(claims, protected, carried); err != nil {
		return nil, err
	}

	if subject, _ := claims[consts.ClaimSubject].(string); subject == "" {
		return nil, errInvalidTxnTokenHook("The '%s' token type hook left the '%s' claim without a non-empty string.", tokenType.Name, consts.ClaimSubject)
	}

	if err = narrowTxnTokenScope(claims, ceiling, tokenType); err != nil {
		return nil, err
	}

	for _, name := range []string{consts.ClaimRequestContext, consts.ClaimTransactionContext} {
		if err = omitEmptyTxnTokenObjectClaim(claims, name, tokenType); err != nil {
			return nil, err
		}
	}

	if err = encodeTxnTokenHookClaims(claims, tokenType); err != nil {
		return nil, err
	}

	return claims, nil
}

func restoreTxnTokenClaims(claims, protected map[string]any, carried map[string]json.RawMessage) error {
	for _, name := range txnTokenProtectedClaims {
		if value, present := protected[name]; present {
			claims[name] = value
		} else {
			delete(claims, name)
		}
	}

	return applyCarriedTxnTokenClaims(claims, carried)
}

func encodeTxnTokenHookClaims(claims map[string]any, tokenType *TxnTokenType) error {
	for name, value := range claims {
		if _, isString := value.(string); isString || slices.Contains(txnTokenProtectedClaims, name) {
			continue
		}

		raw, err := json.Marshal(value)
		if err != nil {
			return errInvalidTxnTokenHook("The '%s' token type hook set the '%s' claim to a value that cannot be encoded.", tokenType.Name, name)
		}

		claims[name] = json.RawMessage(raw)
	}

	return nil
}

func narrowTxnTokenScope(claims map[string]any, ceiling []string, tokenType *TxnTokenType) error {
	value, ok := claims[consts.ClaimScope].(string)
	if !ok {
		return errInvalidTxnTokenHook("The '%s' token type hook left the '%s' claim without a string.", tokenType.Name, consts.ClaimScope)
	}

	var scopes []string

	for _, scope := range strings.Split(value, " ") {
		switch {
		case scope == "", slices.Contains(scopes, scope):
			continue
		case !slices.Contains(ceiling, scope):
			return errInvalidTxnTokenHook("The '%s' token type hook widened the '%s' claim with '%s'.", tokenType.Name, consts.ClaimScope, scope)
		}

		scopes = append(scopes, scope)
	}

	if len(scopes) == 0 {
		return errInvalidTxnTokenHook("The '%s' token type hook left the '%s' claim empty.", tokenType.Name, consts.ClaimScope)
	}

	claims[consts.ClaimScope] = strings.Join(scopes, " ")

	return nil
}

func omitEmptyTxnTokenObjectClaim(claims map[string]any, name string, tokenType *TxnTokenType) error {
	value, present := claims[name]
	if !present {
		return nil
	}

	if object, ok := value.(map[string]any); ok && len(object) == 0 {
		delete(claims, name)

		return nil
	}

	raw, err := json.Marshal(value)
	if err != nil || len(raw) == 0 || raw[0] != '{' {
		return errInvalidTxnTokenHook("The '%s' token type hook set the '%s' claim to a value that is not a JSON object.", tokenType.Name, name)
	}

	if string(raw) == "{}" {
		delete(claims, name)
	}

	return nil
}

func errInvalidTxnTokenHook(format string, args ...any) error {
	return errorsx.WithStack(oauth2.ErrServerError.WithDebugf(format, args...))
}

func (c *TxnTokenTypeHandler) signTxnToken(ctx context.Context, tokenType *TxnTokenType, claims map[string]any) (token string, err error) {
	headers := &jwt.Headers{Extra: map[string]any{consts.JSONWebTokenHeaderType: consts.JSONWebTokenTypeTxnToken}}

	if token, _, err = c.Strategy.Encode(ctx, jwt.MapClaims(claims), jwt.WithHeaders(headers), jwt.WithIssuerSigningAlg(tokenType.signingAlg())); err != nil {
		return "", errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	return token, nil
}

func grantedRequestedScopes(request oauth2.AccessRequester) (scopes []string) {
	requested := request.GetRequestedScopes()

	for _, scope := range request.GetGrantedScopes() {
		if slices.Contains(requested, scope) {
			scopes = append(scopes, scope)
		}
	}

	return scopes
}

// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-11#section-11.2.1
func (c *TxnTokenTypeHandler) validateSelfSigned(ctx context.Context, client oauth2.Client, tokenType *SelfSignedTokenType, value string) (claims jwt.MapClaims, err error) {
	if tokenType.Identifier == "" {
		return nil, errorsx.WithStack(oauth2.ErrServerError.WithDebugf("The '%s' token type has no Identifier configured.", tokenType.Name))
	}

	var (
		keyfunc  jwt.Keyfunc
		resolved bool
	)

	if keyfunc, err = c.selfSignedKeyfunc(ctx, client, &resolved); err != nil {
		return nil, err
	}

	skew := c.Config.GetJWTClockSkew(ctx)

	var token *jwt.Token

	if token, err = jwt.ParseCustomWithClaims(value, jwt.MapClaims{}, keyfunc, txntoken.DefaultAlgorithms()...); err != nil && (!resolved || !jwt.IsTimingValidationError(err)) {
		return nil, errInvalidSelfSigned("The self-signed subject token could not be verified.", err)
	}

	claims = token.Claims.ToMapClaims()

	if err = claims.Valid(jwt.ValidateTimeFunc(time.Now), jwt.ValidateClockSkew(skew), jwt.ValidateRequireExpiresAt(), jwt.ValidateRequireIssuedAt()); err != nil {
		return nil, errInvalidSelfSigned("The time claims of the self-signed subject token are not valid.", err)
	}

	if err = validateSelfSignedType(token); err != nil {
		return nil, err
	}

	if iss, _ := claims[consts.ClaimIssuer].(string); iss != client.GetID() {
		return nil, errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("Claim 'iss' from the self-signed subject token must be the OAuth 2.0 Client."))
	}

	if !claims.VerifyAudience(tokenType.Identifier, true) {
		return nil, errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("Claim 'aud' from the self-signed subject token must include '%s'.", tokenType.Identifier))
	}

	if err = validateSelfSignedWindow(claims, tokenType.window(), skew); err != nil {
		return nil, err
	}

	if tokenType.ValidateJTI {
		if jti, _ := claims[consts.ClaimJWTID].(string); jti == "" {
			return nil, errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("Claim 'jti' from token is missing."))
		}
	}

	return claims, nil
}

// selfSignedKeyfunc returns a key function which sets resolved once it returns a key. It never refreshes the key set on a
// 'kid' miss, as a caller-chosen 'kid' must not force a refetch of the client's 'jwks_uri'.
func (c *TxnTokenTypeHandler) selfSignedKeyfunc(ctx context.Context, client oauth2.Client, resolved *bool) (keyfunc jwt.Keyfunc, err error) {
	keys, ok := client.(oauth2.JSONWebKeysClient)
	if !ok {
		return nil, errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("The OAuth 2.0 Client has no registered JSON Web Keys."))
	}

	jwks, uri := keys.GetJSONWebKeys(), keys.GetJSONWebKeysURI()
	inline := jwks != nil && len(jwks.Keys) != 0

	if !inline && uri == "" {
		return nil, errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("The OAuth 2.0 Client has no registered JSON Web Keys."))
	}

	var fetcher jwt.JWKSFetcherStrategy

	if !inline {
		if fetcher = c.Config.GetJWKSFetcherStrategy(ctx); fetcher == nil {
			return nil, errorsx.WithStack(oauth2.ErrServerError.WithDebug("The JSON Web Key Set fetcher strategy is not configured."))
		}
	}

	return func(token *jwt.Token) (key any, err error) {
		set := jwks

		if !inline {
			if set, err = fetcher.Resolve(ctx, uri, false); err != nil {
				return nil, err
			}

			if set == nil {
				return nil, errors.New("the 'jwks_uri' of the client did not resolve to a JSON Web Key Set")
			}
		}

		var found *jose.JSONWebKey

		if found, err = jwt.SearchJWKS(set, token.KeyID, string(token.SignatureAlgorithm), consts.JSONWebTokenUseSignature, true); err != nil {
			return nil, err
		}

		if err = jwt.ValidateRSAKeyMaximumSize(found); err != nil {
			return nil, err
		}

		public := found.Public()

		*resolved = true

		return &public, nil
	}, nil
}

// Only a generic JWT is a self-signed subject token, as any explicit type names a token with other validation rules, per
// the mutually exclusive validation rules of RFC 8725.
//
// See: https://datatracker.ietf.org/doc/html/rfc8725#section-3.12
func validateSelfSignedType(token *jwt.Token) error {
	value, present := token.Header[jwt.JSONWebTokenHeaderType]
	if !present {
		return nil
	}

	typ, ok := value.(string)
	if !ok {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("The 'typ' header of the self-signed subject token must be a string."))
	}

	if !strings.EqualFold(typ, consts.JSONWebTokenTypeJWT) && !strings.EqualFold(typ, "application/"+consts.JSONWebTokenTypeJWT) {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("The 'typ' header '%s' is not permitted for a self-signed subject token.", typ))
	}

	return nil
}

// A value that is missing or not a number is read as zero by toInt64, and so is refused as too old or as expired. The
// comparison is of seconds so that no value can overflow a time.Time.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-11#section-11.2.1
func validateSelfSignedWindow(claims map[string]any, window, skew time.Duration) error {
	now := time.Now().Unix()
	windowSeconds, skewSeconds := int64(window/time.Second), int64(skew/time.Second)

	iat, exp := toInt64(claims[consts.ClaimIssuedAt]), toInt64(claims[consts.ClaimExpirationTime])

	switch {
	case iat < now-windowSeconds:
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("Claim 'iat' from the self-signed subject token is too far in the past."))
	case iat > now+skewSeconds:
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("Claim 'iat' from the self-signed subject token is in the future."))
	case exp <= now:
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("The self-signed subject token has expired."))
	case exp > now+windowSeconds:
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("Claim 'exp' from the self-signed subject token is too far in the future."))
	}

	return nil
}

// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-11#section-11.2.2
func validateUnsignedJSON(client oauth2.Client, value string) (claims map[string]any, err error) {
	if c, ok := client.(TxnTokenClient); !ok || !c.GetAllowUnsignedJSONSubjectToken() {
		return nil, errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("The OAuth 2.0 Client is not permitted to present an unsigned JSON subject token."))
	}

	decoder := json.NewDecoder(strings.NewReader(value))
	decoder.UseNumber()

	if err = decoder.Decode(&claims); err != nil || claims == nil {
		return nil, errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("The unsigned JSON subject token must be a JSON object."))
	}

	if _, err = decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("The unsigned JSON subject token must be a single JSON object."))
	}

	if err = validateUnsignedExpiry(claims); err != nil {
		return nil, err
	}

	return claims, nil
}

// validateUnsignedExpiry refuses an 'exp' that could not cap the issued token. The claim is optional, as the draft
// requires only 'sub', but one that is present must be a NumericDate in the future.
//
// See: https://datatracker.ietf.org/doc/html/rfc7519#section-2
func validateUnsignedExpiry(claims map[string]any) error {
	value, present := claims[consts.ClaimExpirationTime]
	if !present {
		return nil
	}

	number, ok := value.(json.Number)
	if !ok {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("Claim 'exp' from the '%s' must be a number.", consts.FormParameterSubjectToken))
	}

	exp, err := number.Float64()
	if err != nil || exp <= float64(time.Now().Unix()) || exp > maxUnsignedExpiry {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("Claim 'exp' from the '%s' is not a valid expiry.", consts.FormParameterSubjectToken))
	}

	return nil
}

// validateAssertedSubject refuses the claims that drive delegation and binding once on the session, as RFC 8693 Section
// 4.4 and RFC 7800 Section 3 give them to the issuer of a token and here the requesting workload wrote them.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-11#section-11.2
func validateAssertedSubject(claims map[string]any) (subject string, err error) {
	for _, name := range []string{consts.ClaimAuthorizedActor, consts.ClaimActor, consts.ClaimConfirmation} {
		if _, present := claims[name]; present {
			return "", errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("The '%s' must not contain a '%s' claim.", consts.FormParameterSubjectToken, name))
		}
	}

	if subject, _ = claims[consts.ClaimSubject].(string); subject == "" {
		return "", errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("The '%s' must contain a '%s' claim which is a non-empty string.", consts.FormParameterSubjectToken, consts.ClaimSubject))
	}

	return subject, nil
}

func errInvalidSelfSigned(hint string, err error) error {
	return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint(hint).WithWrap(err).WithDebugError(err))
}

var _ oauth2.TokenEndpointHandler = (*TxnTokenTypeHandler)(nil)
