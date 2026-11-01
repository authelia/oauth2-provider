// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"strings"
	"time"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

const (
	defaultTxnTokenWindow         = 5 * time.Minute
	defaultTxnTokenMaxChainLength = 8
)

// TxnTokenType issues a Transaction Token. It is usable as a 'requested_token_type', and as a 'subject_token_type' only
// when Replacement is set.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-11#section-9
type TxnTokenType struct {
	Name string `json:"name"`

	// TrustDomain is the single Trust Domain of the issued tokens, which is required.
	//
	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-11#section-10
	TrustDomain string `json:"trust_domain"`

	// Issuer is the 'iss' claim of an issued token when not empty. It must not equal the ID Token issuer.
	Issuer string `json:"iss"`

	// Expiry is the lifetime of an issued token. A value that is not positive uses 5 minutes. It has no upper limit, and a
	// subject token with no 'exp' does not shorten it, so it must be kept short, on the order of minutes or less.
	//
	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-11#section-6
	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-11#section-13.1
	Expiry time.Duration `json:"exp"`

	// SigningAlg is the JWS algorithm selecting the issuer key. RS256 is used when empty.
	SigningAlg string `json:"signing_alg"`

	// TranscribeClaims is the only way 'rctx' and 'tctx' reach a token, so without it the 'request_context' and
	// 'request_details' parameters are validated and then dropped, and the token has neither claim, which the draft says it
	// SHOULD have.
	//
	// It runs after all validation and before signing, including when neither 'request_context' nor
	// 'request_details' was sent. It may add any claim, change 'sub', narrow 'scope', and set 'rctx' and 'tctx'.
	//
	// 'txn', 'aud', 'iat', 'exp', 'req_wl', 'iss', 'act' and 'cnf' are restored afterwards, so a 'cnf' is always removed as
	// the draft never contains one. A deleted or widened 'scope', a 'sub' that is empty, or an 'rctx' or 'tctx' that is not
	// a JSON object is a server_error, and an empty 'rctx' or 'tctx' is omitted. A returned error denies the request, and should be an error RFC 8693 Section 2.2.2 defines such as
	// oauth2.ErrInvalidRequest. A panic is not recovered.
	//
	// The full copy of the request parameters is one line, and signs whatever the caller sent:
	//
	//	input.Claims["rctx"], input.Claims["tctx"] = input.RequestContext, input.RequestDetails
	//
	// A credential must not be placed in a claim (section 13.4), so copying input.SubjectClaims or a request parameter
	// is safe only when it holds none.
	//
	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-11#section-11.3
	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-11#section-13.4
	TranscribeClaims func(ctx context.Context, request oauth2.AccessRequester, input *TxnTokenClaimsInput) (err error) `json:"-"`

	// MapScopes returns the Trust Domain scopes for the scopes that passed the checks against the subject token. It runs
	// before TranscribeClaims, its result is the 'scope' of the token and the response, and without it the scopes are not
	// changed. An empty result is 'invalid_scope', and a returned error denies the request.
	//
	// The library cannot compare the two sets of names, so this function is responsible for the result representing no
	// more than the scopes it receives.
	//
	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-11#section-9.2.1
	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-11#section-13.6
	MapScopes func(ctx context.Context, request oauth2.AccessRequester, scopes []string) (mapped []string, err error) `json:"-"`

	// Replacement permits a client implementing TxnTokenReplacementClient to exchange a Transaction Token for another.
	// Nil refuses a Transaction Token as a subject token.
	Replacement *TxnTokenReplacement `json:"-"`
}

// TxnTokenReplacement configures the exchange of a Transaction Token for a replacement, which keeps 'txn', 'sub', 'aud'
// and every other claim of the presented token except 'exp', 'iat', 'jti', 'iss', 'scope' and 'req_wl'. The
// 'req_wl' is the new requester and 'req_wl_chain' gains the previous one, oldest first. The 'scope' is limited to that
// of the presented token and is not given to TxnTokenType.MapScopes, and 'exp' never exceeds that of the presented token.
// TxnTokenType.TranscribeClaims may narrow 'scope' and add a claim, and cannot change or remove a carried claim.
//
// The draft leaves how the Call Chain is maintained to the implementation, so 'req_wl_chain' is specific to this library.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-11#section-13.15
type TxnTokenReplacement struct {
	// KeyFunc returns the key which verifies a presented Transaction Token, and is required. A key that signed this
	// Trust Domain's tokens must remain available for as long as a token it signed can be presented.
	KeyFunc jwt.Keyfunc

	// MaxChainLength refuses a presented token once replacing it would make 'req_wl_chain' longer. A value that is not
	// positive uses 8.
	MaxChainLength int
}

// TxnTokenReplacementClient is a client that may exchange a Transaction Token for a replacement.
type TxnTokenReplacementClient interface {
	// GetAllowTxnTokenReplacement indicates the client may present a Transaction Token as a subject token.
	GetAllowTxnTokenReplacement() bool
}

// TxnTokenClaimsInput is the input of TxnTokenType.TranscribeClaims.
type TxnTokenClaimsInput struct {
	// RequestContext is the parsed 'request_context' parameter, nil when absent. A number is a json.Number.
	RequestContext map[string]any

	// RequestDetails is the parsed 'request_details' parameter, nil when absent. A number is a json.Number.
	RequestDetails map[string]any

	// SubjectClaims is a copy of the claims of the validated subject token.
	SubjectClaims map[string]any

	// Claims is the draft Transaction Token claims, which the function may change.
	Claims map[string]any

	// Replacement is true when the token replaces a presented Transaction Token, which is SubjectClaims.
	Replacement bool
}

// CopyTxnTokenRequestParameters is a TxnTokenType.TranscribeClaims function which copies 'request_context' to 'rctx' and
// 'request_details' to 'tctx'. A parameter that is present replaces the claim, and one that is absent leaves it. A hook
// that also sets these claims can call it, and the later write wins. It copies nothing for a replacement, as those claims
// are immutable through the Call Chain and a replacing workload is not where they originate.
//
// The values are what the requesting workload asserted, and the signature of the Transaction Token makes them appear to
// be asserted by the Transaction Token Service. Set this only when every workload permitted to request a token is
// trusted for every value it can send, as tctx is relied on as immutable through the Call Chain.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-11#section-11.3
func CopyTxnTokenRequestParameters(_ context.Context, _ oauth2.AccessRequester, input *TxnTokenClaimsInput) (err error) {
	if input.Replacement {
		return nil
	}

	if input.RequestContext != nil {
		input.Claims[consts.ClaimRequestContext] = input.RequestContext
	}

	if input.RequestDetails != nil {
		input.Claims[consts.ClaimTransactionContext] = input.RequestDetails
	}

	return nil
}

// SelfSignedTokenType validates a self-signed JWT subject token. Its 'sub' becomes the 'sub' of the issued token as
// presented, and the draft requires it to be unique within the Trust Domain, so a deployer whose workloads do not share one
// namespace must rewrite it in TxnTokenType.TranscribeClaims.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-11#section-11.2.1
type SelfSignedTokenType struct {
	Name string `json:"name"`

	// Identifier is the Transaction Token Service identifier compared against the 'aud' claim.
	//
	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-11#section-11.2.1
	Identifier string `json:"identifier"`

	// ToleranceWindow refuses an 'iat' older, or an 'exp' further ahead, than the window. A value that is not positive
	// uses 5 minutes.
	ToleranceWindow time.Duration `json:"tolerance_window"`

	// ValidateJTI requires a 'jti' claim and consumes it.
	ValidateJTI bool `json:"validate_jti"`
}

// UnsignedJSONTokenType validates an unsigned JSON subject token. Its 'sub' becomes the 'sub' of the issued token as
// presented, and the draft requires it to be unique within the Trust Domain, so a deployer whose workloads do not share one
// namespace must rewrite it in TxnTokenType.TranscribeClaims.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-11#section-11.2.2
type UnsignedJSONTokenType struct {
	Name string `json:"name"`
}

// TxnTokenClient is a client that may present an unsigned JSON subject token.
type TxnTokenClient interface {
	// GetAllowUnsignedJSONSubjectToken indicates the client may use the unsigned JSON subject token type.
	GetAllowUnsignedJSONSubjectToken() bool
}

// TxnTokenStorage resolves the scopes of a subject token that carries none.
type TxnTokenStorage interface {
	// GetTxnTokenSubjectScopes returns the scopes the client may obtain in a Txn-Token for the subject named by a token
	// that carries no scope. An empty result refuses the request.
	GetTxnTokenSubjectScopes(ctx context.Context, client oauth2.Client, subjectTokenType, subject string, claims map[string]any) (scopes []string, err error)
}

// GetName returns the name of the token type.
func (c *TxnTokenType) GetName(ctx context.Context) string {
	return c.Name
}

// GetType returns the Transaction Token type identifier.
func (c *TxnTokenType) GetType(ctx context.Context) string {
	return consts.TokenTypeRFC8693TxnToken
}

func (c *TxnTokenReplacement) maxChainLength() int {
	if c.MaxChainLength <= 0 {
		return defaultTxnTokenMaxChainLength
	}

	return c.MaxChainLength
}

func allowsTxnTokenReplacement(client oauth2.Client, tokenType *TxnTokenType) bool {
	if tokenType.Replacement == nil {
		return false
	}

	c, ok := client.(TxnTokenReplacementClient)

	return ok && c.GetAllowTxnTokenReplacement()
}

func isTxnTokenSubject(ctx context.Context, request oauth2.Requester, config oauth2.RFC8693ConfigProvider) bool {
	subject, ok := config.GetRFC8693TokenTypes(ctx)[request.GetRequestForm().Get(consts.FormParameterSubjectTokenType)].(*TxnTokenType)

	return ok && subject != nil
}

func isTxnTokenReplacement(ctx context.Context, request oauth2.Requester, config oauth2.RFC8693ConfigProvider) bool {
	return isTxnTokenSubject(ctx, request, config) && isTxnTokenRequest(ctx, request, config)
}

func (c *TxnTokenType) expiry() time.Duration {
	if c.Expiry <= 0 {
		return defaultTxnTokenWindow
	}

	return c.Expiry
}

func (c *TxnTokenType) signingAlg() string {
	if c.SigningAlg == "" {
		return string(jose.RS256)
	}

	return c.SigningAlg
}

// GetName returns the name of the token type.
func (c *SelfSignedTokenType) GetName(ctx context.Context) string {
	return c.Name
}

// GetType returns the self-signed token type identifier.
func (c *SelfSignedTokenType) GetType(ctx context.Context) string {
	return consts.TokenTypeRFC8693SelfSigned
}

func (c *SelfSignedTokenType) window() time.Duration {
	if c.ToleranceWindow <= 0 {
		return defaultTxnTokenWindow
	}

	return c.ToleranceWindow
}

// GetName returns the name of the token type.
func (c *UnsignedJSONTokenType) GetName(ctx context.Context) string {
	return c.Name
}

// GetType returns the unsigned JSON token type identifier.
func (c *UnsignedJSONTokenType) GetType(ctx context.Context) string {
	return consts.TokenTypeRFC8693UnsignedJSON
}

func isTxnTokenRequest(ctx context.Context, request oauth2.Requester, config oauth2.RFC8693ConfigProvider) bool {
	txnType, ok := resolveRequestedTokenType(ctx, request, config).(*TxnTokenType)

	return ok && txnType != nil
}

// validateTxnTokenRequest applies the request rules of a Txn-Token exchange.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-11#section-11
func validateTxnTokenRequest(ctx context.Context, request oauth2.AccessRequester, config oauth2.RFC8693ConfigProvider, tokenType *TxnTokenType) (err error) {
	form := request.GetRequestForm()

	// The 'requested_token_type' must be sent, so a configured default does not satisfy section 11.1.
	if form.Get(consts.FormParameterRequestedTokenType) == "" {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("The '%s' parameter is required and must be '%s'.", consts.FormParameterRequestedTokenType, consts.TokenTypeRFC8693TxnToken))
	}

	// A refresh token must not be exchanged for a Txn-Token (section 11.2, section 13.3), and a Txn-Token is exchanged
	// for another only if both the type and the client permit it (section 13.15).
	subjectTokenType := form.Get(consts.FormParameterSubjectTokenType)
	replacing := isTxnTokenSubject(ctx, request, config)

	// A different type has its own Trust Domain, so its token cannot be replaced by one of this type.
	refused := replacing && (config.GetRFC8693TokenTypes(ctx)[subjectTokenType] != oauth2.RFC8693TokenType(tokenType) || !allowsTxnTokenReplacement(request.GetClient(), tokenType))

	if form.Get(consts.FormParameterActorTokenType) == consts.TokenTypeRFC8693RefreshToken {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("The '%s' token type is not supported as a '%s' when the '%s' is '%s'.", consts.TokenTypeRFC8693RefreshToken, consts.FormParameterActorTokenType, consts.FormParameterRequestedTokenType, consts.TokenTypeRFC8693TxnToken))
	}

	if subjectTokenType == consts.TokenTypeRFC8693RefreshToken || refused {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("The '%s' token type is not supported as a '%s' when the '%s' is '%s'.", subjectTokenType, consts.FormParameterSubjectTokenType, consts.FormParameterRequestedTokenType, consts.TokenTypeRFC8693TxnToken))
	}

	// The 'act' of the presented token is carried, and a new actor would rewrite the delegation it records.
	if replacing && form.Get(consts.FormParameterActorToken) != "" {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("The '%s' parameter is not supported when the '%s' is '%s'.", consts.FormParameterActorToken, consts.FormParameterSubjectTokenType, consts.TokenTypeRFC8693TxnToken))
	}

	if tokenType.TrustDomain == "" {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebugf("The '%s' token type has no Trust Domain configured.", tokenType.Name))
	}

	// The 'audience' is exactly the Trust Domain, and 'resource' is not used (section 11.1).
	audience := request.GetRequestedAudience()

	switch {
	case len(audience) == 0:
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("The '%s' parameter is required.", consts.FormParameterAudience))
	case len(audience) != 1 || audience[0] != tokenType.TrustDomain:
		return errorsx.WithStack(oauth2.ErrInvalidTarget.WithHintf("The '%s' parameter must be exactly the Trust Domain.", consts.FormParameterAudience))
	}

	if len(request.GetRequestedResource()) != 0 {
		return errorsx.WithStack(oauth2.ErrInvalidTarget.WithHintf("The '%s' parameter is not supported when the '%s' is '%s'.", consts.FormParameterResource, consts.FormParameterRequestedTokenType, consts.TokenTypeRFC8693TxnToken))
	}

	// The 'scope' parameter is required (section 11.1).
	if len(request.GetRequestedScopes()) == 0 {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("The '%s' parameter is required.", consts.FormParameterScope))
	}

	for _, name := range []string{consts.FormParameterRequestContext, consts.FormParameterRequestDetails} {
		if _, err = parseTxnTokenParameter(form, name); err != nil {
			return err
		}
	}

	return nil
}

// parseTxnTokenParameter returns the JSON object in a form parameter, nil when it is absent. A value that is not a JSON
// object is refused.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-11#section-11.1
func parseTxnTokenParameter(form url.Values, name string) (value map[string]any, err error) {
	if !form.Has(name) {
		return nil, nil
	}

	decoder := json.NewDecoder(strings.NewReader(form.Get(name)))
	decoder.UseNumber()

	if err = decoder.Decode(&value); err != nil || value == nil {
		return nil, errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("The '%s' parameter must be a JSON object.", name))
	}

	if _, err = decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errorsx.WithStack(oauth2.ErrInvalidRequest.WithHintf("The '%s' parameter must be a JSON object.", name))
	}

	return value, nil
}
