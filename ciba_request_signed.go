// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

var (
	// cibaSignedRequestFormParameters are the parameters a signed authentication request keeps outside of the JWT: the
	// request itself and the parameters of the client authentication method.
	//
	// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1.1
	cibaSignedRequestFormParameters = []string{
		consts.FormParameterRequest,
		consts.FormParameterClientID,
		consts.FormParameterClientAssertion,
		consts.FormParameterClientAssertionType,
		consts.FormParameterClientSecret,
	}

	// cibaAuthenticationRequestParameters are the authentication request parameters this endpoint recognises, which a
	// signed authentication request must only include within the JWT.
	//
	// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1.1
	cibaAuthenticationRequestParameters = []string{
		consts.FormParameterScope,
		consts.FormParameterClientNotificationToken,
		consts.FormParameterAuthenticationContextClassReferenceValues,
		consts.FormParameterLoginHintToken,
		consts.FormParameterIDTokenHint,
		consts.FormParameterLoginHint,
		consts.FormParameterBindingMessage,
		consts.FormParameterUserCode,
		consts.FormParameterRequestedExpiry,
		consts.FormParameterRequestContext,
		consts.FormParameterResource,
		consts.FormParameterAudience,
		consts.FormParameterAuthorizationDetails,
		consts.FormParameterDPoPJKT,
		consts.FormParameterNonce,
		consts.FormParameterClaims,
	}
)

const cibaSignedRequestJTIPrefix = "ciba-request:"

// decodeBackChannelSignedRequest decodes a signed authentication request and returns its parameters and its raw
// 'request_context'.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1.1
//
//nolint:gocyclo
func (f *Fosite) decodeBackChannelSignedRequest(ctx context.Context, client Client, form url.Values) (params url.Values, requestContext json.RawMessage, err error) {
	var alg string

	if c, ok := client.(CIBAClient); ok {
		alg = c.GetBackChannelAuthenticationRequestSigningAlg()
	}

	assertion := form.Get(consts.FormParameterRequest)

	// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.4
	switch {
	case alg == "":
		return nil, nil, errorsx.WithStack(ErrInvalidRequest.WithHint("The OAuth 2.0 Client must register the 'backchannel_authentication_request_signing_alg' client metadata to send a signed authentication request.").WithDebugf("The client with id '%s' sent a signed authentication request without a registered signing algorithm.", client.GetID()))
	case assertion == "":
		return nil, nil, errorsx.WithStack(ErrInvalidRequest.WithHint("The OAuth 2.0 Client registered the 'backchannel_authentication_request_signing_alg' client metadata and must send a signed authentication request.").WithDebugf("The client with id '%s' registered the signing algorithm '%s' but did not include the 'request' parameter.", client.GetID(), alg))
	}

	// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.2
	for key := range form {
		if slices.Contains(cibaAuthenticationRequestParameters, key) {
			return nil, nil, errorsx.WithStack(ErrInvalidRequest.WithHintf("The '%s' parameter must not be included outside of the signed authentication request.", key))
		}
	}

	if strings.Count(assertion, ".") == 4 {
		return nil, nil, errorsx.WithStack(ErrInvalidRequest.WithHint("The signed authentication request must be signed and not encrypted."))
	}

	if alg == consts.JSONWebTokenAlgNone || jwt.IsSignedJWTClientSecretAlgStr(alg) {
		return nil, nil, errorsx.WithStack(ErrInvalidRequest.WithHint("The signed authentication request must use an asymmetric signature algorithm.").WithDebugf("The client with id '%s' registered the signing algorithm '%s'.", client.GetID(), alg))
	}

	if !slices.Contains(fapi2SigningAlgValues(client, f.Config.GetCIBARequestSigningAlgValues(ctx)), alg) {
		return nil, nil, errorsx.WithStack(ErrInvalidRequest.WithHint("The 'backchannel_authentication_request_signing_alg' registered for the OAuth 2.0 Client is not supported.").WithDebugf("The client with id '%s' registered the signing algorithm '%s'.", client.GetID(), alg))
	}

	keys, ok := client.(jwt.BaseClient)
	if !ok {
		return nil, nil, errorsx.WithStack(ErrInvalidRequest.WithHint("The OAuth 2.0 Client does not have any JSON Web Keys to verify the signed authentication request.").WithDebugf("The client with id '%s' does not implement JSON Web Key retrieval.", client.GetID()))
	}

	token, err := f.Config.GetJWTStrategy(ctx).Decode(ctx, assertion, jwt.WithSigAlgorithm(jose.SignatureAlgorithm(alg)), jwt.WithClient(&cibaRequestJWTClient{BaseClient: keys, alg: alg}))
	if err != nil {
		return nil, nil, errorsx.WithStack(ErrInvalidRequest.WithHint("The signed authentication request could not be verified.").WithWrap(err).WithDebugError(err))
	}

	if err = token.Valid(jwt.ValidateTypes(jwt.JSONWebTokenTypeJWT), jwt.ValidateAllowEmptyType(true), jwt.ValidateAlgorithm(alg)); err != nil {
		return nil, nil, errorsx.WithStack(ErrInvalidRequest.WithHint("The signed authentication request could not be verified.").WithWrap(err).WithDebugError(err))
	}

	issuer := f.Config.GetIssuer(ctx)

	if issuer == "" {
		return nil, nil, errorsx.WithStack(ErrServerError.WithHint("The signed authentication request could not be processed due to an authorization server configuration issue.").WithDebug("The issuer for this authorization server is not known."))
	}

	claims := token.Claims.ToMapClaims()

	if err = claims.Valid(
		jwt.ValidateTimeFunc(func() time.Time { return time.Now().UTC() }),
		jwt.ValidateClockSkew(f.Config.GetJWTClockSkew(ctx)),
		jwt.ValidateIssuer(client.GetID()),
		jwt.ValidateAudienceAny(issuer),
		jwt.ValidateRequireExpiresAt(),
		jwt.ValidateRequireIssuedAt(),
		jwt.ValidateRequireNotBefore(),
	); err != nil {
		return nil, nil, errorsx.WithStack(ErrInvalidRequest.WithHint("The signed authentication request has invalid claims; the 'iss', 'aud', 'exp', 'iat' and 'nbf' claims are required.").WithWrap(err).WithDebugError(err))
	}

	// See: https://openid.net/specs/fapi-ciba.html#section-4.1.1
	if maximum := f.Config.GetCIBASignedRequestMaximumLifetime(ctx); maximum > 0 {
		exp, _ := claims.GetExpirationTime()
		nbf, _ := claims.GetNotBefore()

		if exp == nil || nbf == nil || exp.Sub(nbf.Time) > maximum {
			return nil, nil, errorsx.WithStack(ErrInvalidRequest.WithHintf("The signed authentication request lifetime between the 'nbf' and 'exp' claims must not exceed %s.", maximum).WithDebugf("The client with id '%s' sent a signed authentication request whose 'nbf' and 'exp' claims exceed the maximum lifetime.", client.GetID()))
		}
	}

	jti, _ := claims[consts.ClaimJWTID].(string)

	if jti == "" {
		return nil, nil, errorsx.WithStack(ErrInvalidRequest.WithHint("The signed authentication request must include the 'jti' claim."))
	}

	var raw map[string]json.RawMessage

	if err = token.UnsafeClaimsWithoutVerification(&raw); err != nil {
		return nil, nil, errorsx.WithStack(ErrInvalidRequest.WithHint("The signed authentication request claims could not be decoded.").WithWrap(err).WithDebugError(err))
	}

	if params, requestContext, err = cibaSignedRequestParameters(client, claims, raw); err != nil {
		return nil, nil, err
	}

	jti = cibaSignedRequestJTIPrefix + jti

	if err = f.Store.ClientAssertionJWTValid(ctx, client.GetID(), jti); err != nil {
		return nil, nil, errorsx.WithStack(ErrInvalidRequest.WithHint("The 'jti' claim of the signed authentication request must only be used once.").WithWrap(err).WithDebugError(err))
	}

	exp, _ := claims.GetExpirationTime()

	if err = f.Store.SetClientAssertionJWT(ctx, client.GetID(), jti, time.Unix(exp.Unix(), 0)); errors.Is(err, ErrJTIKnown) {
		return nil, nil, errorsx.WithStack(ErrInvalidRequest.WithHint("The 'jti' claim of the signed authentication request must only be used once.").WithWrap(err).WithDebugError(err))
	} else if err != nil {
		return nil, nil, errorsx.WithStack(ErrServerError.WithWrap(err).WithDebugError(err))
	}

	return params, requestContext, nil
}

// cibaSignedRequestParameters maps the claims of a signed authentication request to the authentication request
// parameters. 'requested_expiry' is a JSON string or number, and 'authorization_details' and 'request_context' keep
// their JSON text.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1.1
//
//nolint:gocyclo
func cibaSignedRequestParameters(client Client, claims jwt.MapClaims, raw map[string]json.RawMessage) (params url.Values, requestContext json.RawMessage, err error) {
	params = url.Values{}

	var value string

	for k, v := range claims {
		switch k {
		case consts.ClaimIssuer, consts.ClaimAudience, consts.ClaimExpirationTime, consts.ClaimIssuedAt, consts.ClaimNotBefore, consts.ClaimJWTID, consts.ClaimSubject:
			continue
		case consts.FormParameterRequest, consts.FormParameterRequestURI, consts.FormParameterClientAssertion, consts.FormParameterClientAssertionType, consts.FormParameterClientSecret:
			return nil, nil, errorsx.WithStack(ErrInvalidRequest.WithHintf("The signed authentication request must not include the '%s' claim.", k))
		case consts.FormParameterClientID:
			if value, _ = v.(string); value != client.GetID() {
				return nil, nil, errorsx.WithStack(ErrInvalidRequest.WithHint("The 'client_id' claim of the signed authentication request must match the authenticated OAuth 2.0 Client.").WithDebugf("The client with id '%s' sent a signed authentication request with the 'client_id' claim '%v'.", client.GetID(), v))
			}
		case consts.FormParameterRequestContext:
			if isJSONNull(raw[k]) {
				continue
			}

			var object map[string]json.RawMessage

			if err = json.Unmarshal(raw[k], &object); err != nil || object == nil {
				return nil, nil, errorsx.WithStack(ErrInvalidRequest.WithHint("The 'request_context' claim must be a JSON object."))
			}

			requestContext = slices.Clone(raw[k])

			params.Set(k, string(requestContext))
		case consts.FormParameterRequestedExpiry:
			if value, err = cibaRequestedExpiryFormValue(raw[k]); err != nil {
				return nil, nil, err
			}

			params.Set(k, value)
		case consts.FormParameterAuthorizationDetails:
			if value, err = requestObjectJSONFormValue(raw[k]); err != nil {
				return nil, nil, errorsx.WithStack(ErrInvalidRequest.WithHintf("The '%s' claim of the signed authentication request could not be decoded.", k).WithWrap(err).WithDebugError(err))
			}

			params.Set(k, value)
		case consts.FormParameterResource, consts.FormParameterAudience:
			var values []string

			if values, err = requestObjectFormValues(v); err != nil {
				return nil, nil, errorsx.WithStack(ErrInvalidRequest.WithHintf("The '%s' claim of the signed authentication request must be a string or an array of strings.", k).WithWrap(err).WithDebugError(err))
			}

			params[k] = values
		default:
			if value, err = requestObjectFormValue(v); err != nil {
				return nil, nil, errorsx.WithStack(ErrInvalidRequest.WithHintf("The '%s' claim of the signed authentication request could not be decoded.", k).WithWrap(err).WithDebugError(err))
			}

			params.Set(k, value)
		}
	}

	return params, requestContext, nil
}

// cibaRequestedExpiryFormValue maps the 'requested_expiry' claim to its form value. A JSON number with a positive
// integer value in any notation is written in decimal digits, and a value too large to represent is written as the
// largest representable number of seconds.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1.1
func cibaRequestedExpiryFormValue(raw json.RawMessage) (value string, err error) {
	if isJSONNull(raw) {
		return "", nil
	}

	if err = json.Unmarshal(raw, &value); err == nil {
		return value, nil
	}

	var number json.Number

	if err = json.Unmarshal(raw, &number); err != nil {
		return "", errorsx.WithStack(ErrInvalidRequest.WithHint("The 'requested_expiry' claim of the signed authentication request must be a JSON string or number.").WithWrap(err).WithDebugError(err))
	}

	const maximum = math.MaxInt64 / int64(time.Second)

	seconds, err := strconv.ParseFloat(number.String(), 64)

	switch {
	case err != nil, seconds <= 0, seconds != math.Trunc(seconds):
		return "", errorsx.WithStack(ErrInvalidRequest.WithHint("The 'requested_expiry' parameter must be a positive integer."))
	case seconds >= float64(maximum):
		return strconv.FormatInt(maximum, 10), nil
	default:
		return strconv.FormatInt(int64(seconds), 10), nil
	}
}

// cibaRequestJWTClient adapts a Client to a jwt.Client which verifies a signed authentication request with the
// client's registered algorithm and JSON Web Keys.
type cibaRequestJWTClient struct {
	jwt.BaseClient

	alg string
}

func (c *cibaRequestJWTClient) GetSigningKeyID() (kid string) {
	return ""
}

func (c *cibaRequestJWTClient) GetSigningAlg() (alg string) {
	return c.alg
}

func (c *cibaRequestJWTClient) GetEncryptionKeyID() (kid string) {
	return ""
}

func (c *cibaRequestJWTClient) GetEncryptionAlg() (alg string) {
	return ""
}

func (c *cibaRequestJWTClient) GetEncryptionEnc() (enc string) {
	return ""
}

func (c *cibaRequestJWTClient) IsClientSigned() (is bool) {
	return true
}

func (c *cibaRequestJWTClient) IsClientIDMetadataDocumentClient() (is bool) {
	return jwt.IsClientIDMetadataDocumentClient(c.BaseClient)
}
