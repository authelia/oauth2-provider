// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7591

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"maps"
	"reflect"
	"slices"
	"strings"

	josejwt "authelia.com/provider/jose/jwt"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

type softwareStatementConfig interface {
	oauth2.RFC7591ClientRegistrationPolicyProvider
	oauth2.JWKSFetcherStrategyProvider
}

var softwareStatementExcludedClaims = []string{
	consts.ClaimIssuer,
	consts.ClaimSubject,
	consts.ClaimAudience,
	consts.ClaimExpirationTime,
	consts.ClaimNotBefore,
	consts.ClaimIssuedAt,
	consts.ClaimJWTID,
	consts.ClientMetadataSoftwareStatement,
	consts.ClientRegistrationResponseClientID,
	consts.ClientRegistrationResponseClientSecret,
	consts.ClientRegistrationResponseClientIDIssuedAt,
	consts.ClientRegistrationResponseClientSecretExpiresAt,
	consts.ClientRegistrationResponseRegistrationAccessToken,
	consts.ClientRegistrationResponseRegistrationClientURI,
}

func applySoftwareStatement(ctx context.Context, config softwareStatementConfig, metadata *oauth2.ClientRegistrationMetadata) (err error) {
	if metadata == nil {
		return nil
	}

	metadata.SoftwareStatementMembers = nil

	if metadata.SoftwareStatement == "" {
		return nil
	}

	statement := metadata.SoftwareStatement

	if strings.Count(statement, ".") != 2 {
		return errInvalidSoftwareStatement(errors.New("the software statement is not a signed JWT"))
	}

	var approved *oauth2.RFC7591TrustedIssuer

	if approved, err = approvedSoftwareStatementIssuer(ctx, config, statement); err != nil {
		return err
	}

	strategy := &jwt.DefaultStrategy{Config: config}

	var token *jwt.Token

	if token, err = strategy.Decode(ctx, statement, jwt.WithSigAlgorithm(trustedIssuerSignatureAlgorithms...), jwt.WithKeyFunc(jwksKeyFunc(config, approved.JSONWebKeysURI))); err != nil {
		if isKeySourceFailure(err) {
			return errorsx.WithStack(oauth2.ErrServerError.WithHint("The keys of the software statement issuer could not be retrieved.").WithWrap(err).WithDebugError(err))
		}

		return errInvalidSoftwareStatement(err)
	}

	if err = token.Valid(
		jwt.ValidateTypes(config.GetRFC7591SoftwareStatementJWTValidationHeaderAllowTypes(ctx)...),
		jwt.ValidateAllowEmptyType(config.GetRFC7591SoftwareStatementJWTValidationHeaderAllowEmptyType(ctx)),
	); err != nil {
		return errInvalidSoftwareStatement(err)
	}

	if err = token.Claims.Valid(jwt.ValidateIssuer(approved.Issuer)); err != nil {
		return errInvalidSoftwareStatement(err)
	}

	claims := token.Claims.ToMapClaims()

	if config.GetRFC7591SoftwareStatementRequireSoftwareID(ctx) {
		if id, ok := claims[consts.ClientMetadataSoftwareID].(string); !ok || id == "" {
			return errInvalidSoftwareStatement(errors.New("the software statement does not have a 'software_id' claim"))
		}
	}

	var (
		merged  *oauth2.ClientRegistrationMetadata
		members []string
	)

	if merged, members, err = mergeSoftwareStatement(metadata, claims); err != nil {
		return errInvalidSoftwareStatement(err)
	}

	merged.SoftwareStatement = statement
	merged.SoftwareStatementMembers = members

	*metadata = *merged

	return nil
}

func approvedSoftwareStatementIssuer(ctx context.Context, config softwareStatementConfig, statement string) (approved *oauth2.RFC7591TrustedIssuer, err error) {
	var parsed *josejwt.JSONWebToken

	if parsed, err = josejwt.ParseSigned(statement, trustedIssuerSignatureAlgorithms); err != nil {
		return nil, errInvalidSoftwareStatement(err)
	}

	var claims struct {
		Issuer string `json:"iss"`
	}

	if err = parsed.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return nil, errInvalidSoftwareStatement(err)
	}

	if claims.Issuer == "" {
		return nil, errInvalidSoftwareStatement(errors.New("the software statement does not have an 'iss' claim"))
	}

	for _, issuer := range config.GetRFC7591SoftwareStatementIssuers(ctx) {
		if issuer.Issuer == "" || issuer.JSONWebKeysURI == "" || issuer.Issuer != claims.Issuer {
			continue
		}

		return &issuer, nil
	}

	return nil, errorsx.WithStack(oauth2.ErrUnapprovedSoftwareStatement.WithHintf("The software statement issuer '%s' is not approved.", claims.Issuer))
}

func mergeSoftwareStatement(metadata *oauth2.ClientRegistrationMetadata, claims jwt.MapClaims) (merged *oauth2.ClientRegistrationMetadata, members []string, err error) {
	var data []byte

	if data, err = json.Marshal(metadata); err != nil {
		return nil, nil, err
	}

	values := map[string]any{}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()

	if err = decoder.Decode(&values); err != nil {
		return nil, nil, err
	}

	preserveEmptyMetadataArrays(metadata, values)

	for name := range claims {
		if slices.Contains(softwareStatementExcludedClaims, name) {
			continue
		}

		maps.DeleteFunc(values, func(key string, _ any) bool {
			return strings.EqualFold(key, name)
		})

		members = append(members, name)
	}

	slices.Sort(members)

	for _, name := range members {
		values[name] = claims[name]
	}

	if data, err = json.Marshal(values); err != nil {
		return nil, nil, err
	}

	merged = &oauth2.ClientRegistrationMetadata{}

	if err = json.Unmarshal(data, merged); err != nil {
		return nil, nil, err
	}

	return merged, members, nil
}

func preserveEmptyMetadataArrays(metadata *oauth2.ClientRegistrationMetadata, values map[string]any) {
	fields := reflect.ValueOf(metadata).Elem()

	for i := range fields.NumField() {
		field := fields.Field(i)

		if field.Kind() != reflect.Slice || field.IsNil() || field.Len() != 0 {
			continue
		}

		if name, _, _ := strings.Cut(fields.Type().Field(i).Tag.Get("json"), ","); name != "" && name != "-" {
			values[name] = []any{}
		}
	}
}

func isKeySourceFailure(err error) bool {
	var verr *jwt.ValidationError

	return errors.As(err, &verr) && errors.Is(verr.Inner, oauth2.ErrServerError)
}

func errInvalidSoftwareStatement(err error) error {
	return errorsx.WithStack(oauth2.ErrInvalidSoftwareStatement.WithHint("The software statement could not be validated.").WithWrap(err).WithDebugError(err))
}
