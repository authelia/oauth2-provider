// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
)

func TestToken_Valid(t *testing.T) {
	testCases := []struct {
		name   string
		have   *Token
		opts   []HeaderValidationOption
		errors uint32
		err    string
	}{
		{
			name:   "ShouldErrorNoTyp",
			have:   &Token{valid: true},
			errors: ValidationErrorHeaderTypeInvalid,
			err:    "token was signed with an invalid typ",
		},
		{
			name: "ShouldNotErrorNoTyp",
			have: &Token{valid: true},
			opts: []HeaderValidationOption{ValidateAllowEmptyType(true)},
		},
		{
			name: "ShouldNotErrorTypNormal",
			have: &Token{valid: true, Header: map[string]any{consts.JSONWebTokenHeaderType: consts.JSONWebTokenTypeJWT}},
			opts: []HeaderValidationOption{ValidateTypes(consts.JSONWebTokenTypeJWT)},
		},
		{
			name: "ShouldNotErrorTypLowerCase",
			have: &Token{valid: true, Header: map[string]any{consts.JSONWebTokenHeaderType: "jwt"}},
			opts: []HeaderValidationOption{ValidateTypes(consts.JSONWebTokenTypeJWT)},
		},
		{
			name:   "ShouldErrorInvalidSignature",
			have:   &Token{valid: false},
			opts:   []HeaderValidationOption{ValidateAllowEmptyType(true)},
			errors: ValidationErrorSignatureInvalid,
			err:    "token has an invalid or unverified signature",
		},
		{
			name:   "ShouldErrorInvalidAlg",
			have:   &Token{valid: true},
			opts:   []HeaderValidationOption{ValidateAllowEmptyType(true), ValidateAlgorithm("RS256")},
			errors: ValidationErrorHeaderAlgorithmInvalid,
			err:    "token was signed with an invalid alg",
		},
		{
			name: "ShouldNotErrorValidAlg",
			have: &Token{valid: true, SignatureAlgorithm: "RS256"},
			opts: []HeaderValidationOption{ValidateAllowEmptyType(true), ValidateAlgorithm("RS256")},
		},
		{
			name:   "ShouldErrorInvalidKID",
			have:   &Token{valid: true},
			opts:   []HeaderValidationOption{ValidateAllowEmptyType(true), ValidateKeyID("abc")},
			errors: ValidationErrorHeaderKeyIDInvalid,
			err:    "token was signed with an invalid kid",
		},
		{
			name: "ShouldNotErrorValidKID",
			have: &Token{valid: true, KeyID: "abc"},
			opts: []HeaderValidationOption{ValidateAllowEmptyType(true), ValidateKeyID("abc")},
		},
		{
			name:   "ShouldErrorInvalidKeyAlgorithm",
			have:   &Token{valid: true, KeyAlgorithm: jose.RSA_OAEP},
			opts:   []HeaderValidationOption{ValidateAllowEmptyType(true), ValidateKeyAlgorithm("RSA-OAEP-256")},
			errors: ValidationErrorHeaderKeyAlgorithmInvalid,
			err:    "token was encrypted with an invalid alg",
		},
		{
			name: "ShouldNotErrorValidKeyAlgorithm",
			have: &Token{valid: true, KeyAlgorithm: jose.RSA_OAEP_256},
			opts: []HeaderValidationOption{ValidateAllowEmptyType(true), ValidateKeyAlgorithm("RSA-OAEP-256")},
		},
		{
			name: "ShouldNotErrorAbsentKeyAlgorithm",
			have: &Token{valid: true},
			opts: []HeaderValidationOption{ValidateAllowEmptyType(true), ValidateKeyAlgorithm("RSA-OAEP-256")},
		},
		{
			name:   "ShouldErrorInvalidCEK",
			have:   &Token{valid: true, ContentEncryption: jose.A192CBC_HS384},
			opts:   []HeaderValidationOption{ValidateAllowEmptyType(true), ValidateContentEncryption("A128CBC-HS256")},
			errors: ValidationErrorHeaderContentEncryptionInvalid,
			err:    "token was encrypted with an invalid enc",
		},
		{
			name: "ShouldNotErrorValidCEK",
			have: &Token{valid: true, ContentEncryption: jose.A128CBC_HS256},
			opts: []HeaderValidationOption{ValidateAllowEmptyType(true), ValidateContentEncryption("A128CBC-HS256")},
		},
		{
			name: "ShouldNotErrorAbsentCEK",
			have: &Token{valid: true},
			opts: []HeaderValidationOption{ValidateAllowEmptyType(true), ValidateContentEncryption("A128CBC-HS256")},
		},
		{
			name:   "ShouldErrorInvalidEncKID",
			have:   &Token{valid: true, EncryptionKeyID: "abc"},
			opts:   []HeaderValidationOption{ValidateAllowEmptyType(true), ValidateEncryptionKeyID("123")},
			errors: ValidationErrorHeaderEncryptionKeyIDInvalid,
			err:    "token was encrypted with an invalid kid",
		},
		{
			name: "ShouldNotErrorValidEncKID",
			have: &Token{valid: true, EncryptionKeyID: "abc"},
			opts: []HeaderValidationOption{ValidateAllowEmptyType(true), ValidateEncryptionKeyID("abc")},
		},
		{
			name: "ShouldNotErrorAbsentEncKID",
			have: &Token{valid: true},
			opts: []HeaderValidationOption{ValidateAllowEmptyType(true), ValidateEncryptionKeyID("abc")},
		},
		{
			name: "ShouldNotErrorValidCtyTyp",
			have: &Token{
				valid:     true,
				Header:    map[string]any{consts.JSONWebTokenHeaderType: "JWT"},
				HeaderJWE: map[string]any{consts.JSONWebTokenHeaderType: "JWT", consts.JSONWebTokenHeaderContentType: "JWT"},
			},
			opts: []HeaderValidationOption{ValidateAllowEmptyType(true)},
		},
		{
			name: "ShouldNotErrorInvalidJWETyp",
			have: &Token{
				valid:     true,
				Header:    map[string]any{consts.JSONWebTokenHeaderType: "JWT"},
				HeaderJWE: map[string]any{consts.JSONWebTokenHeaderType: "JWT", consts.JSONWebTokenHeaderContentType: "JWT"},
			},
			opts: []HeaderValidationOption{ValidateAllowEmptyType(true)},
		},
		{
			name: "ShouldErrorInvalidJWETypCty",
			have: &Token{
				valid:             true,
				ContentEncryption: jose.A128CBC_HS256,
				KeyAlgorithm:      jose.RSA_OAEP_256,
				Header:            map[string]any{consts.JSONWebTokenHeaderType: "a"},
				HeaderJWE:         map[string]any{consts.JSONWebTokenHeaderType: "a", consts.JSONWebTokenHeaderContentType: "a"},
			},
			opts:   []HeaderValidationOption{ValidateAllowEmptyType(true), ValidateTypes("x")},
			errors: ValidationErrorHeaderTypeInvalid + ValidationErrorHeaderContentTypeInvalid + ValidationErrorHeaderEncryptionTypeInvalid,
			err:    "token was signed with an invalid typ",
		},
		{
			name: "ShouldErrorInvalidJWEMismatchTypCty",
			have: &Token{
				valid:             true,
				ContentEncryption: jose.A128CBC_HS256,
				KeyAlgorithm:      jose.RSA_OAEP_256,
				Header:            map[string]any{consts.JSONWebTokenHeaderType: "a"},
				HeaderJWE:         map[string]any{consts.JSONWebTokenHeaderType: "JWT", consts.JSONWebTokenHeaderContentType: "c"},
			},
			opts:   []HeaderValidationOption{ValidateAllowEmptyType(true), ValidateTypes("a")},
			errors: ValidationErrorHeaderContentTypeInvalidMismatch + ValidationErrorHeaderContentTypeInvalid,
			err:    "token was encrypted with an invalid cty",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.have.Valid(tc.opts...)

			if tc.errors == 0 {
				assert.NoError(t, err)

				return
			}

			assert.EqualError(t, err, tc.err)

			e, ok := err.(*ValidationError)
			require.True(t, ok)
			assert.Equal(t, tc.errors, e.Errors)
		})
	}
}

func TestUnsignedToken(t *testing.T) {
	testCases := []struct {
		name         string
		jwtHeaders   map[string]any
		expectedType string
	}{
		{
			name:         "ShouldDefaultTypToJWTWhenNotInHeaders",
			jwtHeaders:   map[string]any{},
			expectedType: "JWT",
		},
		{
			name:         "ShouldUseExplicitTyp",
			jwtHeaders:   map[string]any{"typ": "at+jwt"},
			expectedType: "at+jwt",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			key := UnsafeAllowNoneSignatureType
			token := NewWithClaims(SigningMethodNone, MapClaims{
				"aud": "foo",
				"exp": time.Now().UTC().Add(time.Hour).Unix(),
				"iat": time.Now().UTC().Unix(),
				"sub": "nestor",
			})
			token.Header = tc.jwtHeaders
			rawToken, err := token.CompactSignedString(key)
			require.NoError(t, err)
			require.NotEmpty(t, rawToken)
			parts := strings.Split(rawToken, ".")
			require.Len(t, parts, 3)
			require.Empty(t, parts[2])
			tk, err := jwt.ParseSigned(rawToken, []jose.SignatureAlgorithm{JSONWebTokenAlgNone, jose.HS256, jose.HS384, jose.HS512, jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512, jose.ES256, jose.ES384, jose.ES512})
			require.NoError(t, err)
			require.Len(t, tk.Headers, 1)
			require.Equal(t, tc.expectedType, tk.Headers[0].ExtraHeaders[(JSONWebTokenHeaderType)])
		})
	}
}

func TestJWTHeaders(t *testing.T) {
	testCases := []struct {
		name         string
		jwtHeaders   map[string]any
		expectedType string
	}{
		{
			name:         "ShouldSetJWTAsHeaderTypWhenNotSpecified",
			jwtHeaders:   map[string]any{},
			expectedType: JSONWebTokenTypeJWT,
		},
		{
			name:         "ShouldUseExplicitHeaderTyp",
			jwtHeaders:   map[string]any{JSONWebTokenHeaderType: JSONWebTokenTypeAccessToken},
			expectedType: JSONWebTokenTypeAccessToken,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rawToken := makeSampleTokenWithCustomHeaders(nil, jose.RS256, tc.jwtHeaders, gen.MustRSAKey())
			tk, err := jwt.ParseSigned(rawToken, []jose.SignatureAlgorithm{jose.HS256, jose.HS384, jose.HS512, jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512, jose.ES256, jose.ES384, jose.ES512})
			require.NoError(t, err)
			require.Len(t, tk.Headers, 1)
			require.Equal(t, "RS256", tk.Headers[0].Algorithm)
			require.Equal(t, tc.expectedType, tk.Headers[0].ExtraHeaders[(JSONWebTokenHeaderType)])
		})
	}
}

var errKeyLoading = errors.New("error loading key")

var (
	jwtTestDefaultKey         = parseRSAPublicKeyFromPEM(defaultPubKeyPEM)
	defaultKeyFunc    Keyfunc = func(t *Token) (any, error) { return jwtTestDefaultKey, nil }
	emptyKeyFunc      Keyfunc = func(t *Token) (any, error) { return nil, nil }
	errorKeyFunc      Keyfunc = func(t *Token) (any, error) { return nil, errKeyLoading }
	nilKeyFunc        Keyfunc = nil
)

// Test cases related to json.Number where excluded because that is not supported by go-jose,
// it is not used here and therefore not supported.
//
//nolint:gocyclo
func TestParser_Parse(t *testing.T) {
	var (
		defaultES256PrivateKey = gen.MustES256Key()
		defaultSigningKey      = parseRSAPrivateKeyFromPEM(defaultPrivateKeyPEM)
		publicECDSAKey         = func(*Token) (any, error) { return &defaultES256PrivateKey.PublicKey, nil }
		noneKey                = func(*Token) (any, error) { return UnsafeAllowNoneSignatureType, nil }
		randomKey              = func(*Token) (any, error) {
			k, err := rsa.GenerateKey(rand.Reader, 2048)
			require.NoError(t, err)
			return &k.PublicKey, nil
		}
	)
	type expected struct {
		errors  uint32
		keyFunc Keyfunc
		valid   bool
		claims  MapClaims
	}
	type generate struct {
		claims     MapClaims
		signingKey any                     // defaultSigningKey
		method     jose.SignatureAlgorithm // default RS256
	}
	type given struct {
		name        string
		tokenString string
		generate    *generate
	}
	var jwtTestData = []struct {
		expected
		given
	}{
		{
			given: given{
				name:        "ShouldPassBasic",
				tokenString: "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
			},
			expected: expected{
				keyFunc: defaultKeyFunc,
				claims:  MapClaims{"foo": "bar"},
				valid:   true,
				errors:  0,
			},
		},
		{
			given: given{
				name: "ShouldFailExpired",
				generate: &generate{
					claims: MapClaims{"foo": "bar", "exp": time.Now().Unix() - 100},
				},
			},
			expected: expected{
				keyFunc: defaultKeyFunc,
				claims:  MapClaims{"foo": "bar", "exp": time.Now().Unix() - 100},
				valid:   false,
				errors:  ValidationErrorExpired,
			},
		},
		{
			given: given{
				name: "ShouldFailNotYetValid",
				generate: &generate{
					claims: MapClaims{"foo": "bar", "nbf": time.Now().Unix() + 100},
				},
			},
			expected: expected{
				keyFunc: defaultKeyFunc,
				claims:  MapClaims{"foo": "bar", "nbf": time.Now().Unix() + 100},
				valid:   false,
				errors:  ValidationErrorNotValidYet,
			},
		},
		{
			given: given{
				name: "ShouldFailExpiredAndNotYetValid",
				generate: &generate{
					claims: MapClaims{"foo": "bar", "nbf": time.Now().Unix() + 100, "exp": time.Now().Unix() - 100},
				},
			},
			expected: expected{
				keyFunc: defaultKeyFunc,
				claims:  MapClaims{"foo": "bar", "nbf": time.Now().Unix() + 100, "exp": time.Now().Unix() - 100},
				valid:   false,
				errors:  ValidationErrorNotValidYet | ValidationErrorExpired,
			},
		},
		{
			given: given{
				name:        "ShouldFailInvalidSignature",
				tokenString: "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.EhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
			},
			expected: expected{
				keyFunc: defaultKeyFunc,
				claims:  MapClaims{"foo": "bar"},
				valid:   false,
				errors:  ValidationErrorSignatureInvalid,
			},
		},
		{
			given: given{
				name:        "ShouldFailNilKeyFunc",
				tokenString: "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
			},
			expected: expected{
				keyFunc: nilKeyFunc,
				claims:  MapClaims{"foo": "bar"},
				valid:   false,
				errors:  ValidationErrorUnverifiable,
			},
		},
		{
			given: given{
				name:        "ShouldFailEmptyKey",
				tokenString: "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
			},
			expected: expected{
				keyFunc: emptyKeyFunc,
				claims:  MapClaims{"foo": "bar"},
				valid:   false,
				errors:  ValidationErrorSignatureInvalid,
			},
		},
		{
			given: given{
				name:        "ShouldFailErroringKeyFunc",
				tokenString: "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
				generate: &generate{
					claims: MapClaims{"foo": "bar"},
				},
			},
			expected: expected{
				keyFunc: errorKeyFunc,
				claims:  MapClaims{"foo": "bar"},
				valid:   false,
				errors:  ValidationErrorUnverifiable,
			},
		},
		{
			given: given{
				name: "ShouldPassValidSigningMethod",
				generate: &generate{
					claims: MapClaims{"foo": "bar"},
				},
			},
			expected: expected{
				keyFunc: defaultKeyFunc,
				claims:  MapClaims{"foo": "bar"},
				valid:   true,
				errors:  0,
			},
		},
		{
			given: given{
				name:        "ShouldFailMalformedToken",
				tokenString: "foo_invalid_token",
			},
			expected: expected{
				keyFunc: defaultKeyFunc,
				claims:  MapClaims(nil),
				valid:   false,
				errors:  ValidationErrorMalformed,
			},
		},
		{
			given: given{
				name:        "ShouldFailValidFormatInvalidContent",
				tokenString: "foo.bar.baz",
			},
			expected: expected{
				keyFunc: defaultKeyFunc,
				claims:  MapClaims(nil),
				valid:   false,
				errors:  ValidationErrorMalformed,
			},
		},
		{
			given: given{
				name:        "ShouldFailWrongKeyExpectedECDSAGotRSA",
				tokenString: "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
			},
			expected: expected{
				keyFunc: publicECDSAKey,
				claims:  MapClaims{"foo": "bar"},
				valid:   false,
				errors:  ValidationErrorSignatureInvalid,
			},
		},
		{
			given: given{
				name:        "ShouldFailRSAWithNoKey",
				tokenString: "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
			},
			expected: expected{
				keyFunc: emptyKeyFunc,
				claims:  MapClaims{"foo": "bar"},
				valid:   false,
				errors:  ValidationErrorSignatureInvalid,
			},
		},
		{
			given: given{
				name:        "ShouldFailKeyDoesNotMatch",
				tokenString: "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
			},
			expected: expected{
				keyFunc: randomKey,
				claims:  MapClaims{"foo": "bar"},
				valid:   false,
				errors:  ValidationErrorSignatureInvalid,
			},
		},
		{
			given: given{
				name: "ShouldFailUsedBeforeIssued",
				generate: &generate{
					claims: MapClaims{"foo": "bar", ClaimIssuedAt: time.Now().Unix() + 500},
				},
			},
			expected: expected{
				keyFunc: defaultKeyFunc,
				claims:  MapClaims{"foo": "bar", ClaimIssuedAt: time.Now().Unix() + 500},
				valid:   false,
				errors:  ValidationErrorIssuedAt,
			},
		},
		{
			given: given{
				name: "ShouldPassValidECDSASigningMethod",
				generate: &generate{
					claims:     MapClaims{"foo": "bar"},
					signingKey: defaultES256PrivateKey,
					method:     jose.ES256,
				},
			},
			expected: expected{
				keyFunc: publicECDSAKey,
				claims:  MapClaims{"foo": "bar"},
				valid:   true,
				errors:  0,
			},
		},
		{
			given: given{
				name: "ShouldPassValidNONESigningMethod",
				generate: &generate{
					claims:     MapClaims{"foo": "bar"},
					signingKey: UnsafeAllowNoneSignatureType,
					method:     SigningMethodNone,
				},
			},
			expected: expected{
				keyFunc: noneKey,
				claims:  MapClaims{"foo": "bar"},
				valid:   true,
				errors:  0,
			},
		},
		{
			given: given{
				name: "ShouldFailExpectedRS256GotNONE",
				generate: &generate{
					claims:     MapClaims{"foo": "bar"},
					signingKey: UnsafeAllowNoneSignatureType,
					method:     SigningMethodNone,
				},
			},
			expected: expected{
				keyFunc: defaultKeyFunc,
				claims:  MapClaims{"foo": "bar"},
				valid:   false,
				errors:  ValidationErrorSignatureInvalid,
			},
		},
		{
			given: given{
				name: "ShouldFailExpectedECDSAGotNONE",
				generate: &generate{
					claims:     MapClaims{"foo": "bar"},
					signingKey: UnsafeAllowNoneSignatureType,
					method:     SigningMethodNone,
				},
			},
			expected: expected{
				keyFunc: publicECDSAKey,
				claims:  MapClaims{"foo": "bar"},
				valid:   false,
				errors:  ValidationErrorSignatureInvalid,
			},
		},
	}

	// Iterate over test data set and run tests
	for _, data := range jwtTestData {
		t.Run(data.name, func(t *testing.T) {
			if data.generate != nil {
				signingKey := data.generate.signingKey
				method := data.generate.method
				if signingKey == nil {
					// use test defaults
					signingKey = defaultSigningKey
					method = jose.RS256
				}
				data.tokenString = makeSampleToken(data.generate.claims, method, signingKey)
			}

			// Parse the token
			var token *Token
			var err error

			// Figure out correct claims type
			token, err = ParseWithClaims(data.tokenString, MapClaims{}, data.keyFunc)
			// Verify result matches expectation
			assert.EqualValues(t, data.claims, token.Claims.ToMapClaims())
			if data.valid && err != nil {
				t.Errorf("[%v] Error while verifying token: %T:%v", data.name, err, err)
			}

			if !data.valid && err == nil {
				t.Errorf("[%v] Invalid token passed validation", data.name)
			}

			if (err == nil && !token.IsSignatureValid()) || (err != nil && token.IsSignatureValid()) {
				t.Errorf("[%v] Inconsistent behavior between returned error and token.Valid", data.name)
			}

			if data.errors != 0 {
				if err == nil {
					t.Errorf("[%v] Expecting error.  Didn't get one.", data.name)
				} else {
					ve := err.(*ValidationError)
					// compare the bitfield part of the error
					if e := ve.Errors; e != data.errors {
						t.Errorf("[%v] Errors don't match expectation.  %v != %v", data.name, e, data.errors)
					}

					if err.Error() == errKeyLoading.Error() && ve.Inner != errKeyLoading {
						t.Errorf("[%v] Inner error does not match expectation.  %v != %v", data.name, ve.Inner, errKeyLoading)
					}
				}
			}
		})
	}
}

func makeSampleToken(c MapClaims, m jose.SignatureAlgorithm, key any) string {
	token := NewWithClaims(m, c)
	s, e := token.CompactSignedString(key)

	if e != nil {
		panic(e.Error())
	}

	return s
}

func makeSampleTokenWithCustomHeaders(c MapClaims, m jose.SignatureAlgorithm, headers map[string]any, key any) string {
	token := NewWithClaims(m, c)
	token.Header = headers
	s, e := token.CompactSignedString(key)

	if e != nil {
		panic(e.Error())
	}

	return s
}

func parseRSAPublicKeyFromPEM(key []byte) *rsa.PublicKey {
	var err error

	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		panic("not possible to decode")
	}

	// Parse the key
	var parsedKey any
	if parsedKey, err = x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			parsedKey = cert.PublicKey
		} else {
			panic(err)
		}
	}

	var pkey *rsa.PublicKey
	var ok bool
	if pkey, ok = parsedKey.(*rsa.PublicKey); !ok {
		panic("not an *rsa.PublicKey")
	}

	return pkey
}

func parseRSAPrivateKeyFromPEM(key []byte) *rsa.PrivateKey {
	var err error

	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		panic("unable to decode")
	}

	var parsedKey any
	if parsedKey, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
			panic(err)
		}
	}

	var pkey *rsa.PrivateKey
	var ok bool
	if pkey, ok = parsedKey.(*rsa.PrivateKey); !ok {
		panic("not an rsa private key")
	}

	return pkey
}

func TestParse(t *testing.T) {
	signingKey := parseRSAPrivateKeyFromPEM(defaultPrivateKeyPEM)
	pubKey := parseRSAPublicKeyFromPEM(defaultPubKeyPEM)
	keyFunc := func(*Token) (any, error) { return pubKey, nil }

	t.Run("ShouldParseValidToken", func(t *testing.T) {
		raw := makeSampleToken(MapClaims{"foo": "bar"}, jose.RS256, signingKey)

		token, err := Parse(raw, keyFunc)
		require.NoError(t, err)
		require.NotNil(t, token)
		assert.True(t, token.IsSignatureValid())
	})

	t.Run("ShouldErrorOnInvalidToken", func(t *testing.T) {
		_, err := Parse("not-a-jwt", keyFunc)
		require.Error(t, err)
	})
}

func TestParseCustom(t *testing.T) {
	signingKey := parseRSAPrivateKeyFromPEM(defaultPrivateKeyPEM)
	pubKey := parseRSAPublicKeyFromPEM(defaultPubKeyPEM)
	keyFunc := func(*Token) (any, error) { return pubKey, nil }

	t.Run("ShouldParseWithRS256Restricted", func(t *testing.T) {
		raw := makeSampleToken(MapClaims{"foo": "bar"}, jose.RS256, signingKey)

		token, err := ParseCustom(raw, keyFunc, jose.RS256)
		require.NoError(t, err)
		assert.True(t, token.IsSignatureValid())
	})

	t.Run("ShouldErrorWhenAlgNotAllowed", func(t *testing.T) {
		raw := makeSampleToken(MapClaims{"foo": "bar"}, jose.RS256, signingKey)

		_, err := ParseCustom(raw, keyFunc, jose.ES256)
		require.Error(t, err)
	})
}

func TestParseCustomWithClaims_KeyFuncValidationErrorWrapping(t *testing.T) {
	signingKey := parseRSAPrivateKeyFromPEM(defaultPrivateKeyPEM)
	raw := makeSampleToken(MapClaims{"foo": "bar"}, jose.RS256, signingKey)

	wantedVE := &ValidationError{Errors: ValidationErrorUnverifiable, text: "wrapped"}
	keyFunc := func(*Token) (any, error) { return nil, wantedVE }

	_, err := ParseWithClaims(raw, MapClaims{}, keyFunc)
	require.Error(t, err)

	var ve *ValidationError
	require.ErrorAs(t, err, &ve)
	assert.Equal(t, "wrapped", ve.text)
}

func TestParseCustomWithClaims_NilKeyFromKeyFunc(t *testing.T) {
	signingKey := parseRSAPrivateKeyFromPEM(defaultPrivateKeyPEM)
	raw := makeSampleToken(MapClaims{"foo": "bar"}, jose.RS256, signingKey)

	keyFunc := func(*Token) (any, error) { return nil, nil }

	_, err := ParseWithClaims(raw, MapClaims{}, keyFunc)
	require.Error(t, err)

	var ve *ValidationError
	require.ErrorAs(t, err, &ve)
	assert.Equal(t, ValidationErrorSignatureInvalid, ve.Errors)
}

func TestToken_IsJWTProfileAccessToken(t *testing.T) {
	testCases := []struct {
		name     string
		token    *Token
		expected bool
	}{
		{
			name:     "ShouldReturnFalseWhenTypIsMissing",
			token:    &Token{Header: map[string]any{}},
			expected: false,
		},
		{
			name: "ShouldReturnTrueWhenTypIsAccessToken",
			token: &Token{
				Header: map[string]any{JSONWebTokenHeaderType: JSONWebTokenTypeAccessToken},
			},
			expected: true,
		},
		{
			name: "ShouldReturnFalseWhenTypIsJWT",
			token: &Token{
				Header: map[string]any{JSONWebTokenHeaderType: JSONWebTokenTypeJWT},
			},
			expected: false,
		},
		{
			name: "ShouldReturnTrueWithJWEContentTypeAccessToken",
			token: &Token{
				Header:    map[string]any{JSONWebTokenHeaderType: JSONWebTokenTypeAccessToken},
				HeaderJWE: map[string]any{JSONWebTokenHeaderContentType: JSONWebTokenTypeAccessToken},
			},
			expected: true,
		},
		{
			name: "ShouldReturnFalseWhenJWEContentTypeIsNotAccessToken",
			token: &Token{
				Header:    map[string]any{JSONWebTokenHeaderType: JSONWebTokenTypeAccessToken},
				HeaderJWE: map[string]any{JSONWebTokenHeaderContentType: JSONWebTokenTypeJWT},
			},
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.token.IsJWTProfileAccessToken())
		})
	}
}

func TestIsUnsafeNoneMagicConstant(t *testing.T) {
	t.Run("ShouldReturnTrueForRawConstant", func(t *testing.T) {
		assert.True(t, isUnsafeNoneMagicConstant(UnsafeAllowNoneSignatureType))
	})

	t.Run("ShouldReturnTrueForJWKWithConstant", func(t *testing.T) {
		jwk := jose.JSONWebKey{Key: UnsafeAllowNoneSignatureType}
		assert.True(t, isUnsafeNoneMagicConstant(jwk))
	})

	t.Run("ShouldReturnTrueForJWKPointerWithConstant", func(t *testing.T) {
		jwk := &jose.JSONWebKey{Key: UnsafeAllowNoneSignatureType}
		assert.True(t, isUnsafeNoneMagicConstant(jwk))
	})

	t.Run("ShouldReturnFalseForJWKWithOtherKey", func(t *testing.T) {
		jwk := jose.JSONWebKey{Key: []byte("not-none")}
		assert.False(t, isUnsafeNoneMagicConstant(jwk))
	})

	t.Run("ShouldReturnFalseForNonJWKValue", func(t *testing.T) {
		assert.False(t, isUnsafeNoneMagicConstant("string"))
	})
}

func TestValidateTokenTypeValue(t *testing.T) {
	testCases := []struct {
		name     string
		raw      any
		values   []string
		expected bool
	}{
		{
			name:     "ShouldReturnFalseForNonString",
			raw:      123,
			values:   []string{JSONWebTokenTypeJWT},
			expected: false,
		},
		{
			name:     "ShouldMatchSameCase",
			raw:      "JWT",
			values:   []string{"JWT"},
			expected: true,
		},
		{
			name:     "ShouldMatchCaseInsensitive",
			raw:      "jwt",
			values:   []string{"JWT"},
			expected: true,
		},
		{
			name:     "ShouldMatchApplicationPrefix",
			raw:      "application/jwt",
			values:   []string{"JWT"},
			expected: true,
		},
		{
			name:     "ShouldReturnFalseOnNoMatch",
			raw:      "other",
			values:   []string{"JWT"},
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, validateTokenTypeValue(tc.raw, tc.values...))
		})
	}
}

func TestToken_AssignJWE(t *testing.T) {
	t.Run("ShouldNotAlterTokenWhenJWENil", func(t *testing.T) {
		token := &Token{HeaderJWE: map[string]any{"existing": "value"}}
		token.AssignJWE(nil)
		assert.Equal(t, map[string]any{"existing": "value"}, token.HeaderJWE)
	})

	t.Run("ShouldPopulateFieldsFromJWEHeader", func(t *testing.T) {
		jwe := &jose.JSONWebEncryption{
			Header: jose.Header{
				Algorithm: string(jose.RSA_OAEP_256),
				KeyID:     "enc-kid",
				ExtraHeaders: map[jose.HeaderKey]any{
					JSONWebTokenHeaderEncryptionAlgorithm:  string(jose.A128CBC_HS256),
					JSONWebTokenHeaderCompressionAlgorithm: string(jose.DEFLATE),
					"custom":                               "value",
				},
			},
		}

		token := &Token{}
		token.AssignJWE(jwe)

		assert.Equal(t, "enc-kid", token.EncryptionKeyID)
		assert.Equal(t, jose.KeyAlgorithm(jose.RSA_OAEP_256), token.KeyAlgorithm)
		assert.Equal(t, jose.A128CBC_HS256, token.ContentEncryption)
		assert.Equal(t, jose.DEFLATE, token.CompressionAlgorithm)
		assert.Equal(t, "value", token.HeaderJWE["custom"])
		assert.Equal(t, "enc-kid", token.HeaderJWE[JSONWebTokenHeaderKeyIdentifier])
	})
}

func TestToken_CompactSignedString_ErrorPaths(t *testing.T) {
	t.Run("ShouldErrorOnInvalidKeyForSigner", func(t *testing.T) {
		token := NewWithClaims(jose.RS256, MapClaims{"foo": "bar"})
		_, err := token.CompactSignedString("not-a-real-key")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "error signing jwt")
	})

	t.Run("ShouldProduceUnsignedTokenForNoneMagicConstant", func(t *testing.T) {
		token := NewWithClaims(SigningMethodNone, MapClaims{"foo": "bar"})
		out, err := token.CompactSignedString(UnsafeAllowNoneSignatureType)
		require.NoError(t, err)
		assert.True(t, strings.HasSuffix(out, "."))
	})
}

func TestToken_CompactSigned_ReturnsSignature(t *testing.T) {
	signingKey := parseRSAPrivateKeyFromPEM(defaultPrivateKeyPEM)
	token := NewWithClaims(jose.RS256, MapClaims{"foo": "bar"})

	raw, sig, err := token.CompactSigned(signingKey)
	require.NoError(t, err)
	assert.NotEmpty(t, raw)
	assert.NotEmpty(t, sig)

	parts := strings.Split(raw, ".")
	require.Len(t, parts, 3)
	assert.Equal(t, parts[2], sig)
}

func TestToken_CompactSigned_PropagatesError(t *testing.T) {
	token := NewWithClaims(jose.RS256, MapClaims{"foo": "bar"})
	_, _, err := token.CompactSigned("not-a-real-key")
	require.Error(t, err)
}

func TestToken_CompactEncrypted_PropagatesSigningError(t *testing.T) {
	token := NewWithClaims(jose.RS256, MapClaims{"foo": "bar"})
	_, _, err := token.CompactEncrypted("not-a-real-key", nil)
	require.Error(t, err)
}

var (
	defaultPubKeyPEM = []byte(`
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4f5wg5l2hKsTeNem/V41
fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7
mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBp
HssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2
XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3b
ODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy
7wIDAQAB
-----END PUBLIC KEY-----`)
	defaultPrivateKeyPEM = []byte(`
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtn
SgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0i
cqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhC
PUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsAR
ap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKA
Rdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQABAoIBAQCwia1k7+2oZ2d3
n6agCAbqIE1QXfCmh41ZqJHbOY3oRQG3X1wpcGH4Gk+O+zDVTV2JszdcOt7E5dAy
MaomETAhRxB7hlIOnEN7WKm+dGNrKRvV0wDU5ReFMRHg31/Lnu8c+5BvGjZX+ky9
POIhFFYJqwCRlopGSUIxmVj5rSgtzk3iWOQXr+ah1bjEXvlxDOWkHN6YfpV5ThdE
KdBIPGEVqa63r9n2h+qazKrtiRqJqGnOrHzOECYbRFYhexsNFz7YT02xdfSHn7gM
IvabDDP/Qp0PjE1jdouiMaFHYnLBbgvlnZW9yuVf/rpXTUq/njxIXMmvmEyyvSDn
FcFikB8pAoGBAPF77hK4m3/rdGT7X8a/gwvZ2R121aBcdPwEaUhvj/36dx596zvY
mEOjrWfZhF083/nYWE2kVquj2wjs+otCLfifEEgXcVPTnEOPO9Zg3uNSL0nNQghj
FuD3iGLTUBCtM66oTe0jLSslHe8gLGEQqyMzHOzYxNqibxcOZIe8Qt0NAoGBAO+U
I5+XWjWEgDmvyC3TrOSf/KCGjtu0TSv30ipv27bDLMrpvPmD/5lpptTFwcxvVhCs
2b+chCjlghFSWFbBULBrfci2FtliClOVMYrlNBdUSJhf3aYSG2Doe6Bgt1n2CpNn
/iu37Y3NfemZBJA7hNl4dYe+f+uzM87cdQ214+jrAoGAXA0XxX8ll2+ToOLJsaNT
OvNB9h9Uc5qK5X5w+7G7O998BN2PC/MWp8H+2fVqpXgNENpNXttkRm1hk1dych86
EunfdPuqsX+as44oCyJGFHVBnWpm33eWQw9YqANRI+pCJzP08I5WK3osnPiwshd+
hR54yjgfYhBFNI7B95PmEQkCgYBzFSz7h1+s34Ycr8SvxsOBWxymG5zaCsUbPsL0
4aCgLScCHb9J+E86aVbbVFdglYa5Id7DPTL61ixhl7WZjujspeXZGSbmq0Kcnckb
mDgqkLECiOJW2NHP/j0McAkDLL4tysF8TLDO8gvuvzNC+WQ6drO2ThrypLVZQ+ry
eBIPmwKBgEZxhqa0gVvHQG/7Od69KWj4eJP28kq13RhKay8JOoN0vPmspXJo1HY3
CKuHRG+AP579dncdUnOMvfXOtkdM4vk0+hWASBQzM9xzVcztCa+koAugjVaLS9A+
9uQoqEeVNTckxx0S2bYevRy7hGQmUJTyQm3j1zEUR5jpdbL83Fbq
-----END RSA PRIVATE KEY-----`)
)
