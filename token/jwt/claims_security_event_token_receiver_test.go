// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package jwt_test

import (
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	. "authelia.com/provider/oauth2/token/jwt"
)

func TestSecurityEventTokenClaimsReceiver(t *testing.T) {
	const (
		head     = `{"iss":"https://transmitter.example.com","jti":"756E69717565206964656E746966696572","iat":1520364019,"aud":"636C69656E745F6964",`
		email    = `"sub_id":{"format":"email","email":"user@example.com"},`
		catalog  = `"sub_id":{"format":"catalog_item","catalog_id":"c0384/winter/2354122"},`
		event    = `"events":{"https://schemas.openid.net/secevent/caep/event-type/session-revoked":{"event_timestamp":1520364000}}}`
		sessions = `"events":{"https://schemas.openid.net/secevent/risc/event-type/sessions-revoked":{}}}`
	)

	now := ValidateTimeFunc(func() time.Time { return time.Unix(1520364020, 0) })

	testCases := []struct {
		name string
		have string
		// The validation error flags as a receiver and as a transmitter.
		receiver, transmitter uint32
	}{
		{"ShouldAcceptKnownSubjectFormat", head + email + event, 0, 0},
		{"ShouldAcceptUnknownSubjectFormat", head + catalog + event, 0, ValidationErrorClaimsInvalid},
		{"ShouldAcceptUndefinedSubjectMember", head + `"sub_id":{"format":"email","email":"user@example.com","extra":true},` + event, 0, 0},
		{"ShouldAcceptUnknownFormatOfComplexMember", head + `"sub_id":{"format":"complex","user":{"format":"email","email":"user@example.com"},"tenant":{"format":"catalog_item","catalog_id":"c0384"}},` + event, 0, ValidationErrorClaimsInvalid},
		{"ShouldAcceptComplexSubjectOfAdditionalMembersOnly", head + `"sub_id":{"format":"complex","catalog":{"format":"catalog_item","catalog_id":"c0384"}},` + event, 0, ValidationErrorClaimsInvalid},
		{"ShouldAcceptUnknownFormatOfAliases", head + `"sub_id":{"format":"aliases","identifiers":[{"format":"catalog_item","catalog_id":"c0384"},{"format":"catalog_item","catalog_id":"c0385"}]},` + event, 0, ValidationErrorClaimsInvalid},
		{"ShouldAcceptRISCSessionsRevoked", head + email + sessions, 0, ValidationErrorClaimsInvalid},
		{"ShouldAcceptRISCSessionsRevokedWithUnknownSubjectFormat", head + catalog + sessions, 0, ValidationErrorClaimsInvalid},
		{"ShouldAcceptUnknownEventType", head + email + `"events":{"https://example.com/event":{"count":18446744073709551616}}}`, 0, 0},
		{"ShouldRejectMissingSubjectIdentifier", head + event, ValidationErrorClaimsInvalid, ValidationErrorClaimsInvalid},
		{"ShouldRejectNullSubjectIdentifier", head + `"sub_id":null,` + event, ValidationErrorClaimsInvalid, ValidationErrorClaimsInvalid},
		{"ShouldRejectSubjectWithoutFormat", head + `"sub_id":{"email":"user@example.com"},` + event, ValidationErrorClaimsInvalid, ValidationErrorClaimsInvalid},
		{"ShouldRejectEmptyComplexSubject", head + `"sub_id":{"format":"complex"},` + event, ValidationErrorClaimsInvalid, ValidationErrorClaimsInvalid},
		{"ShouldRejectInvalidMemberOfKnownFormat", head + `"sub_id":{"format":"email","email":"not an email"},` + event, ValidationErrorClaimsInvalid, ValidationErrorClaimsInvalid},
		{"ShouldRejectMissingMemberOfKnownFormat", head + `"sub_id":{"format":"email","EMAIL":"user@example.com"},` + event, ValidationErrorClaimsInvalid, ValidationErrorClaimsInvalid},
		{"ShouldRejectInvalidKnownFormatOfComplexMember", head + `"sub_id":{"format":"complex","user":{"format":"email"}},` + event, ValidationErrorClaimsInvalid, ValidationErrorClaimsInvalid},
		{"ShouldRejectNestedComplexSubject", head + `"sub_id":{"format":"complex","user":{"format":"complex","catalog":{"format":"catalog_item"}}},` + event, ValidationErrorClaimsInvalid, ValidationErrorClaimsInvalid},
		{"ShouldRejectDuplicateAlias", head + `"sub_id":{"format":"aliases","identifiers":[{"format":"opaque","id":"x"},{"format":"opaque","id":"x"}]},` + event, ValidationErrorClaimsInvalid, ValidationErrorClaimsInvalid},
		{"ShouldRejectDuplicateAliasWithAdditionalMembers", head + `"sub_id":{"format":"aliases","identifiers":[{"format":"opaque","id":"x","extra":true},{"format":"opaque","id":"x","extra":true}]},` + event, ValidationErrorClaimsInvalid, ValidationErrorClaimsInvalid},
		{"ShouldRejectDuplicateAliasOfUnknownFormat", head + `"sub_id":{"format":"aliases","identifiers":[{"format":"catalog_item","catalog_id":"c0384"},{"format":"catalog_item","catalog_id":"c0384"}]},` + event, ValidationErrorClaimsInvalid, ValidationErrorClaimsInvalid},
		{"ShouldAcceptAliasesWhichDifferInAdditionalMembers", head + `"sub_id":{"format":"aliases","identifiers":[{"format":"opaque","id":"x","extra":true},{"format":"opaque","id":"x","extra":false}]},` + event, 0, ValidationErrorClaimsInvalid},
		{"ShouldRejectTwoEvents", head + email + `"events":{"https://schemas.openid.net/secevent/caep/event-type/session-revoked":{},"https://example.com/event":{}}}`, ValidationErrorClaimsInvalid, ValidationErrorClaimsInvalid},
		{"ShouldRejectNoEvents", head + email + `"events":{}}`, ValidationErrorClaimsInvalid, ValidationErrorClaimsInvalid},
		{"ShouldRejectSub", head + `"sub":"user",` + email + event, ValidationErrorSubject, ValidationErrorSubject},
		{"ShouldRejectExp", head + `"exp":1520367619,` + email + event, ValidationErrorExpired, ValidationErrorExpired},
		{"ShouldRejectInvalidKnownPayload", head + email + `"events":{"https://schemas.openid.net/secevent/caep/event-type/credential-change":{"change_type":"rotate"}}}`, ValidationErrorClaimsInvalid, ValidationErrorClaimsInvalid},
		{"ShouldRejectEventSubjectRuleWithUnknownSubjectFormat", head + catalog + `"events":{"https://schemas.openid.net/secevent/risc/event-type/identifier-changed":{}}}`, ValidationErrorClaimsInvalid, ValidationErrorClaimsInvalid},
		{"ShouldRejectPayloadThatIsNotAnObject", head + email + `"events":{"https://schemas.openid.net/secevent/risc/event-type/sessions-revoked":"x"}}`, ValidationErrorClaimsInvalid, ValidationErrorClaimsInvalid},
		{"ShouldRejectMissingJTI", `{"iss":"https://transmitter.example.com","iat":1520364019,"aud":"636C69656E745F6964",` + email + event, ValidationErrorId, ValidationErrorId},
		{"ShouldRejectMissingIssuedAt", `{"iss":"https://transmitter.example.com","jti":"x","aud":"636C69656E745F6964",` + email + event, ValidationErrorIssuedAt, ValidationErrorIssuedAt},
		{"ShouldRejectZeroIssuedAt", `{"iss":"https://transmitter.example.com","jti":"x","iat":0,"aud":"636C69656E745F6964",` + email + event, ValidationErrorIssuedAt, ValidationErrorIssuedAt},
		{"ShouldRejectFutureIssuedAt", `{"iss":"https://transmitter.example.com","jti":"x","iat":1520364021,"aud":"636C69656E745F6964",` + email + event, ValidationErrorIssuedAt, ValidationErrorIssuedAt},
		{"ShouldRejectMissingAudience", `{"iss":"https://transmitter.example.com","jti":"x","iat":1520364019,` + email + event, ValidationErrorAudience, ValidationErrorAudience},
		{"ShouldRejectOtherIssuer", `{"iss":"https://other.example.com","jti":"x","iat":1520364019,"aud":"636C69656E745F6964",` + email + event, ValidationErrorIssuer, ValidationErrorIssuer},
		{"ShouldRejectOtherAudience", `{"iss":"https://transmitter.example.com","jti":"x","iat":1520364019,"aud":["other"],` + email + event, ValidationErrorAudience, ValidationErrorAudience},
	}

	check := func(t *testing.T, err error, expected uint32) {
		t.Helper()

		if expected == 0 {
			require.NoError(t, err)

			return
		}

		var vErr *ValidationError

		require.ErrorAs(t, err, &vErr)
		assert.Equal(t, expected, vErr.Errors)
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			claims, err := ParseSecurityEventTokenClaims([]byte(tc.have))

			require.NoError(t, err)
			require.NotNil(t, claims)

			iss, aud := ValidateIssuer("https://transmitter.example.com"), ValidateAudienceAny("636C69656E745F6964")

			check(t, claims.Valid(now, iss, aud, ValidateSecurityEventReceiver()), tc.receiver)
			check(t, claims.Valid(now, iss, aud), tc.transmitter)
		})
	}

	t.Run("ShouldKeepUnknownSubjectMembers", func(t *testing.T) {
		claims, err := ParseSecurityEventTokenClaims([]byte(head + catalog + event))

		require.NoError(t, err)
		assert.Equal(t, &SubjectIdentifier{Format: "catalog_item", Additional: map[string]any{"catalog_id": "c0384/winter/2354122"}}, claims.SubjectIdentifier)
		assert.Equal(t, "https://transmitter.example.com", claims.Issuer)
		assert.Equal(t, "756E69717565206964656E746966696572", claims.JTI)
		assert.Equal(t, []string{"636C69656E745F6964"}, claims.Audience)
		assert.Equal(t, int64(1520364019), claims.IssuedAt.Unix())
		assert.Equal(t, map[string]any{SecurityEventTypeCAEPSessionRevoked: map[string]any{"event_timestamp": int64(1520364000)}}, claims.Events)
	})

	t.Run("ShouldPreserveLargeIntegers", func(t *testing.T) {
		huge, ok := new(big.Int).SetString("1180591620717411303424", 10)
		require.True(t, ok)

		claims, err := ParseSecurityEventTokenClaims([]byte(head + `"txn":"8675309","sub_id":{"format":"opaque","id":"x","serial":9007199254740993},"events":{"https://example.com/event":{"a":9007199254740993,"b":18446744073709551615,"c":1180591620717411303424,"d":[9007199254740993],"e":1.5,"f":{"g":-9007199254740993}}}}`))

		require.NoError(t, err)
		assert.Equal(t, "8675309", claims.Transaction)
		assert.Equal(t, map[string]any{"serial": int64(9007199254740993)}, claims.SubjectIdentifier.Additional)
		assert.Equal(t, map[string]any{"https://example.com/event": map[string]any{
			"a": int64(9007199254740993),
			"b": uint64(18446744073709551615),
			"c": huge,
			"d": []any{int64(9007199254740993)},
			"e": 1.5,
			"f": map[string]any{"g": int64(-9007199254740993)},
		}}, claims.Events)

		require.NoError(t, claims.Valid(now, ValidateSecurityEventReceiver()))

		decoded, err := DecodeSecurityEvent("https://example.com/event", claims.Events["https://example.com/event"].(map[string]any))

		require.NoError(t, err)

		data, err := json.Marshal(decoded)

		require.NoError(t, err)
		assert.JSONEq(t, `{"a":9007199254740993,"b":18446744073709551615,"c":1180591620717411303424,"d":[9007199254740993],"e":1.5,"f":{"g":-9007199254740993}}`, string(data))
	})

	t.Run("ShouldAcceptSurroundingWhitespace", func(t *testing.T) {
		claims, err := ParseSecurityEventTokenClaims([]byte(" \n" + head + email + event + " \r\n\t"))

		require.NoError(t, err)
		require.NoError(t, claims.Valid(now, ValidateSecurityEventReceiver()))
	})

	t.Run("ShouldRejectPayloadThatDoesNotDecode", func(t *testing.T) {
		for name, have := range map[string]string{
			"NotJSON":               `x`,
			"Array":                 `[]`,
			"Compact":               `eyJhbGciOiJub25lIn0.e30.`,
			"TrailingData":          head + email + event + `{}`,
			"TrailingObjectEnd":     head + email + event + `}`,
			"TrailingArrayEnd":      head + email + event + `]`,
			"TrailingSpacedEnds":    head + email + event + ` }}`,
			"TrailingValue":         head + email + event + ` 1`,
			"TrailingComma":         head + email + event + `,`,
			"DuplicateClaim":        `{"jti":"a","jti":"b"}`,
			"NumberIssuer":          `{"iss":5}`,
			"NumberJTI":             `{"jti":5}`,
			"StringIssuedAt":        `{"iat":"now"}`,
			"NumberAudience":        `{"aud":5}`,
			"ArrayEvents":           `{"events":[]}`,
			"NumberTransaction":     `{"txn":5}`,
			"StringSubject":         `{"sub_id":"user"}`,
			"NumberSubjectFormat":   `{"sub_id":{"format":5}}`,
			"NumberSubjectMember":   `{"sub_id":{"format":"email","email":5}}`,
			"DuplicateSubjectField": `{"sub_id":{"format":"email","email":"a@example.com","email":"b@example.com"}}`,
			"NumberOutOfRange":      `{"events":{"https://example.com/event":{"a":1e999}}}`,
		} {
			t.Run(name, func(t *testing.T) {
				claims, err := ParseSecurityEventTokenClaims([]byte(have))

				require.Error(t, err)
				assert.Nil(t, claims)
			})
		}
	})

	t.Run("ShouldNotChangeTransmitterValidation", func(t *testing.T) {
		t.Run("ShouldStillDecodeStrictly", func(t *testing.T) {
			claims := &SecurityEventTokenClaims{}

			require.Error(t, json.Unmarshal([]byte(head+`"sub_id":{"format":"email","email":"user@example.com","extra":true},`+event), claims))

			require.NoError(t, json.Unmarshal([]byte(head+catalog+event), claims))
			assert.Equal(t, &SubjectIdentifier{Format: "catalog_item"}, claims.SubjectIdentifier)
			check(t, claims.Valid(now), ValidationErrorClaimsInvalid)
		})

		t.Run("ShouldStillRefuseToIssueRISCSessionsRevoked", func(t *testing.T) {
			subject, err := NewSubjectIdentifierEmail("user@example.com")
			require.NoError(t, err)

			claims, err := NewSecurityEventTokenClaims("https://transmitter.example.com", []string{"aud"}, subject, RawSecurityEvent{URI: SecurityEventTypeRISCSessionsRevoked}, "")

			require.ErrorIs(t, err, ErrInvalidSecurityEvent)
			assert.Nil(t, claims)
		})

		t.Run("ShouldStillRefuseUnknownFormatFromValidate", func(t *testing.T) {
			subject := &SubjectIdentifier{Format: "catalog_item", Additional: map[string]any{"catalog_id": "c0384"}}

			require.ErrorIs(t, subject.Validate(), ErrInvalidSubjectIdentifier)

			complex := &SubjectIdentifier{Format: SubjectIdentifierFormatComplex, Additional: map[string]any{"catalog": map[string]any{}}}

			require.ErrorIs(t, complex.Validate(), ErrInvalidSubjectIdentifier)
		})

		t.Run("ShouldValidateIssuedClaimsTheSameWithTheOption", func(t *testing.T) {
			subject, err := NewSubjectIdentifierEmail("user@example.com")
			require.NoError(t, err)

			claims, err := NewSecurityEventTokenClaims("https://transmitter.example.com", []string{"aud"}, subject, &CAEPSessionRevoked{}, "")
			require.NoError(t, err)

			require.NoError(t, claims.Valid())
			require.NoError(t, claims.Valid(ValidateSecurityEventReceiver()))

			claims.Events = map[string]any{SecurityEventTypeCAEPCredentialChange: map[string]any{}}

			check(t, claims.Valid(), ValidationErrorClaimsInvalid)
			check(t, claims.Valid(ValidateSecurityEventReceiver()), ValidationErrorClaimsInvalid)
		})
	})
}
