// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"encoding/json"
	"maps"
	"math"
	"time"

	"authelia.com/provider/oauth2/internal/consts"
)

// UserinfoClaims are the claims of a UserInfo Response. The standard claims are carried in their own fields and any
// other claim in Extra. A standard claim is omitted when its field is the zero value.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
type UserinfoClaims struct {
	Subject             string
	Name                string
	GivenName           string
	FamilyName          string
	MiddleName          string
	Nickname            string
	PreferredUsername   string
	Profile             string
	Picture             string
	Website             string
	Email               string
	EmailVerified       *bool
	Gender              string
	Birthdate           string
	Zoneinfo            string
	Locale              string
	PhoneNumber         string
	PhoneNumberVerified *bool
	Address             *UserinfoAddressClaim
	UpdatedAt           time.Time

	// Extra are the claims other than the standard claims. A key naming a standard claim is ignored by ToMap, as the
	// standard claims are always taken from their fields.
	Extra map[string]any
}

// UserinfoAddressClaim is the 'address' claim. A member is omitted when its field is empty.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#AddressClaim
type UserinfoAddressClaim struct {
	Formatted     string
	StreetAddress string
	Locality      string
	Region        string
	PostalCode    string
	Country       string
}

// ToMap returns the claims as a map: the Extra claims, with each standard claim set from its field or removed when the
// field is the zero value.
func (c *UserinfoClaims) ToMap() (claims map[string]any) {
	claims = make(map[string]any, len(c.Extra)+4)

	maps.Copy(claims, c.Extra)

	for claim, value := range map[string]string{
		consts.ClaimSubject:           c.Subject,
		consts.ClaimFullName:          c.Name,
		consts.ClaimGivenName:         c.GivenName,
		consts.ClaimFamilyName:        c.FamilyName,
		consts.ClaimMiddleName:        c.MiddleName,
		consts.ClaimNickname:          c.Nickname,
		consts.ClaimPreferredUsername: c.PreferredUsername,
		consts.ClaimProfile:           c.Profile,
		consts.ClaimPicture:           c.Picture,
		consts.ClaimWebsite:           c.Website,
		consts.ClaimPreferredEmail:    c.Email,
		consts.ClaimGender:            c.Gender,
		consts.ClaimBirthdate:         c.Birthdate,
		consts.ClaimZoneinfo:          c.Zoneinfo,
		consts.ClaimLocale:            c.Locale,
		consts.ClaimPhoneNumber:       c.PhoneNumber,
	} {
		if value == "" {
			delete(claims, claim)
		} else {
			claims[claim] = value
		}
	}

	for claim, value := range map[string]*bool{
		consts.ClaimEmailVerified:       c.EmailVerified,
		consts.ClaimPhoneNumberVerified: c.PhoneNumberVerified,
	} {
		if value == nil {
			delete(claims, claim)
		} else {
			claims[claim] = *value
		}
	}

	if address := c.Address.toMap(); len(address) != 0 {
		claims[consts.ClaimAddress] = address
	} else {
		delete(claims, consts.ClaimAddress)
	}

	if c.UpdatedAt.IsZero() {
		delete(claims, consts.ClaimUpdatedAt)
	} else {
		claims[consts.ClaimUpdatedAt] = c.UpdatedAt.Unix()
	}

	return claims
}

// FromMap sets the claims from a map, replacing every field. A standard claim whose value has the wrong type is
// dropped. Every other claim is stored in Extra.
//
//nolint:gocyclo
func (c *UserinfoClaims) FromMap(claims map[string]any) {
	*c = UserinfoClaims{Extra: map[string]any{}}

	for claim, value := range claims {
		switch claim {
		case consts.ClaimSubject:
			c.Subject, _ = value.(string)
		case consts.ClaimFullName:
			c.Name, _ = value.(string)
		case consts.ClaimGivenName:
			c.GivenName, _ = value.(string)
		case consts.ClaimFamilyName:
			c.FamilyName, _ = value.(string)
		case consts.ClaimMiddleName:
			c.MiddleName, _ = value.(string)
		case consts.ClaimNickname:
			c.Nickname, _ = value.(string)
		case consts.ClaimPreferredUsername:
			c.PreferredUsername, _ = value.(string)
		case consts.ClaimProfile:
			c.Profile, _ = value.(string)
		case consts.ClaimPicture:
			c.Picture, _ = value.(string)
		case consts.ClaimWebsite:
			c.Website, _ = value.(string)
		case consts.ClaimPreferredEmail:
			c.Email, _ = value.(string)
		case consts.ClaimEmailVerified:
			c.EmailVerified = userinfoBool(value)
		case consts.ClaimGender:
			c.Gender, _ = value.(string)
		case consts.ClaimBirthdate:
			c.Birthdate, _ = value.(string)
		case consts.ClaimZoneinfo:
			c.Zoneinfo, _ = value.(string)
		case consts.ClaimLocale:
			c.Locale, _ = value.(string)
		case consts.ClaimPhoneNumber:
			c.PhoneNumber, _ = value.(string)
		case consts.ClaimPhoneNumberVerified:
			c.PhoneNumberVerified = userinfoBool(value)
		case consts.ClaimAddress:
			c.Address = userinfoAddress(value)
		case consts.ClaimUpdatedAt:
			c.UpdatedAt = userinfoTime(value)
		default:
			c.Extra[claim] = value
		}
	}
}

func (a *UserinfoAddressClaim) toMap() (address map[string]any) {
	if a == nil {
		return nil
	}

	address = map[string]any{}

	for member, value := range map[string]string{
		consts.ClaimAddressFormatted:     a.Formatted,
		consts.ClaimAddressStreetAddress: a.StreetAddress,
		consts.ClaimAddressLocality:      a.Locality,
		consts.ClaimAddressRegion:        a.Region,
		consts.ClaimAddressPostalCode:    a.PostalCode,
		consts.ClaimAddressCountry:       a.Country,
	} {
		if value != "" {
			address[member] = value
		}
	}

	return address
}

func userinfoBool(value any) *bool {
	if v, ok := value.(bool); ok {
		return &v
	}

	return nil
}

func userinfoAddress(value any) *UserinfoAddressClaim {
	switch v := value.(type) {
	case UserinfoAddressClaim:
		return &v
	case *UserinfoAddressClaim:
		return v
	case map[string]any:
		address := &UserinfoAddressClaim{}

		address.Formatted, _ = v[consts.ClaimAddressFormatted].(string)
		address.StreetAddress, _ = v[consts.ClaimAddressStreetAddress].(string)
		address.Locality, _ = v[consts.ClaimAddressLocality].(string)
		address.Region, _ = v[consts.ClaimAddressRegion].(string)
		address.PostalCode, _ = v[consts.ClaimAddressPostalCode].(string)
		address.Country, _ = v[consts.ClaimAddressCountry].(string)

		return address
	default:
		return nil
	}
}

func userinfoTime(value any) time.Time {
	switch v := value.(type) {
	case time.Time:
		return v
	case int64:
		return time.Unix(v, 0).UTC()
	case int:
		return time.Unix(int64(v), 0).UTC()
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return time.Time{}
		}

		return time.Unix(int64(v), 0).UTC()
	case json.Number:
		if i, err := v.Int64(); err == nil {
			return time.Unix(i, 0).UTC()
		}

		if f, err := v.Float64(); err == nil {
			return userinfoTime(f)
		}
	}

	return time.Time{}
}
