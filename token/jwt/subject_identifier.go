// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
)

const (
	SubjectIdentifierFormatEmail           = "email"
	SubjectIdentifierFormatIssuerSubject   = "iss_sub"
	SubjectIdentifierFormatOpaque          = "opaque"
	SubjectIdentifierFormatPhoneNumber     = "phone_number"
	SubjectIdentifierFormatAccount         = "account"
	SubjectIdentifierFormatDID             = "did"
	SubjectIdentifierFormatURI             = "uri"
	SubjectIdentifierFormatAliases         = "aliases"
	SubjectIdentifierFormatComplex         = "complex"
	SubjectIdentifierFormatJWTID           = "jwt_id"
	SubjectIdentifierFormatSAMLAssertionID = "saml_assertion_id"
	SubjectIdentifierFormatIPAddresses     = "ip-addresses"
)

// ErrInvalidSubjectIdentifier is returned for a subject identifier that is missing a required member.
var ErrInvalidSubjectIdentifier = errors.New("invalid subject identifier")

// SubjectIdentifierComplexMembers are the members of a complex subject (SSF 1.0 §3.3). At least one is required.
type SubjectIdentifierComplexMembers struct {
	User        *SubjectIdentifier `json:"user,omitempty"`
	Device      *SubjectIdentifier `json:"device,omitempty"`
	Session     *SubjectIdentifier `json:"session,omitempty"`
	Application *SubjectIdentifier `json:"application,omitempty"`
	Tenant      *SubjectIdentifier `json:"tenant,omitempty"`
	OrgUnit     *SubjectIdentifier `json:"org_unit,omitempty"`
	Group       *SubjectIdentifier `json:"group,omitempty"`
}

// SubjectIdentifier is an RFC 9493 §3 subject identifier, with the SSF 1.0 §3.3 and §3.5 formats. Only the members of
// Format are validated and marshaled.
type SubjectIdentifier struct {
	Format string `json:"format"`

	Email       string              `json:"email,omitempty"`
	Issuer      string              `json:"iss,omitempty"`
	Subject     string              `json:"sub,omitempty"`
	ID          string              `json:"id,omitempty"`
	PhoneNumber string              `json:"phone_number,omitempty"`
	URI         string              `json:"uri,omitempty"`
	URL         string              `json:"url,omitempty"`
	Identifiers []SubjectIdentifier `json:"identifiers,omitempty"`
	JWTID       string              `json:"jti,omitempty"`
	SAMLIssuer  string              `json:"issuer,omitempty"`
	AssertionID string              `json:"assertion_id,omitempty"`
	IPAddresses []string            `json:"ip-addresses,omitempty"`

	SubjectIdentifierComplexMembers
}

// MarshalJSON marshals the 'format' and the members of Format only.
func (s SubjectIdentifier) MarshalJSON() (data []byte, err error) {
	type subjectIdentifier SubjectIdentifier

	out := subjectIdentifier{Format: s.Format}

	switch s.Format {
	case SubjectIdentifierFormatEmail:
		out.Email = s.Email
	case SubjectIdentifierFormatIssuerSubject:
		out.Issuer, out.Subject = s.Issuer, s.Subject
	case SubjectIdentifierFormatOpaque:
		out.ID = s.ID
	case SubjectIdentifierFormatPhoneNumber:
		out.PhoneNumber = s.PhoneNumber
	case SubjectIdentifierFormatAccount, SubjectIdentifierFormatURI:
		out.URI = s.URI
	case SubjectIdentifierFormatDID:
		out.URL = s.URL
	case SubjectIdentifierFormatAliases:
		out.Identifiers = s.Identifiers
	case SubjectIdentifierFormatComplex:
		out.SubjectIdentifierComplexMembers = s.SubjectIdentifierComplexMembers
	case SubjectIdentifierFormatJWTID:
		out.Issuer, out.JWTID = s.Issuer, s.JWTID
	case SubjectIdentifierFormatSAMLAssertionID:
		out.SAMLIssuer, out.AssertionID = s.SAMLIssuer, s.AssertionID
	case SubjectIdentifierFormatIPAddresses:
		out.IPAddresses = s.IPAddresses
	}

	return json.Marshal(out)
}

// NewSubjectIdentifierEmail returns an email subject identifier (RFC 9493 §3.2.2).
func NewSubjectIdentifierEmail(email string) (subject *SubjectIdentifier, err error) {
	return validated(&SubjectIdentifier{Format: SubjectIdentifierFormatEmail, Email: email})
}

// NewSubjectIdentifierIssuerSubject returns an iss_sub subject identifier (RFC 9493 §3.2.3).
func NewSubjectIdentifierIssuerSubject(iss, sub string) (subject *SubjectIdentifier, err error) {
	return validated(&SubjectIdentifier{Format: SubjectIdentifierFormatIssuerSubject, Issuer: iss, Subject: sub})
}

// NewSubjectIdentifierOpaque returns an opaque subject identifier (RFC 9493 §3.2.4).
func NewSubjectIdentifierOpaque(id string) (subject *SubjectIdentifier, err error) {
	return validated(&SubjectIdentifier{Format: SubjectIdentifierFormatOpaque, ID: id})
}

// NewSubjectIdentifierComplex returns a complex subject identifier (SSF 1.0 §3.3).
func NewSubjectIdentifierComplex(members SubjectIdentifierComplexMembers) (subject *SubjectIdentifier, err error) {
	return validated(&SubjectIdentifier{Format: SubjectIdentifierFormatComplex, SubjectIdentifierComplexMembers: members})
}

func validated(s *SubjectIdentifier) (subject *SubjectIdentifier, err error) {
	if err = s.Validate(); err != nil {
		return nil, err
	}

	return s, nil
}

func subjectRequire(format, member, value string) (err error) {
	if value == "" {
		return fmt.Errorf("%w: format '%s' requires the '%s' member", ErrInvalidSubjectIdentifier, format, member)
	}

	return nil
}

// Validate checks the members required by the format (RFC 9493 §3.2, SSF 1.0 §3.3 and §3.5).
func (s *SubjectIdentifier) Validate() (err error) {
	if s == nil {
		return fmt.Errorf("%w: the subject is nil", ErrInvalidSubjectIdentifier)
	}

	switch s.Format {
	case SubjectIdentifierFormatEmail:
		return subjectRequire(s.Format, "email", s.Email)
	case SubjectIdentifierFormatIssuerSubject:
		if err = subjectRequire(s.Format, "iss", s.Issuer); err != nil {
			return err
		}

		return subjectRequire(s.Format, "sub", s.Subject)
	case SubjectIdentifierFormatOpaque:
		return subjectRequire(s.Format, "id", s.ID)
	case SubjectIdentifierFormatPhoneNumber:
		return subjectRequire(s.Format, "phone_number", s.PhoneNumber)
	case SubjectIdentifierFormatAccount, SubjectIdentifierFormatURI:
		return subjectRequire(s.Format, "uri", s.URI)
	case SubjectIdentifierFormatDID:
		return subjectRequire(s.Format, "url", s.URL)
	case SubjectIdentifierFormatAliases:
		return s.validateAliases()
	case SubjectIdentifierFormatComplex:
		return s.validateComplex()
	case SubjectIdentifierFormatJWTID:
		if err = subjectRequire(s.Format, "iss", s.Issuer); err != nil {
			return err
		}

		return subjectRequire(s.Format, "jti", s.JWTID)
	case SubjectIdentifierFormatSAMLAssertionID:
		if err = subjectRequire(s.Format, "issuer", s.SAMLIssuer); err != nil {
			return err
		}

		return subjectRequire(s.Format, "assertion_id", s.AssertionID)
	case SubjectIdentifierFormatIPAddresses:
		return s.validateIPAddresses()
	case "":
		return fmt.Errorf("%w: the 'format' member is required", ErrInvalidSubjectIdentifier)
	default:
		return fmt.Errorf("%w: the 'format' member '%s' is not supported", ErrInvalidSubjectIdentifier, s.Format)
	}
}

// validateAliases enforces RFC 9493 §3.2.8: a non-empty list that is not nested.
func (s *SubjectIdentifier) validateAliases() (err error) {
	if len(s.Identifiers) == 0 {
		return fmt.Errorf("%w: format 'aliases' requires the 'identifiers' member", ErrInvalidSubjectIdentifier)
	}

	for i := range s.Identifiers {
		if s.Identifiers[i].Format == SubjectIdentifierFormatAliases {
			return fmt.Errorf("%w: 'aliases' identifiers must not be nested", ErrInvalidSubjectIdentifier)
		}

		if err = s.Identifiers[i].Validate(); err != nil {
			return fmt.Errorf("%w: 'identifiers' member %d is invalid: %w", ErrInvalidSubjectIdentifier, i, err)
		}
	}

	return nil
}

// validateComplex requires at least one member, each a valid subject identifier (SSF 1.0 §3.3).
func (s *SubjectIdentifier) validateComplex() (err error) {
	members := []struct {
		name  string
		value *SubjectIdentifier
	}{
		{"user", s.User}, {"device", s.Device}, {"session", s.Session}, {"application", s.Application},
		{"tenant", s.Tenant}, {"org_unit", s.OrgUnit}, {"group", s.Group},
	}

	var present int

	for _, member := range members {
		if member.value == nil {
			continue
		}

		present++

		if err = member.value.Validate(); err != nil {
			return fmt.Errorf("%w: complex member '%s' is invalid: %w", ErrInvalidSubjectIdentifier, member.name, err)
		}
	}

	if present == 0 {
		return fmt.Errorf("%w: format 'complex' requires at least one member", ErrInvalidSubjectIdentifier)
	}

	return nil
}

// validateIPAddresses requires a non-empty array of IP address strings (SSF 1.0 §3.5.3).
func (s *SubjectIdentifier) validateIPAddresses() (err error) {
	if len(s.IPAddresses) == 0 {
		return fmt.Errorf("%w: format 'ip-addresses' requires the 'ip-addresses' member", ErrInvalidSubjectIdentifier)
	}

	for _, address := range s.IPAddresses {
		if _, err = netip.ParseAddr(address); err != nil {
			return fmt.Errorf("%w: 'ip-addresses' member '%s' is not an IP address", ErrInvalidSubjectIdentifier, address)
		}
	}

	return nil
}
