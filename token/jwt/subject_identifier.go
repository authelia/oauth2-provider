// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/mail"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	jjson "authelia.com/provider/jose/json"
)

const (
	// SubjectIdentifierFormatEmail is the subject identifier format for an email address.
	SubjectIdentifierFormatEmail = "email"
	// SubjectIdentifierFormatIssuerSubject is the subject identifier format for an issuer and subject pair.
	SubjectIdentifierFormatIssuerSubject = "iss_sub"
	// SubjectIdentifierFormatOpaque is the subject identifier format for an opaque identifier.
	SubjectIdentifierFormatOpaque = "opaque"
	// SubjectIdentifierFormatPhoneNumber is the subject identifier format for a phone number.
	SubjectIdentifierFormatPhoneNumber = "phone_number"
	// SubjectIdentifierFormatAccount is the subject identifier format for an account URI.
	SubjectIdentifierFormatAccount = "account"
	// SubjectIdentifierFormatDID is the subject identifier format for a decentralized identifier.
	SubjectIdentifierFormatDID = "did"
	// SubjectIdentifierFormatURI is the subject identifier format for a URI.
	SubjectIdentifierFormatURI = "uri"
	// SubjectIdentifierFormatAliases is the subject identifier format for a list of aliases.
	SubjectIdentifierFormatAliases = "aliases"
	// SubjectIdentifierFormatComplex is the subject identifier format for a complex identifier.
	SubjectIdentifierFormatComplex = "complex"
	// SubjectIdentifierFormatJWTID is the subject identifier format for a JWT identifier.
	SubjectIdentifierFormatJWTID = "jwt_id"
	// SubjectIdentifierFormatSAMLAssertionID is the subject identifier format for a SAML assertion identifier.
	SubjectIdentifierFormatSAMLAssertionID = "saml_assertion_id"
	// SubjectIdentifierFormatIPAddresses is the subject identifier format for a list of IP addresses.
	SubjectIdentifierFormatIPAddresses = "ip-addresses"
)

// ErrInvalidSubjectIdentifier is returned for a subject identifier that is missing a required member.
var ErrInvalidSubjectIdentifier = errors.New("invalid subject identifier")

// SubjectIdentifierComplexMembers are the members of a complex subject (SSF 1.0 §3.3). At least one is required. Every
// member describes the same subject, and together they refer to exactly one (SSF 1.0 §3.3.1).
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
// Format are validated and marshaled, and only they are accepted when unmarshaled.
//
// The syntax of each member is validated. What the identifier means is the duty of the caller:
//
//   - The format is the most specific one for the value, such as email rather than uri for an email address (RFC 9493
//     §3.2).
//   - An email identifies a mailbox that email can be delivered to (RFC 9493 §3.2.2).
//   - Every identifier of an aliases subject identifies the same entity (RFC 9493 §3.2.8), and they are sent together
//     only to a recipient that already knows they are related, or when the use case depends on it (RFC 9493 §6.1).
//   - The identifier does not let the recipient correlate claims it does not already know to be about the subject, and
//     a subject has the same format and values for a given recipient every time (SSF 1.0 §10.1).
type SubjectIdentifier struct {
	Format string `json:"format"`

	Email string `json:"email,omitempty"`
	// Issuer provides the JSON Web Keys and algorithms used to issue tokens.
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

// UnmarshalJSON decodes a subject identifier. Member names are matched by exact case, and a duplicate member or a
// member the format does not define is an error (RFC 9493 §3). A format that is unknown is left for Validate.
func (s *SubjectIdentifier) UnmarshalJSON(data []byte) (err error) {
	if string(bytes.TrimSpace(data)) == jsonNull {
		return nil
	}

	var members map[string]jjson.RawMessage

	if err = jjson.Unmarshal(data, &members); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSubjectIdentifier, err)
	}

	var format string

	if raw, ok := members["format"]; ok {
		if err = jjson.Unmarshal(raw, &format); err != nil {
			return fmt.Errorf("%w: the 'format' member is not a string", ErrInvalidSubjectIdentifier)
		}
	}

	if defined, ok := subjectIdentifierMembers(format); ok {
		for _, member := range slices.Sorted(maps.Keys(members)) {
			if member != "format" && !slices.Contains(defined, member) {
				return fmt.Errorf("%w: format '%s' does not define the '%s' member", ErrInvalidSubjectIdentifier, format, member)
			}
		}
	}

	type subjectIdentifier SubjectIdentifier

	var decoded subjectIdentifier

	if err = jjson.Unmarshal(data, &decoded); err != nil {
		if errors.Is(err, ErrInvalidSubjectIdentifier) {
			return err
		}

		return fmt.Errorf("%w: %w", ErrInvalidSubjectIdentifier, err)
	}

	*s = SubjectIdentifier(decoded)

	return nil
}

func subjectIdentifierMembers(format string) (members []string, known bool) {
	switch format {
	case SubjectIdentifierFormatEmail:
		return []string{"email"}, true
	case SubjectIdentifierFormatIssuerSubject:
		return []string{ClaimIssuer, ClaimSubject}, true
	case SubjectIdentifierFormatOpaque:
		return []string{"id"}, true
	case SubjectIdentifierFormatPhoneNumber:
		return []string{"phone_number"}, true
	case SubjectIdentifierFormatAccount, SubjectIdentifierFormatURI:
		return []string{"uri"}, true
	case SubjectIdentifierFormatDID:
		return []string{"url"}, true
	case SubjectIdentifierFormatAliases:
		return []string{"identifiers"}, true
	case SubjectIdentifierFormatComplex:
		for _, member := range (&SubjectIdentifier{}).complexMembers() {
			members = append(members, member.name)
		}

		return members, true
	case SubjectIdentifierFormatJWTID:
		return []string{ClaimIssuer, ClaimJWTID}, true
	case SubjectIdentifierFormatSAMLAssertionID:
		return []string{"issuer", "assertion_id"}, true
	case SubjectIdentifierFormatIPAddresses:
		return []string{SubjectIdentifierFormatIPAddresses}, true
	default:
		return nil, false
	}
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

func subjectMember(format, member, value, rule string, valid func(value string) bool) (err error) {
	if err = subjectRequire(format, member, value); err != nil {
		return err
	}

	if !valid(value) {
		return fmt.Errorf("%w: format '%s' requires the '%s' member to be %s", ErrInvalidSubjectIdentifier, format, member, rule)
	}

	return nil
}

const (
	subjectRuleStringOrURI = "a string without a ':' or a URI"
	subjectRuleURI         = "a URI"
)

// Validate checks the members required by the format and their values (RFC 9493 §3.2, SSF 1.0 §3.3 and §3.5).
//
//nolint:gocyclo
func (s *SubjectIdentifier) Validate() (err error) {
	if s == nil {
		return fmt.Errorf("%w: the subject is nil", ErrInvalidSubjectIdentifier)
	}

	switch s.Format {
	case SubjectIdentifierFormatEmail:
		// RFC 9493 §3.2.2: an RFC 5322 §3.4.1 addr-spec.
		return subjectMember(s.Format, "email", s.Email, "an email address", isAddrSpec)
	case SubjectIdentifierFormatIssuerSubject:
		// RFC 9493 §3.2.3: the RFC 7519 formats of 'iss' and 'sub'.
		if err = subjectMember(s.Format, "iss", s.Issuer, subjectRuleStringOrURI, isStringOrURI); err != nil {
			return err
		}

		return subjectMember(s.Format, "sub", s.Subject, subjectRuleStringOrURI, isStringOrURI)
	case SubjectIdentifierFormatOpaque:
		return subjectRequire(s.Format, "id", s.ID)
	case SubjectIdentifierFormatPhoneNumber:
		// RFC 9493 §3.2.5: E.164 with the international dialing prefix.
		return subjectMember(s.Format, "phone_number", s.PhoneNumber, "an E.164 number with a '+' prefix", regexpSubjectPhoneNumber.MatchString)
	case SubjectIdentifierFormatAccount:
		// RFC 9493 §3.2.1: an RFC 7565 'acct' URI.
		return subjectMember(s.Format, "uri", s.URI, "an 'acct' URI", regexpSubjectAccount.MatchString)
	case SubjectIdentifierFormatURI:
		// RFC 9493 §3.2.7.
		return subjectMember(s.Format, "uri", s.URI, subjectRuleURI, isURI)
	case SubjectIdentifierFormatDID:
		// RFC 9493 §3.2.6: a DID URL or a bare DID.
		return subjectMember(s.Format, "url", s.URL, "a DID URL", regexpSubjectDID.MatchString)
	case SubjectIdentifierFormatAliases:
		return s.validateAliases()
	case SubjectIdentifierFormatComplex:
		return s.validateComplex()
	case SubjectIdentifierFormatJWTID:
		// SSF 1.0 §3.5.1: the RFC 7519 'iss' and 'jti' of the JWT.
		if err = subjectMember(s.Format, "iss", s.Issuer, subjectRuleStringOrURI, isStringOrURI); err != nil {
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

func (s *SubjectIdentifier) validateAliases() (err error) {
	if len(s.Identifiers) == 0 {
		return fmt.Errorf("%w: format 'aliases' requires the 'identifiers' member", ErrInvalidSubjectIdentifier)
	}

	seen := make(map[string]struct{}, len(s.Identifiers))

	for i := range s.Identifiers {
		switch s.Identifiers[i].Format {
		case SubjectIdentifierFormatAliases:
			// RFC 9493 §3.2.8: aliases are not nested.
			return fmt.Errorf("%w: 'aliases' identifiers must not be nested", ErrInvalidSubjectIdentifier)
		case SubjectIdentifierFormatComplex:
			// RFC 9493 §3.2.8, SSF 1.0 §3.3: an alias identifies one entity, a complex subject a tuple of them.
			return fmt.Errorf("%w: 'identifiers' member %d must not be a complex subject", ErrInvalidSubjectIdentifier, i)
		}

		if err = s.Identifiers[i].Validate(); err != nil {
			return fmt.Errorf("%w: 'identifiers' member %d is invalid: %w", ErrInvalidSubjectIdentifier, i, err)
		}

		var data []byte

		if data, err = json.Marshal(s.Identifiers[i]); err != nil {
			return fmt.Errorf("%w: 'identifiers' member %d is invalid: %w", ErrInvalidSubjectIdentifier, i, err)
		}

		// RFC 9493 §3.2.8: no exact duplicates.
		if _, ok := seen[string(data)]; ok {
			return fmt.Errorf("%w: 'identifiers' member %d is a duplicate", ErrInvalidSubjectIdentifier, i)
		}

		seen[string(data)] = struct{}{}
	}

	return nil
}

// validateComplex requires at least one member, each a valid subject identifier (SSF 1.0 §3.3).
func (s *SubjectIdentifier) validateComplex() (err error) {
	var present int

	for _, member := range s.complexMembers() {
		if member.value == nil {
			continue
		}

		present++

		// SSF 1.0 §3.3: the value of each member is a simple subject.
		if member.value.Format == SubjectIdentifierFormatComplex {
			return fmt.Errorf("%w: complex member '%s' must not be a complex subject", ErrInvalidSubjectIdentifier, member.name)
		}

		if err = member.value.Validate(); err != nil {
			return fmt.Errorf("%w: complex member '%s' is invalid: %w", ErrInvalidSubjectIdentifier, member.name, err)
		}
	}

	if present == 0 {
		return fmt.Errorf("%w: format 'complex' requires at least one member", ErrInvalidSubjectIdentifier)
	}

	return nil
}

type subjectComplexMember struct {
	name  string
	value *SubjectIdentifier
}

func (s *SubjectIdentifier) complexMembers() (members []subjectComplexMember) {
	return []subjectComplexMember{
		{"user", s.User}, {"device", s.Device}, {"session", s.Session}, {"application", s.Application},
		{"tenant", s.Tenant}, {"org_unit", s.OrgUnit}, {"group", s.Group},
	}
}

// validateIPAddresses requires a non-empty array of IP address strings (SSF 1.0 §3.5.3).
func (s *SubjectIdentifier) validateIPAddresses() (err error) {
	if len(s.IPAddresses) == 0 {
		return fmt.Errorf("%w: format 'ip-addresses' requires the 'ip-addresses' member", ErrInvalidSubjectIdentifier)
	}

	for _, address := range s.IPAddresses {
		if !isInetAddress(address) {
			return fmt.Errorf("%w: 'ip-addresses' member '%s' is not an IP address", ErrInvalidSubjectIdentifier, address)
		}
	}

	return nil
}

const (
	uriPathChar  = `(?:[A-Za-z0-9._~!$&'()*+,;=:@-]|%[0-9A-Fa-f]{2})`
	uriIPLiteral = `\[(?:[0-9A-Fa-f:.]+(?:%25(?:[A-Za-z0-9._~-]|%[0-9A-Fa-f]{2})+)?|[vV][0-9A-Fa-f]+\.[A-Za-z0-9._~!$&'()*+,;=:-]+)\]`
	uriAuthority = `(?:(?:[A-Za-z0-9._~!$&'()*+,;=:-]|%[0-9A-Fa-f]{2})*@)?(?:` + uriIPLiteral + `|(?:[A-Za-z0-9._~!$&'()*+,;=-]|%[0-9A-Fa-f]{2})*)(?::[0-9]*)?`
)

var (
	regexpSubjectPhoneNumber = regexp.MustCompile(`^\+[1-9][0-9]{1,14}$`)
	regexpSubjectAccount     = regexp.MustCompile(`^(?i:acct):(?:[A-Za-z0-9._~!$&'()*+,;=-]|%[0-9A-Fa-f]{2})+@(?:(?:[A-Za-z0-9._~!$&'()*+,;=-]|%[0-9A-Fa-f]{2})+|\[[0-9A-Fa-f:.]+\])$`)
	regexpSubjectDID         = regexp.MustCompile(`^did:[a-z0-9]+:(?:(?:[A-Za-z0-9._-]|%[0-9A-Fa-f]{2})*:)*(?:[A-Za-z0-9._-]|%[0-9A-Fa-f]{2})+(?:/(?:[A-Za-z0-9._~!$&'()*+,;=:@/-]|%[0-9A-Fa-f]{2})*)?(?:\?(?:[A-Za-z0-9._~!$&'()*+,;=:@/?-]|%[0-9A-Fa-f]{2})*)?(?:#(?:[A-Za-z0-9._~!$&'()*+,;=:@/?-]|%[0-9A-Fa-f]{2})*)?$`)
	regexpURIScheme          = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*$`)
	regexpURIRemainder       = regexp.MustCompile(`^(?://` + uriAuthority + `(?:/` + uriPathChar + `*)*|/?(?:` + uriPathChar + `+(?:/` + uriPathChar + `*)*)?)(?:\?(?:` + uriPathChar + `|[/?])*)?(?:#(?:` + uriPathChar + `|[/?])*)?$`)
)

func isAddrSpec(value string) bool {
	// RFC 5322 §3.4: an angle-addr is an addr-spec in angle brackets, and a name-addr has a display name before it.
	address, err := mail.ParseAddress("<" + value + ">")

	return err == nil && address.Name == "" && strings.TrimLeft(value, " \t") == value
}

func isURI(value string) bool {
	// RFC 3986 §3.2.2: square brackets are allowed in the IP-literal of a host and nowhere else in a URI.
	scheme, remainder, ok := strings.Cut(value, ":")
	if !ok || !regexpURIScheme.MatchString(scheme) || !regexpURIRemainder.MatchString(remainder) {
		return false
	}

	_, err := url.Parse(value)

	return err == nil
}

func isStringOrURI(value string) bool {
	return !strings.Contains(value, ":") || isURI(value)
}

func isInetAddress(value string) bool {
	address, err := netip.ParseAddr(value)
	if err != nil {
		return false
	}

	zone := address.Zone()
	if zone == "" {
		return true
	}

	// RFC 4001 §3: the zone index of InetAddressIPv6z is an unsigned 32-bit number.
	_, err = strconv.ParseUint(zone, 10, 32)

	return err == nil
}
