// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package ssfreceiver

import (
	"context"
	"fmt"
	"net/http"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/token/jwt"
)

// streamSubjectRequest is the body of an add subject or a remove subject request.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.3.2
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.3.3
type streamSubjectRequest struct {
	StreamID string                 `json:"stream_id"`
	Subject  *jwt.SubjectIdentifier `json:"subject"`
	Verified *bool                  `json:"verified,omitempty"`
}

// AddSubject asks the Transmitter to send the events about the subject on the stream. The subject must be valid and
// of a format with defined members, as only those are sent. A subject with Additional members, such as one taken from
// a received SET, is refused before any request, as sending it without them would widen it. The 'verified' member
// says whether this Receiver verified the subject, and is not sent when nil, which a Transmitter should take as
// verified. Any 2xx is a success, and nothing is stored.
//
// A nil error does not mean events about the subject will follow: a Transmitter may answer so for a subject it does
// not know or will not send events about. An error matching ErrStreamNotFound may be of a subject the Transmitter does
// not recognize instead of the stream. It returns ErrEndpointNotSupported for a Transmitter without an Add Subject
// Endpoint, and ErrSubjectsImplicit, before any request, when Config.EnforceCAEPInteroperabilityProfile is set. A POST
// is not sent again after a connection error.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.3.2
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-9.1
// See: https://openid.net/specs/openid-caep-interoperability-profile-1_0.html#section-2.4.4
func (r *Receiver) AddSubject(ctx context.Context, issuer, streamID string, subject *jwt.SubjectIdentifier, verified *bool) (err error) {
	return r.changeSubject(ctx, issuer, streamSubjectRequest{StreamID: streamID, Subject: subject, Verified: verified}, func(configuration *oauth2.SSFConfiguration) string {
		return configuration.AddSubjectEndpoint
	})
}

// RemoveSubject asks the Transmitter to no longer send the events about the subject on the stream. The subject is
// checked, the response is read and the errors are returned as AddSubject does, for the Remove Subject Endpoint. A
// nil error does not mean no events about the subject will follow.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.3.3
// See: https://openid.net/specs/openid-caep-interoperability-profile-1_0.html#section-2.4.4
func (r *Receiver) RemoveSubject(ctx context.Context, issuer, streamID string, subject *jwt.SubjectIdentifier) (err error) {
	return r.changeSubject(ctx, issuer, streamSubjectRequest{StreamID: streamID, Subject: subject}, func(configuration *oauth2.SSFConfiguration) string {
		return configuration.RemoveSubjectEndpoint
	})
}

// changeSubject sends the add subject or remove subject request to the endpoint of the validated Transmitter
// Configuration Metadata.
func (r *Receiver) changeSubject(ctx context.Context, issuer string, body streamSubjectRequest, endpoint func(configuration *oauth2.SSFConfiguration) string) (err error) {
	// Profile Section 2.4.4: all subjects are implicitly included in a stream.
	if r.Config.EnforceCAEPInteroperabilityProfile {
		return ErrSubjectsImplicit
	}

	if body.StreamID == "" {
		return streamRequestError("the stream id is required")
	}

	// SSF Section 8.1.3.2: the 'subject' is required.
	if err = body.Subject.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrStreamRequest, err)
	}

	// SSF Sections 3.3.1 and 8.1.3.1: an omitted complex member matches any value, so a member that is not sent widens
	// the subject.
	if subjectHasAdditional(body.Subject) {
		return streamRequestError("the subject has members its format does not define, which are not sent")
	}

	var configuration *oauth2.SSFConfiguration

	if configuration, err = r.Discover(ctx, issuer); err != nil {
		return err
	}

	// SSF Sections 8.1.3.2 and 9.1: the success of the two is described as a 200 and a 204, so any 2xx is one. An
	// empty endpoint is one the Transmitter does not have.
	_, err = r.transmit(ctx, issuer, transmitterRequest{
		method:   http.MethodPost,
		endpoint: endpoint(configuration),
		scope:    oauth2.ScopeSSFManage,
		body:     body,
	})

	return err
}

// subjectHasAdditional reports whether the subject, or a subject its format marshals, has members that are not
// marshaled. Only the members of the format are followed, which for a valid subject is at most a complex subject of
// 'aliases' of simple subjects, as neither format nests in itself and an alias is not complex (RFC 9493 §3.2.8, SSF
// 1.0 §3.3).
func subjectHasAdditional(subject *jwt.SubjectIdentifier) bool {
	if subject == nil {
		return false
	}

	if len(subject.Additional) != 0 {
		return true
	}

	switch subject.Format {
	case jwt.SubjectIdentifierFormatAliases:
		for i := range subject.Identifiers {
			if subjectHasAdditional(&subject.Identifiers[i]) {
				return true
			}
		}
	case jwt.SubjectIdentifierFormatComplex:
		for _, member := range []*jwt.SubjectIdentifier{subject.User, subject.Device, subject.Session, subject.Application, subject.Tenant, subject.OrgUnit, subject.Group} {
			if subjectHasAdditional(member) {
				return true
			}
		}
	}

	return false
}
