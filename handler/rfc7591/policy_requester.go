// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7591

import (
	"authelia.com/provider/oauth2"
)

// RegistrationPolicyRequester is the oauth2.Requester returned by DefaultEndpointAuthStrategy. It carries the raw
// registration policy claim of the credential and the key the registration counter is kept under.
type RegistrationPolicyRequester interface {
	oauth2.Requester

	// GetRegistrationPolicyClaim returns the raw policy claim and whether the credential carries one.
	GetRegistrationPolicyClaim() (claim any, ok bool)

	// GetRegistrationCounterKey returns the key registrations are counted under, or empty when the credential is not
	// counted.
	GetRegistrationCounterKey() (key string)

	// GetRegistrationPolicyPatternsPermitted returns true if the policy may hold 'pattern' rules, which is the case for
	// a credential issued by this server or by an issuer of GetRFC7591ClientRegistrationPatternIssuers.
	GetRegistrationPolicyPatternsPermitted() (permitted bool)
}

type policyRequester struct {
	oauth2.Requester

	claim    any
	ok       bool
	key      string
	patterns bool
}

func (r *policyRequester) GetRegistrationPolicyClaim() (claim any, ok bool) {
	return r.claim, r.ok
}

func (r *policyRequester) GetRegistrationCounterKey() (key string) {
	return r.key
}

func (r *policyRequester) GetRegistrationPolicyPatternsPermitted() (permitted bool) {
	return r.patterns
}

func newPolicyRequester(requester oauth2.Requester, name, key string, patterns bool) (wrapped *policyRequester) {
	wrapped = &policyRequester{Requester: requester, key: key, patterns: patterns}

	if session, ok := requester.GetSession().(oauth2.ExtraClaimsSession); ok {
		wrapped.claim, wrapped.ok = session.GetExtraClaims()[name]
	}

	return wrapped
}

var (
	_ RegistrationPolicyRequester = (*policyRequester)(nil)
)
