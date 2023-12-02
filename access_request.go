// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package goauth2

type AccessRequest struct {
	GrantTypes       Arguments `json:"grantTypes" gorethink:"grantTypes"`
	HandledGrantType Arguments `json:"handledGrantType" gorethink:"handledGrantType"`

	Request
}

func NewAccessRequest(session Session) *AccessRequest {
	r := &AccessRequest{
		GrantTypes:       Arguments{},
		HandledGrantType: Arguments{},
		Request:          *NewRequest(),
	}
	r.Session = session
	return r
}

func (a *AccessRequest) GetGrantTypes() Arguments {
	return a.GrantTypes
}
