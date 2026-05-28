// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"time"
)

// CIBAStatus is the user authorization status of an OpenID Connect CIBA backchannel authentication request.
type CIBAStatus int

const (
	// CIBAStatusNew indicates that the CIBA request is awaiting the user's authentication decision.
	CIBAStatusNew CIBAStatus = iota

	// CIBAStatusApproved indicates that the user has approved the CIBA request.
	CIBAStatusApproved

	// CIBAStatusDenied indicates that the user has denied the CIBA request.
	CIBAStatusDenied
)

var (
	_ CIBARequester = (*CIBARequest)(nil)
)

// CIBARequest is an implementation of CIBARequester used by the OpenID Connect Client Initiated Backchannel
// Authentication (CIBA) backchannel authentication endpoint.
type CIBARequest struct {
	Request

	AuthRequestIDSignature string
	Status                 CIBAStatus
	LastChecked            time.Time
}

// NewCIBARequest returns an empty CIBARequest with its embedded Request initialized.
func NewCIBARequest() *CIBARequest {
	return &CIBARequest{
		Request: *NewRequest(),
	}
}

// SetAuthRequestIDSignature records the signature of the auth_req_id issued for this request. It is the storage key
// for retrieving the CIBA session at the token endpoint.
func (r *CIBARequest) SetAuthRequestIDSignature(signature string) {
	r.AuthRequestIDSignature = signature
}

// GetAuthRequestIDSignature returns the signature of the auth_req_id issued for this request.
func (r *CIBARequest) GetAuthRequestIDSignature() string {
	return r.AuthRequestIDSignature
}

// SetStatus records the user authorization status (new, approved, or denied) for the CIBA flow.
func (r *CIBARequest) SetStatus(status CIBAStatus) {
	r.Status = status
}

// GetStatus returns the user authorization status (new, approved, or denied) for the CIBA flow.
func (r *CIBARequest) GetStatus() CIBAStatus {
	return r.Status
}

// SetLastChecked records the time of the most recent token endpoint polling attempt for the request. The value is
// normalized to UTC and is used by token endpoint handlers to enforce the polling interval.
func (r *CIBARequest) SetLastChecked(lastChecked time.Time) {
	r.LastChecked = lastChecked.UTC()
}

// GetLastChecked returns the time of the most recent token endpoint polling attempt for the request.
func (r *CIBARequest) GetLastChecked() time.Time {
	return r.LastChecked
}

// Merge copies the requester data into this request. When requester is a *CIBARequest the status, auth_req_id
// signature and last-checked timestamp are also merged.
func (r *CIBARequest) Merge(requester Requester) {
	r.Request.Merge(requester)

	if other, ok := requester.(*CIBARequest); ok {
		r.Status = other.Status
		r.AuthRequestIDSignature = other.AuthRequestIDSignature
		r.LastChecked = other.LastChecked
	}
}
