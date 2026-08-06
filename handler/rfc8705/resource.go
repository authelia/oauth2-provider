// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8705

import (
	"crypto/x509"
	"net/http"

	"authelia.com/provider/oauth2"
)

// ValidateResourceAccess performs the RFC 8705 Section 3 resource server check for a certificate-bound access token.
//
// boundX5T is the confirmed 'cnf' member 'x5t#S256' the caller obtained by introspecting the access token, for which
// oauth2.GetMTLSConfirmationX509SHA256Thumbprint is provided; header names the trusted proxy header to fall back to
// when the connection carries no peer certificate, and is empty when there is none. On success it returns the
// certificate the connection was authenticated with.
//
// Every failure returns an error wrapping oauth2.ErrInvalidToken, which Section 3 requires be reported with an HTTP
// 401 status and the 'invalid_token' error code.
//
// The method is intended only for tokens already known to be certificate bound; an empty boundX5T is treated as caller
// misuse rather than as a token that is bound to nothing.
func ValidateResourceAccess(r *http.Request, header, boundX5T string) (cert *x509.Certificate, err error) {
	return oauth2.ValidateClientCertificateBinding(r, header, boundX5T)
}
