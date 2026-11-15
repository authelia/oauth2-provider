// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package clients

import (
	"fmt"
	"net/http"
)

// RequestError is returned when the token endpoint responds with an error.
type RequestError struct {
	Response *http.Response
	Body     []byte
}

// Error implements the error interface.
func (r *RequestError) Error() string {
	return fmt.Sprintf("oauth2: cannot fetch token: %v\nResponse: %s", r.Response.Status, r.Body)
}
