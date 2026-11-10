// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"net/http"
)

// AuthorizeSSFRequestForTest exposes authorizeSSFRequest to the external test package.
func (f *Fosite) AuthorizeSSFRequestForTest(ctx context.Context, r *http.Request, session Session, write bool) (requester AccessRequester, storage SSFStreamStorage, err error) {
	return f.authorizeSSFRequest(ctx, r, session, write)
}
