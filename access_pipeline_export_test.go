// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
)

// IssueInternalAccessResponseForTest exposes issueInternalAccessResponse to the external test package.
func (f *Fosite) IssueInternalAccessResponseForTest(ctx context.Context, requester *AccessRequest) (AccessResponder, error) {
	return f.issueInternalAccessResponse(ctx, requester)
}
