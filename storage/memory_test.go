// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"

	"authelia.com/provider/oauth2"
)

func TestMemoryStore_Authenticate(t *testing.T) {
	type args struct {
		in0    context.Context
		name   string
		secret string
	}

	testCases := []struct {
		name  string
		users map[string]MemoryUserRelation
		args  args
		err   string
	}{
		{
			name: "ShouldHandleInvalidPassword",
			args: args{
				name:   "peter",
				secret: "invalid",
			},
			users: map[string]MemoryUserRelation{
				"peter": {
					Username: "peter",
					Password: "secret",
				},
			},
			err: "Could not find the requested resource(s). Invalid credentials.",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			s := &MemoryStore{
				Users:      tc.users,
				usersMutex: sync.RWMutex{},
			}

			err := s.Authenticate(tc.args.in0, tc.args.name, tc.args.secret)

			if len(tc.err) == 0 {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.err)
			}
		})
	}
}
