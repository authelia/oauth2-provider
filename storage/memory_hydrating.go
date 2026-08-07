// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"authelia.com/provider/oauth2"
)

// HydratingMemoryStore is a MemoryStore which honours the documented session hydration contract: it marshals a
// request's session on write and unmarshals it into the caller-supplied session on read, returning a requester
// carrying that caller-supplied value.
//
// MemoryStore does neither: it ignores the session argument and hands back the object it was given, which makes it
// unable to detect a whole class of defect. Code that type asserts on the session returned by a Get*Session call
// passes against MemoryStore and fails against every JSON or SQL backed store, because only the latter actually
// hydrates. A guard written that way shipped green once already; use this store for any test whose subject is what
// the returned session is.
//
// Hydration works by cloning the stored request and swapping in the caller-supplied session, and it can only clone
// a *oauth2.Request. A Get*Session call for a request stored as any other oauth2.Requester implementation returns an
// error rather than silently handing back an unhydrated result, so this store never trades a wrong answer for a
// convenient one.
//
// The clone is shallow: fields such as Form and Client are shared with the stored request, so a caller mutating them
// after a Get still reaches the stored copy. Only Session is decoupled, which is the property this fixture exists to
// test.
type HydratingMemoryStore struct {
	*MemoryStore

	sessionsMutex sync.RWMutex
	sessions      map[string][]byte
}

// NewHydratingMemoryStore returns a new *HydratingMemoryStore.
func NewHydratingMemoryStore() *HydratingMemoryStore {
	return &HydratingMemoryStore{
		MemoryStore: NewMemoryStore(),
		sessions:    map[string][]byte{},
	}
}

func (s *HydratingMemoryStore) marshal(key string, request oauth2.Requester) (err error) {
	if request.GetSession() == nil {
		return nil
	}

	var data []byte

	if data, err = json.Marshal(request.GetSession()); err != nil {
		return err
	}

	s.sessionsMutex.Lock()
	defer s.sessionsMutex.Unlock()

	s.sessions[key] = data

	return nil
}

// hydrate unmarshals the stored session blob into session and returns a shallow copy of request carrying it. When no
// blob was stored, or the caller supplied no session, request is returned untouched.
//
// request must be a *oauth2.Request, the only type this method knows how to clone. It is checked before any
// unmarshalling happens, so a caller-supplied session is never mutated on a path that then fails to return it.
func (s *HydratingMemoryStore) hydrate(key string, request oauth2.Requester, session oauth2.Session) (out oauth2.Requester, err error) {
	if session == nil {
		return request, nil
	}

	req, ok := request.(*oauth2.Request)
	if !ok {
		return nil, fmt.Errorf("HydratingMemoryStore cannot hydrate a %T; it can only clone *oauth2.Request", request)
	}

	s.sessionsMutex.RLock()
	data, ok := s.sessions[key]
	s.sessionsMutex.RUnlock()

	if !ok {
		return request, nil
	}

	if err = json.Unmarshal(data, session); err != nil {
		return nil, err
	}

	clone := *req
	clone.Session = session

	return &clone, nil
}

func (s *HydratingMemoryStore) CreateAccessTokenSession(ctx context.Context, signature string, request oauth2.Requester) (err error) {
	if err = s.marshal("at:"+signature, request); err != nil {
		return err
	}

	return s.MemoryStore.CreateAccessTokenSession(ctx, signature, request)
}

func (s *HydratingMemoryStore) GetAccessTokenSession(ctx context.Context, signature string, session oauth2.Session) (request oauth2.Requester, err error) {
	if request, err = s.MemoryStore.GetAccessTokenSession(ctx, signature, session); err != nil {
		return nil, err
	}

	return s.hydrate("at:"+signature, request, session)
}

func (s *HydratingMemoryStore) CreateClientRegistrationTokenSession(ctx context.Context, signature string, request oauth2.Requester) (err error) {
	if err = s.marshal("cr:"+signature, request); err != nil {
		return err
	}

	return s.MemoryStore.CreateClientRegistrationTokenSession(ctx, signature, request)
}

func (s *HydratingMemoryStore) GetClientRegistrationTokenSession(ctx context.Context, signature string, session oauth2.Session) (request oauth2.Requester, err error) {
	if request, err = s.MemoryStore.GetClientRegistrationTokenSession(ctx, signature, session); err != nil {
		return nil, err
	}

	return s.hydrate("cr:"+signature, request, session)
}
