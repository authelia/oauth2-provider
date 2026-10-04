// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"authelia.com/provider/oauth2"
)

// HydratingMemoryStore is a MemoryStore which honours the documented session hydration contract: it marshals a
// request's session on write and unmarshals it into the caller-supplied session on read, returning a requester
// carrying that caller-supplied value. MemoryStore does neither, so use this store for any test whose subject is the
// session a Get*Session call returns.
//
// Hydration clones the stored request and swaps in the caller-supplied session. Only a *oauth2.Request or a
// *oauth2.AccessRequest can be cloned; a Get*Session call for any other oauth2.Requester implementation returns an
// error. The clone is shallow: fields such as Form and Client are shared with the stored request, and only Session
// is decoupled.
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
// request must be a *oauth2.Request or a *oauth2.AccessRequest - the only types this method knows how to clone. It is
// checked before any unmarshalling happens, so a caller-supplied session is never mutated on a path that then fails to
// return it.
func (s *HydratingMemoryStore) hydrate(key string, request oauth2.Requester, session oauth2.Session) (out oauth2.Requester, err error) {
	if session == nil {
		return request, nil
	}

	switch request.(type) {
	case *oauth2.Request, *oauth2.AccessRequest:
	default:
		return nil, fmt.Errorf("HydratingMemoryStore cannot hydrate a %T; it can only clone *oauth2.Request or *oauth2.AccessRequest", request)
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

	switch req := request.(type) {
	case *oauth2.AccessRequest:
		clone := *req
		clone.Session = session

		return &clone, nil
	default:
		clone := *req.(*oauth2.Request)
		clone.Session = session

		return &clone, nil
	}
}

// CreateAccessTokenSession marshals the session of the request and stores the request against the access token
// signature.
func (s *HydratingMemoryStore) CreateAccessTokenSession(ctx context.Context, signature string, request oauth2.Requester) (err error) {
	if err = s.marshal("at:"+signature, request); err != nil {
		return err
	}

	return s.MemoryStore.CreateAccessTokenSession(ctx, signature, request)
}

// GetAccessTokenSession returns the request stored against the access token signature, carrying the caller-supplied
// session hydrated from the marshalled session.
func (s *HydratingMemoryStore) GetAccessTokenSession(ctx context.Context, signature string, session oauth2.Session) (request oauth2.Requester, err error) {
	if request, err = s.MemoryStore.GetAccessTokenSession(ctx, signature, session); err != nil {
		return nil, err
	}

	return s.hydrate("at:"+signature, request, session)
}

// CreateClientRegistrationTokenSession marshals the session of the request and stores the request against the client
// registration token signature.
func (s *HydratingMemoryStore) CreateClientRegistrationTokenSession(ctx context.Context, signature string, request oauth2.Requester) (err error) {
	if err = s.marshal("cr:"+signature, request); err != nil {
		return err
	}

	return s.MemoryStore.CreateClientRegistrationTokenSession(ctx, signature, request)
}

// GetClientRegistrationTokenSession returns the request stored against the client registration token signature,
// carrying the caller-supplied session hydrated from the marshalled session.
func (s *HydratingMemoryStore) GetClientRegistrationTokenSession(ctx context.Context, signature string, session oauth2.Session) (request oauth2.Requester, err error) {
	if request, err = s.MemoryStore.GetClientRegistrationTokenSession(ctx, signature, session); err != nil {
		return nil, err
	}

	return s.hydrate("cr:"+signature, request, session)
}

// CreateRefreshTokenSession marshals the session of the request and stores the request against the refresh token
// signature.
func (s *HydratingMemoryStore) CreateRefreshTokenSession(ctx context.Context, signature, accessSignature string, request oauth2.Requester) (err error) {
	if err = s.marshal("rt:"+signature, request); err != nil {
		return err
	}

	return s.MemoryStore.CreateRefreshTokenSession(ctx, signature, accessSignature, request)
}

// UpdateRefreshTokenSession replaces the request stored against the refresh token signature and, when the request has a
// session, the marshalled session stored with it.
func (s *HydratingMemoryStore) UpdateRefreshTokenSession(ctx context.Context, signature string, request oauth2.Requester) (err error) {
	var data []byte

	if session := request.GetSession(); session != nil {
		if data, err = json.Marshal(session); err != nil {
			return err
		}
	}

	if err = s.MemoryStore.UpdateRefreshTokenSession(ctx, signature, request); err != nil {
		return err
	}

	if data != nil {
		s.sessionsMutex.Lock()
		s.sessions["rt:"+signature] = data
		s.sessionsMutex.Unlock()
	}

	return nil
}

// GetRefreshTokenSession returns the request stored against the refresh token signature, carrying the caller-supplied
// session hydrated from the marshalled session. When the refresh token has been deactivated it returns the hydrated
// request alongside oauth2.ErrInactiveToken.
func (s *HydratingMemoryStore) GetRefreshTokenSession(ctx context.Context, signature string, session oauth2.Session) (request oauth2.Requester, err error) {
	if request, err = s.MemoryStore.GetRefreshTokenSession(ctx, signature, session); err != nil && !errors.Is(err, oauth2.ErrInactiveToken) {
		return nil, err
	}

	if stored, ok := request.(StoreRefreshToken); ok {
		request = stored.Requester
	}

	hydrated, herr := s.hydrate("rt:"+signature, request, session)
	if herr != nil {
		return nil, herr
	}

	return hydrated, err
}
