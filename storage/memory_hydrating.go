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

// CreateCIBASession stores a copy of the request against the 'auth_req_id' signature. The marshalled session is
// published under the same lock as the write and only once it succeeds, so a failed write leaves no session behind.
func (s *HydratingMemoryStore) CreateCIBASession(ctx context.Context, signature string, request oauth2.BackChannelAuthenticationRequester) (err error) {
	var data []byte

	if request.GetSession() != nil {
		if data, err = json.Marshal(request.GetSession()); err != nil {
			return err
		}
	}

	s.sessionsMutex.Lock()
	defer s.sessionsMutex.Unlock()

	if err = s.MemoryStore.CreateCIBASession(ctx, signature, request); err != nil {
		return err
	}

	if data != nil {
		s.sessions["ciba:"+signature] = data
	}

	return nil
}

// UpdateCIBASession writes the polling state of the request onto the stored request, as MemoryStore does. The
// marshalled session is not republished.
func (s *HydratingMemoryStore) UpdateCIBASession(ctx context.Context, signature string, request oauth2.BackChannelAuthenticationRequester) (err error) {
	return s.MemoryStore.UpdateCIBASession(ctx, signature, request)
}

// DecideCIBASession stores the request only while the stored request is pending. The marshalled session is published
// under the same lock as the decision and only once it succeeds, so a reader never sees a decided request with another
// decider's session and a rejected decision never overwrites the blob.
func (s *HydratingMemoryStore) DecideCIBASession(ctx context.Context, signature string, request oauth2.BackChannelAuthenticationRequester) (err error) {
	var data []byte

	if request.GetSession() != nil {
		if data, err = json.Marshal(request.GetSession()); err != nil {
			return err
		}
	}

	s.sessionsMutex.Lock()
	defer s.sessionsMutex.Unlock()

	if err = s.MemoryStore.DecideCIBASession(ctx, signature, request); err != nil {
		return err
	}

	if data != nil {
		s.sessions["ciba:"+signature] = data
	}

	return nil
}

// GetCIBASession returns the request stored against the 'auth_req_id' signature, carrying the caller-supplied session
// hydrated from the marshalled session. The request is returned alongside oauth2.ErrInvalidatedCIBASession.
func (s *HydratingMemoryStore) GetCIBASession(ctx context.Context, signature string, session oauth2.Session) (request oauth2.BackChannelAuthenticationRequester, err error) {
	s.sessionsMutex.RLock()
	defer s.sessionsMutex.RUnlock()

	request, err = s.MemoryStore.GetCIBASession(ctx, signature, session)

	return s.hydrateCIBA("ciba:"+signature, request, session, err)
}

// GetCIBASessionByRequestID returns the request with the given request ID, hydrated as GetCIBASession does.
func (s *HydratingMemoryStore) GetCIBASessionByRequestID(ctx context.Context, requestID string, session oauth2.Session) (request oauth2.BackChannelAuthenticationRequester, err error) {
	s.cibaSessionsMutex.RLock()
	signature, ok := s.CIBARequestIDs[requestID]
	s.cibaSessionsMutex.RUnlock()

	if !ok {
		return nil, oauth2.ErrNotFound
	}

	return s.GetCIBASession(ctx, signature, session)
}

// hydrateCIBA requires the caller to hold sessionsMutex.
func (s *HydratingMemoryStore) hydrateCIBA(key string, request oauth2.BackChannelAuthenticationRequester, session oauth2.Session, getErr error) (oauth2.BackChannelAuthenticationRequester, error) {
	if request == nil || (getErr != nil && !errors.Is(getErr, oauth2.ErrInvalidatedCIBASession)) {
		return nil, getErr
	}

	req, ok := request.(*oauth2.BackChannelAuthenticationRequest)
	if !ok {
		return nil, fmt.Errorf("HydratingMemoryStore cannot hydrate a %T; it can only clone *oauth2.BackChannelAuthenticationRequest", request)
	}

	if session == nil {
		return req, getErr
	}

	data, found := s.sessions[key]
	if !found {
		return req, getErr
	}

	if err := json.Unmarshal(data, session); err != nil {
		return nil, err
	}

	req.Session = session

	return req, getErr
}
