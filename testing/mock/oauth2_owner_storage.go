// Code generated by MockGen. DO NOT EDIT.
// Source: authelia.com/provider/oauth2/handler/oauth2 (interfaces: ResourceOwnerPasswordCredentialsGrantStorage)
//
// Generated by this command:
//
//	mockgen -package mock -destination testing/mock/oauth2_owner_storage.go authelia.com/provider/oauth2/handler/oauth2 ResourceOwnerPasswordCredentialsGrantStorage
//

// Package mock is a generated GoMock package.
package mock

import (
	context "context"
	reflect "reflect"

	oauth2 "authelia.com/provider/oauth2"
	gomock "go.uber.org/mock/gomock"
)

// MockResourceOwnerPasswordCredentialsGrantStorage is a mock of ResourceOwnerPasswordCredentialsGrantStorage interface.
type MockResourceOwnerPasswordCredentialsGrantStorage struct {
	ctrl     *gomock.Controller
	recorder *MockResourceOwnerPasswordCredentialsGrantStorageMockRecorder
	isgomock struct{}
}

// MockResourceOwnerPasswordCredentialsGrantStorageMockRecorder is the mock recorder for MockResourceOwnerPasswordCredentialsGrantStorage.
type MockResourceOwnerPasswordCredentialsGrantStorageMockRecorder struct {
	mock *MockResourceOwnerPasswordCredentialsGrantStorage
}

// NewMockResourceOwnerPasswordCredentialsGrantStorage creates a new mock instance.
func NewMockResourceOwnerPasswordCredentialsGrantStorage(ctrl *gomock.Controller) *MockResourceOwnerPasswordCredentialsGrantStorage {
	mock := &MockResourceOwnerPasswordCredentialsGrantStorage{ctrl: ctrl}
	mock.recorder = &MockResourceOwnerPasswordCredentialsGrantStorageMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockResourceOwnerPasswordCredentialsGrantStorage) EXPECT() *MockResourceOwnerPasswordCredentialsGrantStorageMockRecorder {
	return m.recorder
}

// Authenticate mocks base method.
func (m *MockResourceOwnerPasswordCredentialsGrantStorage) Authenticate(ctx context.Context, name, secret string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Authenticate", ctx, name, secret)
	ret0, _ := ret[0].(error)
	return ret0
}

// Authenticate indicates an expected call of Authenticate.
func (mr *MockResourceOwnerPasswordCredentialsGrantStorageMockRecorder) Authenticate(ctx, name, secret any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Authenticate", reflect.TypeOf((*MockResourceOwnerPasswordCredentialsGrantStorage)(nil).Authenticate), ctx, name, secret)
}

// CreateAccessTokenSession mocks base method.
func (m *MockResourceOwnerPasswordCredentialsGrantStorage) CreateAccessTokenSession(ctx context.Context, signature string, request oauth2.Requester) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateAccessTokenSession", ctx, signature, request)
	ret0, _ := ret[0].(error)
	return ret0
}

// CreateAccessTokenSession indicates an expected call of CreateAccessTokenSession.
func (mr *MockResourceOwnerPasswordCredentialsGrantStorageMockRecorder) CreateAccessTokenSession(ctx, signature, request any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateAccessTokenSession", reflect.TypeOf((*MockResourceOwnerPasswordCredentialsGrantStorage)(nil).CreateAccessTokenSession), ctx, signature, request)
}

// CreateRefreshTokenSession mocks base method.
func (m *MockResourceOwnerPasswordCredentialsGrantStorage) CreateRefreshTokenSession(ctx context.Context, signature string, request oauth2.Requester) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateRefreshTokenSession", ctx, signature, request)
	ret0, _ := ret[0].(error)
	return ret0
}

// CreateRefreshTokenSession indicates an expected call of CreateRefreshTokenSession.
func (mr *MockResourceOwnerPasswordCredentialsGrantStorageMockRecorder) CreateRefreshTokenSession(ctx, signature, request any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateRefreshTokenSession", reflect.TypeOf((*MockResourceOwnerPasswordCredentialsGrantStorage)(nil).CreateRefreshTokenSession), ctx, signature, request)
}

// DeleteAccessTokenSession mocks base method.
func (m *MockResourceOwnerPasswordCredentialsGrantStorage) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteAccessTokenSession", ctx, signature)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteAccessTokenSession indicates an expected call of DeleteAccessTokenSession.
func (mr *MockResourceOwnerPasswordCredentialsGrantStorageMockRecorder) DeleteAccessTokenSession(ctx, signature any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteAccessTokenSession", reflect.TypeOf((*MockResourceOwnerPasswordCredentialsGrantStorage)(nil).DeleteAccessTokenSession), ctx, signature)
}

// DeleteRefreshTokenSession mocks base method.
func (m *MockResourceOwnerPasswordCredentialsGrantStorage) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteRefreshTokenSession", ctx, signature)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteRefreshTokenSession indicates an expected call of DeleteRefreshTokenSession.
func (mr *MockResourceOwnerPasswordCredentialsGrantStorageMockRecorder) DeleteRefreshTokenSession(ctx, signature any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteRefreshTokenSession", reflect.TypeOf((*MockResourceOwnerPasswordCredentialsGrantStorage)(nil).DeleteRefreshTokenSession), ctx, signature)
}

// GetAccessTokenSession mocks base method.
func (m *MockResourceOwnerPasswordCredentialsGrantStorage) GetAccessTokenSession(ctx context.Context, signature string, session oauth2.Session) (oauth2.Requester, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAccessTokenSession", ctx, signature, session)
	ret0, _ := ret[0].(oauth2.Requester)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetAccessTokenSession indicates an expected call of GetAccessTokenSession.
func (mr *MockResourceOwnerPasswordCredentialsGrantStorageMockRecorder) GetAccessTokenSession(ctx, signature, session any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAccessTokenSession", reflect.TypeOf((*MockResourceOwnerPasswordCredentialsGrantStorage)(nil).GetAccessTokenSession), ctx, signature, session)
}

// GetRefreshTokenSession mocks base method.
func (m *MockResourceOwnerPasswordCredentialsGrantStorage) GetRefreshTokenSession(ctx context.Context, signature string, session oauth2.Session) (oauth2.Requester, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetRefreshTokenSession", ctx, signature, session)
	ret0, _ := ret[0].(oauth2.Requester)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetRefreshTokenSession indicates an expected call of GetRefreshTokenSession.
func (mr *MockResourceOwnerPasswordCredentialsGrantStorageMockRecorder) GetRefreshTokenSession(ctx, signature, session any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRefreshTokenSession", reflect.TypeOf((*MockResourceOwnerPasswordCredentialsGrantStorage)(nil).GetRefreshTokenSession), ctx, signature, session)
}
