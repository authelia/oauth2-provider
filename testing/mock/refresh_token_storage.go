// Code generated by MockGen. DO NOT EDIT.
// Source: authelia.com/provider/oauth2/handler/oauth2 (interfaces: RefreshTokenStorage)
//
// Generated by this command:
//
//	mockgen -package mock -destination testing/mock/refresh_token_storage.go authelia.com/provider/oauth2/handler/oauth2 RefreshTokenStorage
//

// Package mock is a generated GoMock package.
package mock

import (
	context "context"
	reflect "reflect"

	oauth2 "authelia.com/provider/oauth2"
	gomock "go.uber.org/mock/gomock"
)

// MockRefreshTokenStorage is a mock of RefreshTokenStorage interface.
type MockRefreshTokenStorage struct {
	ctrl     *gomock.Controller
	recorder *MockRefreshTokenStorageMockRecorder
}

// MockRefreshTokenStorageMockRecorder is the mock recorder for MockRefreshTokenStorage.
type MockRefreshTokenStorageMockRecorder struct {
	mock *MockRefreshTokenStorage
}

// NewMockRefreshTokenStorage creates a new mock instance.
func NewMockRefreshTokenStorage(ctrl *gomock.Controller) *MockRefreshTokenStorage {
	mock := &MockRefreshTokenStorage{ctrl: ctrl}
	mock.recorder = &MockRefreshTokenStorageMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockRefreshTokenStorage) EXPECT() *MockRefreshTokenStorageMockRecorder {
	return m.recorder
}

// CreateRefreshTokenSession mocks base method.
func (m *MockRefreshTokenStorage) CreateRefreshTokenSession(arg0 context.Context, arg1 string, arg2 oauth2.Requester) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateRefreshTokenSession", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// CreateRefreshTokenSession indicates an expected call of CreateRefreshTokenSession.
func (mr *MockRefreshTokenStorageMockRecorder) CreateRefreshTokenSession(arg0, arg1, arg2 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateRefreshTokenSession", reflect.TypeOf((*MockRefreshTokenStorage)(nil).CreateRefreshTokenSession), arg0, arg1, arg2)
}

// DeleteRefreshTokenSession mocks base method.
func (m *MockRefreshTokenStorage) DeleteRefreshTokenSession(arg0 context.Context, arg1 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteRefreshTokenSession", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteRefreshTokenSession indicates an expected call of DeleteRefreshTokenSession.
func (mr *MockRefreshTokenStorageMockRecorder) DeleteRefreshTokenSession(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteRefreshTokenSession", reflect.TypeOf((*MockRefreshTokenStorage)(nil).DeleteRefreshTokenSession), arg0, arg1)
}

// GetRefreshTokenSession mocks base method.
func (m *MockRefreshTokenStorage) GetRefreshTokenSession(arg0 context.Context, arg1 string, arg2 oauth2.Session) (oauth2.Requester, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetRefreshTokenSession", arg0, arg1, arg2)
	ret0, _ := ret[0].(oauth2.Requester)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetRefreshTokenSession indicates an expected call of GetRefreshTokenSession.
func (mr *MockRefreshTokenStorageMockRecorder) GetRefreshTokenSession(arg0, arg1, arg2 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRefreshTokenSession", reflect.TypeOf((*MockRefreshTokenStorage)(nil).GetRefreshTokenSession), arg0, arg1, arg2)
}
