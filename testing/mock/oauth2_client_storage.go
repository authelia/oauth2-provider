// Code generated by MockGen. DO NOT EDIT.
// Source: authelia.com/provider/oauth2/handler/oauth2 (interfaces: ClientCredentialsGrantStorage)
//
// Generated by this command:
//
//	mockgen -package mock -destination testing/mock/oauth2_client_storage.go authelia.com/provider/oauth2/handler/oauth2 ClientCredentialsGrantStorage
//

// Package mock is a generated GoMock package.
package mock

import (
	context "context"
	reflect "reflect"

	oauth2 "authelia.com/provider/oauth2"
	gomock "go.uber.org/mock/gomock"
)

// MockClientCredentialsGrantStorage is a mock of ClientCredentialsGrantStorage interface.
type MockClientCredentialsGrantStorage struct {
	ctrl     *gomock.Controller
	recorder *MockClientCredentialsGrantStorageMockRecorder
}

// MockClientCredentialsGrantStorageMockRecorder is the mock recorder for MockClientCredentialsGrantStorage.
type MockClientCredentialsGrantStorageMockRecorder struct {
	mock *MockClientCredentialsGrantStorage
}

// NewMockClientCredentialsGrantStorage creates a new mock instance.
func NewMockClientCredentialsGrantStorage(ctrl *gomock.Controller) *MockClientCredentialsGrantStorage {
	mock := &MockClientCredentialsGrantStorage{ctrl: ctrl}
	mock.recorder = &MockClientCredentialsGrantStorageMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockClientCredentialsGrantStorage) EXPECT() *MockClientCredentialsGrantStorageMockRecorder {
	return m.recorder
}

// CreateAccessTokenSession mocks base method.
func (m *MockClientCredentialsGrantStorage) CreateAccessTokenSession(arg0 context.Context, arg1 string, arg2 oauth2.Requester) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateAccessTokenSession", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// CreateAccessTokenSession indicates an expected call of CreateAccessTokenSession.
func (mr *MockClientCredentialsGrantStorageMockRecorder) CreateAccessTokenSession(arg0, arg1, arg2 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateAccessTokenSession", reflect.TypeOf((*MockClientCredentialsGrantStorage)(nil).CreateAccessTokenSession), arg0, arg1, arg2)
}

// DeleteAccessTokenSession mocks base method.
func (m *MockClientCredentialsGrantStorage) DeleteAccessTokenSession(arg0 context.Context, arg1 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteAccessTokenSession", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteAccessTokenSession indicates an expected call of DeleteAccessTokenSession.
func (mr *MockClientCredentialsGrantStorageMockRecorder) DeleteAccessTokenSession(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteAccessTokenSession", reflect.TypeOf((*MockClientCredentialsGrantStorage)(nil).DeleteAccessTokenSession), arg0, arg1)
}

// GetAccessTokenSession mocks base method.
func (m *MockClientCredentialsGrantStorage) GetAccessTokenSession(arg0 context.Context, arg1 string, arg2 oauth2.Session) (oauth2.Requester, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAccessTokenSession", arg0, arg1, arg2)
	ret0, _ := ret[0].(oauth2.Requester)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetAccessTokenSession indicates an expected call of GetAccessTokenSession.
func (mr *MockClientCredentialsGrantStorageMockRecorder) GetAccessTokenSession(arg0, arg1, arg2 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAccessTokenSession", reflect.TypeOf((*MockClientCredentialsGrantStorage)(nil).GetAccessTokenSession), arg0, arg1, arg2)
}
