// Code generated by MockGen. DO NOT EDIT.
// Source: authelia.com/provider/oauth2/handler/openid (interfaces: OpenIDConnectRequestStorage)
//
// Generated by this command:
//
//	mockgen -package mock -destination testing/mock/openid_id_token_storage.go authelia.com/provider/oauth2/handler/openid OpenIDConnectRequestStorage
//

// Package mock is a generated GoMock package.
package mock

import (
	context "context"
	reflect "reflect"

	oauth2 "authelia.com/provider/oauth2"
	gomock "go.uber.org/mock/gomock"
)

// MockOpenIDConnectRequestStorage is a mock of OpenIDConnectRequestStorage interface.
type MockOpenIDConnectRequestStorage struct {
	ctrl     *gomock.Controller
	recorder *MockOpenIDConnectRequestStorageMockRecorder
	isgomock struct{}
}

// MockOpenIDConnectRequestStorageMockRecorder is the mock recorder for MockOpenIDConnectRequestStorage.
type MockOpenIDConnectRequestStorageMockRecorder struct {
	mock *MockOpenIDConnectRequestStorage
}

// NewMockOpenIDConnectRequestStorage creates a new mock instance.
func NewMockOpenIDConnectRequestStorage(ctrl *gomock.Controller) *MockOpenIDConnectRequestStorage {
	mock := &MockOpenIDConnectRequestStorage{ctrl: ctrl}
	mock.recorder = &MockOpenIDConnectRequestStorageMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockOpenIDConnectRequestStorage) EXPECT() *MockOpenIDConnectRequestStorageMockRecorder {
	return m.recorder
}

// CreateOpenIDConnectSession mocks base method.
func (m *MockOpenIDConnectRequestStorage) CreateOpenIDConnectSession(ctx context.Context, authorizeCode string, requester oauth2.Requester) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateOpenIDConnectSession", ctx, authorizeCode, requester)
	ret0, _ := ret[0].(error)
	return ret0
}

// CreateOpenIDConnectSession indicates an expected call of CreateOpenIDConnectSession.
func (mr *MockOpenIDConnectRequestStorageMockRecorder) CreateOpenIDConnectSession(ctx, authorizeCode, requester any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateOpenIDConnectSession", reflect.TypeOf((*MockOpenIDConnectRequestStorage)(nil).CreateOpenIDConnectSession), ctx, authorizeCode, requester)
}

// DeleteOpenIDConnectSession mocks base method.
func (m *MockOpenIDConnectRequestStorage) DeleteOpenIDConnectSession(ctx context.Context, authorizeCode string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteOpenIDConnectSession", ctx, authorizeCode)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteOpenIDConnectSession indicates an expected call of DeleteOpenIDConnectSession.
func (mr *MockOpenIDConnectRequestStorageMockRecorder) DeleteOpenIDConnectSession(ctx, authorizeCode any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteOpenIDConnectSession", reflect.TypeOf((*MockOpenIDConnectRequestStorage)(nil).DeleteOpenIDConnectSession), ctx, authorizeCode)
}

// GetOpenIDConnectSession mocks base method.
func (m *MockOpenIDConnectRequestStorage) GetOpenIDConnectSession(ctx context.Context, authorizeCode string, requester oauth2.Requester) (oauth2.Requester, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetOpenIDConnectSession", ctx, authorizeCode, requester)
	ret0, _ := ret[0].(oauth2.Requester)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetOpenIDConnectSession indicates an expected call of GetOpenIDConnectSession.
func (mr *MockOpenIDConnectRequestStorageMockRecorder) GetOpenIDConnectSession(ctx, authorizeCode, requester any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetOpenIDConnectSession", reflect.TypeOf((*MockOpenIDConnectRequestStorage)(nil).GetOpenIDConnectSession), ctx, authorizeCode, requester)
}
