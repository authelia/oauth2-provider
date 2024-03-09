// Code generated by MockGen. DO NOT EDIT.
// Source: authelia.com/provider/oauth2 (interfaces: RevocationHandler)
//
// Generated by this command:
//
//	mockgen -package internal -destination testing/mock/revoke_handler.go authelia.com/provider/oauth2 RevocationHandler
//

// Package internal is a generated GoMock package.
package internal

import (
	context "context"
	reflect "reflect"

	oauth2 "authelia.com/provider/oauth2"
	gomock "go.uber.org/mock/gomock"
)

// MockRevocationHandler is a mock of RevocationHandler interface.
type MockRevocationHandler struct {
	ctrl     *gomock.Controller
	recorder *MockRevocationHandlerMockRecorder
}

// MockRevocationHandlerMockRecorder is the mock recorder for MockRevocationHandler.
type MockRevocationHandlerMockRecorder struct {
	mock *MockRevocationHandler
}

// NewMockRevocationHandler creates a new mock instance.
func NewMockRevocationHandler(ctrl *gomock.Controller) *MockRevocationHandler {
	mock := &MockRevocationHandler{ctrl: ctrl}
	mock.recorder = &MockRevocationHandlerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockRevocationHandler) EXPECT() *MockRevocationHandlerMockRecorder {
	return m.recorder
}

// RevokeToken mocks base method.
func (m *MockRevocationHandler) RevokeToken(arg0 context.Context, arg1 string, arg2 oauth2.TokenType, arg3 oauth2.Client) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RevokeToken", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(error)
	return ret0
}

// RevokeToken indicates an expected call of RevokeToken.
func (mr *MockRevocationHandlerMockRecorder) RevokeToken(arg0, arg1, arg2, arg3 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RevokeToken", reflect.TypeOf((*MockRevocationHandler)(nil).RevokeToken), arg0, arg1, arg2, arg3)
}
