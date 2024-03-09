// Code generated by MockGen. DO NOT EDIT.
// Source: authelia.com/provider/oauth2/handler/oauth2 (interfaces: CodeTokenEndpointHandler)
//
// Generated by this command:
//
//	mockgen -package internal -destination testing/mock/device_oauth2_handler.go authelia.com/provider/oauth2/handler/oauth2 CodeTokenEndpointHandler
//

// Package internal is a generated GoMock package.
package internal

import (
	context "context"
	reflect "reflect"

	oauth2 "authelia.com/provider/oauth2"
	gomock "go.uber.org/mock/gomock"
)

// MockCodeTokenEndpointHandler is a mock of CodeTokenEndpointHandler interface.
type MockCodeTokenEndpointHandler struct {
	ctrl     *gomock.Controller
	recorder *MockCodeTokenEndpointHandlerMockRecorder
}

// MockCodeTokenEndpointHandlerMockRecorder is the mock recorder for MockCodeTokenEndpointHandler.
type MockCodeTokenEndpointHandlerMockRecorder struct {
	mock *MockCodeTokenEndpointHandler
}

// NewMockCodeTokenEndpointHandler creates a new mock instance.
func NewMockCodeTokenEndpointHandler(ctrl *gomock.Controller) *MockCodeTokenEndpointHandler {
	mock := &MockCodeTokenEndpointHandler{ctrl: ctrl}
	mock.recorder = &MockCodeTokenEndpointHandlerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockCodeTokenEndpointHandler) EXPECT() *MockCodeTokenEndpointHandlerMockRecorder {
	return m.recorder
}

// CanHandleTokenEndpointRequest mocks base method.
func (m *MockCodeTokenEndpointHandler) CanHandleTokenEndpointRequest(arg0 context.Context, arg1 oauth2.AccessRequester) bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CanHandleTokenEndpointRequest", arg0, arg1)
	ret0, _ := ret[0].(bool)
	return ret0
}

// CanHandleTokenEndpointRequest indicates an expected call of CanHandleTokenEndpointRequest.
func (mr *MockCodeTokenEndpointHandlerMockRecorder) CanHandleTokenEndpointRequest(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CanHandleTokenEndpointRequest", reflect.TypeOf((*MockCodeTokenEndpointHandler)(nil).CanHandleTokenEndpointRequest), arg0, arg1)
}

// CanSkipClientAuth mocks base method.
func (m *MockCodeTokenEndpointHandler) CanSkipClientAuth(arg0 context.Context, arg1 oauth2.AccessRequester) bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CanSkipClientAuth", arg0, arg1)
	ret0, _ := ret[0].(bool)
	return ret0
}

// CanSkipClientAuth indicates an expected call of CanSkipClientAuth.
func (mr *MockCodeTokenEndpointHandlerMockRecorder) CanSkipClientAuth(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CanSkipClientAuth", reflect.TypeOf((*MockCodeTokenEndpointHandler)(nil).CanSkipClientAuth), arg0, arg1)
}

// DeviceCodeSignature mocks base method.
func (m *MockCodeTokenEndpointHandler) DeviceCodeSignature(arg0 context.Context, arg1 string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeviceCodeSignature", arg0, arg1)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DeviceCodeSignature indicates an expected call of DeviceCodeSignature.
func (mr *MockCodeTokenEndpointHandlerMockRecorder) DeviceCodeSignature(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeviceCodeSignature", reflect.TypeOf((*MockCodeTokenEndpointHandler)(nil).DeviceCodeSignature), arg0, arg1)
}

// GetCodeAndSession mocks base method.
func (m *MockCodeTokenEndpointHandler) GetCodeAndSession(arg0 context.Context, arg1 oauth2.AccessRequester) (string, string, oauth2.Requester, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetCodeAndSession", arg0, arg1)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(string)
	ret2, _ := ret[2].(oauth2.Requester)
	ret3, _ := ret[3].(error)
	return ret0, ret1, ret2, ret3
}

// GetCodeAndSession indicates an expected call of GetCodeAndSession.
func (mr *MockCodeTokenEndpointHandlerMockRecorder) GetCodeAndSession(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetCodeAndSession", reflect.TypeOf((*MockCodeTokenEndpointHandler)(nil).GetCodeAndSession), arg0, arg1)
}

// InvalidateSession mocks base method.
func (m *MockCodeTokenEndpointHandler) InvalidateSession(arg0 context.Context, arg1 string, arg2 oauth2.Requester) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "InvalidateSession", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// InvalidateSession indicates an expected call of InvalidateSession.
func (mr *MockCodeTokenEndpointHandlerMockRecorder) InvalidateSession(arg0, arg1, arg2 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InvalidateSession", reflect.TypeOf((*MockCodeTokenEndpointHandler)(nil).InvalidateSession), arg0, arg1, arg2)
}

// UpdateLastChecked mocks base method.
func (m *MockCodeTokenEndpointHandler) UpdateLastChecked(arg0 context.Context, arg1 oauth2.AccessRequester, arg2 oauth2.Requester) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateLastChecked", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// UpdateLastChecked indicates an expected call of UpdateLastChecked.
func (mr *MockCodeTokenEndpointHandlerMockRecorder) UpdateLastChecked(arg0, arg1, arg2 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateLastChecked", reflect.TypeOf((*MockCodeTokenEndpointHandler)(nil).UpdateLastChecked), arg0, arg1, arg2)
}

// ValidateCodeAndSession mocks base method.
func (m *MockCodeTokenEndpointHandler) ValidateCodeAndSession(arg0 context.Context, arg1 oauth2.AccessRequester, arg2 oauth2.Requester, arg3 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ValidateCodeAndSession", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(error)
	return ret0
}

// ValidateCodeAndSession indicates an expected call of ValidateCodeAndSession.
func (mr *MockCodeTokenEndpointHandlerMockRecorder) ValidateCodeAndSession(arg0, arg1, arg2, arg3 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ValidateCodeAndSession", reflect.TypeOf((*MockCodeTokenEndpointHandler)(nil).ValidateCodeAndSession), arg0, arg1, arg2, arg3)
}

// ValidateGrantTypes mocks base method.
func (m *MockCodeTokenEndpointHandler) ValidateGrantTypes(arg0 context.Context, arg1 oauth2.AccessRequester) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ValidateGrantTypes", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// ValidateGrantTypes indicates an expected call of ValidateGrantTypes.
func (mr *MockCodeTokenEndpointHandlerMockRecorder) ValidateGrantTypes(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ValidateGrantTypes", reflect.TypeOf((*MockCodeTokenEndpointHandler)(nil).ValidateGrantTypes), arg0, arg1)
}
