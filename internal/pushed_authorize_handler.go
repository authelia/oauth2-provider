// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"context"
	"reflect"

	"go.uber.org/mock/gomock"

	"authelia.com/provider/oauth2"
)

// MockPushedAuthorizeEndpointHandler is a mock of PushedAuthorizeEndpointHandler interface
type MockPushedAuthorizeEndpointHandler struct {
	ctrl     *gomock.Controller
	recorder *MockPushedAuthorizeEndpointHandlerMockRecorder
}

// MockPushedAuthorizeEndpointHandlerMockRecorder is the mock recorder for PushedMockAuthorizeEndpointHandler
type MockPushedAuthorizeEndpointHandlerMockRecorder struct {
	mock *MockPushedAuthorizeEndpointHandler
}

// NewMockPushedAuthorizeEndpointHandler creates a new mock instance
func NewMockPushedAuthorizeEndpointHandler(ctrl *gomock.Controller) *MockPushedAuthorizeEndpointHandler {
	mock := &MockPushedAuthorizeEndpointHandler{ctrl: ctrl}
	mock.recorder = &MockPushedAuthorizeEndpointHandlerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockPushedAuthorizeEndpointHandler) EXPECT() *MockPushedAuthorizeEndpointHandlerMockRecorder {
	return m.recorder
}

// HandlePushedAuthorizeEndpointRequest mocks base method
func (m *MockPushedAuthorizeEndpointHandler) HandlePushedAuthorizeEndpointRequest(arg0 context.Context, arg1 oauth2.AuthorizeRequester, arg2 oauth2.PushedAuthorizeResponder) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "HandlePushedAuthorizeEndpointRequest", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// HandlePushedAuthorizeEndpointRequest indicates an expected call of HandlePushedAuthorizeEndpointRequest
func (mr *MockPushedAuthorizeEndpointHandlerMockRecorder) HandlePushedAuthorizeEndpointRequest(arg0, arg1, arg2 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "HandlePushedAuthorizeEndpointRequest", reflect.TypeOf((*MockPushedAuthorizeEndpointHandler)(nil).HandlePushedAuthorizeEndpointRequest), arg0, arg1, arg2)
}
