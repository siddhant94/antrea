// Copyright 2020 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/vmware-tanzu/antrea/pkg/agent/flowexporter/ipfix (interfaces: IPFIXExportingProcess,IPFIXRecord)

// Package testing is a generated GoMock package.
package testing

import (
	bytes "bytes"
	gomock "github.com/golang/mock/gomock"
	entities "github.com/vmware/go-ipfix/pkg/entities"
	reflect "reflect"
)

// MockIPFIXExportingProcess is a mock of IPFIXExportingProcess interface
type MockIPFIXExportingProcess struct {
	ctrl     *gomock.Controller
	recorder *MockIPFIXExportingProcessMockRecorder
}

// MockIPFIXExportingProcessMockRecorder is the mock recorder for MockIPFIXExportingProcess
type MockIPFIXExportingProcessMockRecorder struct {
	mock *MockIPFIXExportingProcess
}

// NewMockIPFIXExportingProcess creates a new mock instance
func NewMockIPFIXExportingProcess(ctrl *gomock.Controller) *MockIPFIXExportingProcess {
	mock := &MockIPFIXExportingProcess{ctrl: ctrl}
	mock.recorder = &MockIPFIXExportingProcessMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockIPFIXExportingProcess) EXPECT() *MockIPFIXExportingProcessMockRecorder {
	return m.recorder
}

// AddRecordAndSendMsg mocks base method
func (m *MockIPFIXExportingProcess) AddRecordAndSendMsg(arg0 entities.ContentType, arg1 entities.Record) (int, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddRecordAndSendMsg", arg0, arg1)
	ret0, _ := ret[0].(int)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AddRecordAndSendMsg indicates an expected call of AddRecordAndSendMsg
func (mr *MockIPFIXExportingProcessMockRecorder) AddRecordAndSendMsg(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddRecordAndSendMsg", reflect.TypeOf((*MockIPFIXExportingProcess)(nil).AddRecordAndSendMsg), arg0, arg1)
}

// CloseConnToCollector mocks base method
func (m *MockIPFIXExportingProcess) CloseConnToCollector() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "CloseConnToCollector")
}

// CloseConnToCollector indicates an expected call of CloseConnToCollector
func (mr *MockIPFIXExportingProcessMockRecorder) CloseConnToCollector() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CloseConnToCollector", reflect.TypeOf((*MockIPFIXExportingProcess)(nil).CloseConnToCollector))
}

// GetAntreaRegistryInfoElement mocks base method
func (m *MockIPFIXExportingProcess) GetAntreaRegistryInfoElement(arg0 string, arg1 bool) (*entities.InfoElement, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAntreaRegistryInfoElement", arg0, arg1)
	ret0, _ := ret[0].(*entities.InfoElement)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetAntreaRegistryInfoElement indicates an expected call of GetAntreaRegistryInfoElement
func (mr *MockIPFIXExportingProcessMockRecorder) GetAntreaRegistryInfoElement(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAntreaRegistryInfoElement", reflect.TypeOf((*MockIPFIXExportingProcess)(nil).GetAntreaRegistryInfoElement), arg0, arg1)
}

// GetIANARegistryInfoElement mocks base method
func (m *MockIPFIXExportingProcess) GetIANARegistryInfoElement(arg0 string, arg1 bool) (*entities.InfoElement, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetIANARegistryInfoElement", arg0, arg1)
	ret0, _ := ret[0].(*entities.InfoElement)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetIANARegistryInfoElement indicates an expected call of GetIANARegistryInfoElement
func (mr *MockIPFIXExportingProcessMockRecorder) GetIANARegistryInfoElement(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetIANARegistryInfoElement", reflect.TypeOf((*MockIPFIXExportingProcess)(nil).GetIANARegistryInfoElement), arg0, arg1)
}

// LoadRegistries mocks base method
func (m *MockIPFIXExportingProcess) LoadRegistries() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "LoadRegistries")
}

// LoadRegistries indicates an expected call of LoadRegistries
func (mr *MockIPFIXExportingProcessMockRecorder) LoadRegistries() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "LoadRegistries", reflect.TypeOf((*MockIPFIXExportingProcess)(nil).LoadRegistries))
}

// NewTemplateID mocks base method
func (m *MockIPFIXExportingProcess) NewTemplateID() uint16 {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "NewTemplateID")
	ret0, _ := ret[0].(uint16)
	return ret0
}

// NewTemplateID indicates an expected call of NewTemplateID
func (mr *MockIPFIXExportingProcessMockRecorder) NewTemplateID() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NewTemplateID", reflect.TypeOf((*MockIPFIXExportingProcess)(nil).NewTemplateID))
}

// MockIPFIXRecord is a mock of IPFIXRecord interface
type MockIPFIXRecord struct {
	ctrl     *gomock.Controller
	recorder *MockIPFIXRecordMockRecorder
}

// MockIPFIXRecordMockRecorder is the mock recorder for MockIPFIXRecord
type MockIPFIXRecordMockRecorder struct {
	mock *MockIPFIXRecord
}

// NewMockIPFIXRecord creates a new mock instance
func NewMockIPFIXRecord(ctrl *gomock.Controller) *MockIPFIXRecord {
	mock := &MockIPFIXRecord{ctrl: ctrl}
	mock.recorder = &MockIPFIXRecordMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockIPFIXRecord) EXPECT() *MockIPFIXRecordMockRecorder {
	return m.recorder
}

// AddInfoElement mocks base method
func (m *MockIPFIXRecord) AddInfoElement(arg0 *entities.InfoElement, arg1 interface{}) (uint16, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddInfoElement", arg0, arg1)
	ret0, _ := ret[0].(uint16)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AddInfoElement indicates an expected call of AddInfoElement
func (mr *MockIPFIXRecordMockRecorder) AddInfoElement(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddInfoElement", reflect.TypeOf((*MockIPFIXRecord)(nil).AddInfoElement), arg0, arg1)
}

// GetBuffer mocks base method
func (m *MockIPFIXRecord) GetBuffer() *bytes.Buffer {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetBuffer")
	ret0, _ := ret[0].(*bytes.Buffer)
	return ret0
}

// GetBuffer indicates an expected call of GetBuffer
func (mr *MockIPFIXRecordMockRecorder) GetBuffer() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetBuffer", reflect.TypeOf((*MockIPFIXRecord)(nil).GetBuffer))
}

// GetFieldCount mocks base method
func (m *MockIPFIXRecord) GetFieldCount() uint16 {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetFieldCount")
	ret0, _ := ret[0].(uint16)
	return ret0
}

// GetFieldCount indicates an expected call of GetFieldCount
func (mr *MockIPFIXRecordMockRecorder) GetFieldCount() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetFieldCount", reflect.TypeOf((*MockIPFIXRecord)(nil).GetFieldCount))
}

// GetRecord mocks base method
func (m *MockIPFIXRecord) GetRecord() entities.Record {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetRecord")
	ret0, _ := ret[0].(entities.Record)
	return ret0
}

// GetRecord indicates an expected call of GetRecord
func (mr *MockIPFIXRecordMockRecorder) GetRecord() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRecord", reflect.TypeOf((*MockIPFIXRecord)(nil).GetRecord))
}

// GetTemplateElements mocks base method
func (m *MockIPFIXRecord) GetTemplateElements() []*entities.InfoElement {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetTemplateElements")
	ret0, _ := ret[0].([]*entities.InfoElement)
	return ret0
}

// GetTemplateElements indicates an expected call of GetTemplateElements
func (mr *MockIPFIXRecordMockRecorder) GetTemplateElements() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetTemplateElements", reflect.TypeOf((*MockIPFIXRecord)(nil).GetTemplateElements))
}

// PrepareRecord mocks base method
func (m *MockIPFIXRecord) PrepareRecord() (uint16, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PrepareRecord")
	ret0, _ := ret[0].(uint16)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// PrepareRecord indicates an expected call of PrepareRecord
func (mr *MockIPFIXRecordMockRecorder) PrepareRecord() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PrepareRecord", reflect.TypeOf((*MockIPFIXRecord)(nil).PrepareRecord))
}
