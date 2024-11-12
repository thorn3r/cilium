// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             v5.28.3
// source: recorder/recorder.proto

package recorder

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.62.0 or later.
const _ = grpc.SupportPackageIsVersion8

const (
	Recorder_Record_FullMethodName = "/recorder.Recorder/Record"
)

// RecorderClient is the client API for Recorder service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
//
// Recorder implements the Hubble module for capturing network packets
type RecorderClient interface {
	// Record can start and stop a single recording. The recording is
	// automatically stopped if the client aborts this rpc call.
	Record(ctx context.Context, opts ...grpc.CallOption) (Recorder_RecordClient, error)
}

type recorderClient struct {
	cc grpc.ClientConnInterface
}

func NewRecorderClient(cc grpc.ClientConnInterface) RecorderClient {
	return &recorderClient{cc}
}

func (c *recorderClient) Record(ctx context.Context, opts ...grpc.CallOption) (Recorder_RecordClient, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	stream, err := c.cc.NewStream(ctx, &Recorder_ServiceDesc.Streams[0], Recorder_Record_FullMethodName, cOpts...)
	if err != nil {
		return nil, err
	}
	x := &recorderRecordClient{ClientStream: stream}
	return x, nil
}

type Recorder_RecordClient interface {
	Send(*RecordRequest) error
	Recv() (*RecordResponse, error)
	grpc.ClientStream
}

type recorderRecordClient struct {
	grpc.ClientStream
}

func (x *recorderRecordClient) Send(m *RecordRequest) error {
	return x.ClientStream.SendMsg(m)
}

func (x *recorderRecordClient) Recv() (*RecordResponse, error) {
	m := new(RecordResponse)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// RecorderServer is the server API for Recorder service.
// All implementations should embed UnimplementedRecorderServer
// for forward compatibility
//
// Recorder implements the Hubble module for capturing network packets
type RecorderServer interface {
	// Record can start and stop a single recording. The recording is
	// automatically stopped if the client aborts this rpc call.
	Record(Recorder_RecordServer) error
}

// UnimplementedRecorderServer should be embedded to have forward compatible implementations.
type UnimplementedRecorderServer struct {
}

func (UnimplementedRecorderServer) Record(Recorder_RecordServer) error {
	return status.Errorf(codes.Unimplemented, "method Record not implemented")
}

// UnsafeRecorderServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to RecorderServer will
// result in compilation errors.
type UnsafeRecorderServer interface {
	mustEmbedUnimplementedRecorderServer()
}

func RegisterRecorderServer(s grpc.ServiceRegistrar, srv RecorderServer) {
	s.RegisterService(&Recorder_ServiceDesc, srv)
}

func _Recorder_Record_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(RecorderServer).Record(&recorderRecordServer{ServerStream: stream})
}

type Recorder_RecordServer interface {
	Send(*RecordResponse) error
	Recv() (*RecordRequest, error)
	grpc.ServerStream
}

type recorderRecordServer struct {
	grpc.ServerStream
}

func (x *recorderRecordServer) Send(m *RecordResponse) error {
	return x.ServerStream.SendMsg(m)
}

func (x *recorderRecordServer) Recv() (*RecordRequest, error) {
	m := new(RecordRequest)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// Recorder_ServiceDesc is the grpc.ServiceDesc for Recorder service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Recorder_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "recorder.Recorder",
	HandlerType: (*RecorderServer)(nil),
	Methods:     []grpc.MethodDesc{},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "Record",
			Handler:       _Recorder_Record_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
	},
	Metadata: "recorder/recorder.proto",
}
