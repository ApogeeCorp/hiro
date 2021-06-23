// Code generated by protoc-gen-go-grpc. DO NOT EDIT.

package pb

import (
	context "context"
	empty "github.com/golang/protobuf/ptypes/empty"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion7

// HiroClient is the client API for Hiro service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type HiroClient interface {
	InstanceCreate(ctx context.Context, in *InstanceCreateRequest, opts ...grpc.CallOption) (*Instance, error)
	InstanceUpdate(ctx context.Context, in *InstanceUpdateRequest, opts ...grpc.CallOption) (*Instance, error)
	InstanceGet(ctx context.Context, in *InstanceGetRequest, opts ...grpc.CallOption) (*Instance, error)
	InstanceList(ctx context.Context, in *InstanceListRequest, opts ...grpc.CallOption) (Hiro_InstanceListClient, error)
	InstanceDelete(ctx context.Context, in *InstanceDeleteRequest, opts ...grpc.CallOption) (*empty.Empty, error)
	ApplicationCreate(ctx context.Context, in *ApplicationCreateRequest, opts ...grpc.CallOption) (*Application, error)
	ApplicationUpdate(ctx context.Context, in *ApplicationUpdateRequest, opts ...grpc.CallOption) (*Application, error)
	ApplicationGet(ctx context.Context, in *ApplicationGetRequest, opts ...grpc.CallOption) (*Application, error)
	ApplicationList(ctx context.Context, in *ApplicationListRequest, opts ...grpc.CallOption) (Hiro_ApplicationListClient, error)
	ApplicationDelete(ctx context.Context, in *ApplicationDeleteRequest, opts ...grpc.CallOption) (*empty.Empty, error)
	SecretCreate(ctx context.Context, in *SecretCreateRequest, opts ...grpc.CallOption) (*Secret, error)
	SecreteDelete(ctx context.Context, in *SecretDeleteRequest, opts ...grpc.CallOption) (*empty.Empty, error)
}

type hiroClient struct {
	cc grpc.ClientConnInterface
}

func NewHiroClient(cc grpc.ClientConnInterface) HiroClient {
	return &hiroClient{cc}
}

func (c *hiroClient) InstanceCreate(ctx context.Context, in *InstanceCreateRequest, opts ...grpc.CallOption) (*Instance, error) {
	out := new(Instance)
	err := c.cc.Invoke(ctx, "/hiro.Hiro/InstanceCreate", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *hiroClient) InstanceUpdate(ctx context.Context, in *InstanceUpdateRequest, opts ...grpc.CallOption) (*Instance, error) {
	out := new(Instance)
	err := c.cc.Invoke(ctx, "/hiro.Hiro/InstanceUpdate", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *hiroClient) InstanceGet(ctx context.Context, in *InstanceGetRequest, opts ...grpc.CallOption) (*Instance, error) {
	out := new(Instance)
	err := c.cc.Invoke(ctx, "/hiro.Hiro/InstanceGet", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *hiroClient) InstanceList(ctx context.Context, in *InstanceListRequest, opts ...grpc.CallOption) (Hiro_InstanceListClient, error) {
	stream, err := c.cc.NewStream(ctx, &_Hiro_serviceDesc.Streams[0], "/hiro.Hiro/InstanceList", opts...)
	if err != nil {
		return nil, err
	}
	x := &hiroInstanceListClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type Hiro_InstanceListClient interface {
	Recv() (*Instance, error)
	grpc.ClientStream
}

type hiroInstanceListClient struct {
	grpc.ClientStream
}

func (x *hiroInstanceListClient) Recv() (*Instance, error) {
	m := new(Instance)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *hiroClient) InstanceDelete(ctx context.Context, in *InstanceDeleteRequest, opts ...grpc.CallOption) (*empty.Empty, error) {
	out := new(empty.Empty)
	err := c.cc.Invoke(ctx, "/hiro.Hiro/InstanceDelete", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *hiroClient) ApplicationCreate(ctx context.Context, in *ApplicationCreateRequest, opts ...grpc.CallOption) (*Application, error) {
	out := new(Application)
	err := c.cc.Invoke(ctx, "/hiro.Hiro/ApplicationCreate", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *hiroClient) ApplicationUpdate(ctx context.Context, in *ApplicationUpdateRequest, opts ...grpc.CallOption) (*Application, error) {
	out := new(Application)
	err := c.cc.Invoke(ctx, "/hiro.Hiro/ApplicationUpdate", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *hiroClient) ApplicationGet(ctx context.Context, in *ApplicationGetRequest, opts ...grpc.CallOption) (*Application, error) {
	out := new(Application)
	err := c.cc.Invoke(ctx, "/hiro.Hiro/ApplicationGet", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *hiroClient) ApplicationList(ctx context.Context, in *ApplicationListRequest, opts ...grpc.CallOption) (Hiro_ApplicationListClient, error) {
	stream, err := c.cc.NewStream(ctx, &_Hiro_serviceDesc.Streams[1], "/hiro.Hiro/ApplicationList", opts...)
	if err != nil {
		return nil, err
	}
	x := &hiroApplicationListClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type Hiro_ApplicationListClient interface {
	Recv() (*Application, error)
	grpc.ClientStream
}

type hiroApplicationListClient struct {
	grpc.ClientStream
}

func (x *hiroApplicationListClient) Recv() (*Application, error) {
	m := new(Application)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *hiroClient) ApplicationDelete(ctx context.Context, in *ApplicationDeleteRequest, opts ...grpc.CallOption) (*empty.Empty, error) {
	out := new(empty.Empty)
	err := c.cc.Invoke(ctx, "/hiro.Hiro/ApplicationDelete", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *hiroClient) SecretCreate(ctx context.Context, in *SecretCreateRequest, opts ...grpc.CallOption) (*Secret, error) {
	out := new(Secret)
	err := c.cc.Invoke(ctx, "/hiro.Hiro/SecretCreate", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *hiroClient) SecreteDelete(ctx context.Context, in *SecretDeleteRequest, opts ...grpc.CallOption) (*empty.Empty, error) {
	out := new(empty.Empty)
	err := c.cc.Invoke(ctx, "/hiro.Hiro/SecreteDelete", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// HiroServer is the server API for Hiro service.
// All implementations must embed UnimplementedHiroServer
// for forward compatibility
type HiroServer interface {
	InstanceCreate(context.Context, *InstanceCreateRequest) (*Instance, error)
	InstanceUpdate(context.Context, *InstanceUpdateRequest) (*Instance, error)
	InstanceGet(context.Context, *InstanceGetRequest) (*Instance, error)
	InstanceList(*InstanceListRequest, Hiro_InstanceListServer) error
	InstanceDelete(context.Context, *InstanceDeleteRequest) (*empty.Empty, error)
	ApplicationCreate(context.Context, *ApplicationCreateRequest) (*Application, error)
	ApplicationUpdate(context.Context, *ApplicationUpdateRequest) (*Application, error)
	ApplicationGet(context.Context, *ApplicationGetRequest) (*Application, error)
	ApplicationList(*ApplicationListRequest, Hiro_ApplicationListServer) error
	ApplicationDelete(context.Context, *ApplicationDeleteRequest) (*empty.Empty, error)
	SecretCreate(context.Context, *SecretCreateRequest) (*Secret, error)
	SecreteDelete(context.Context, *SecretDeleteRequest) (*empty.Empty, error)
	mustEmbedUnimplementedHiroServer()
}

// UnimplementedHiroServer must be embedded to have forward compatible implementations.
type UnimplementedHiroServer struct {
}

func (UnimplementedHiroServer) InstanceCreate(context.Context, *InstanceCreateRequest) (*Instance, error) {
	return nil, status.Errorf(codes.Unimplemented, "method InstanceCreate not implemented")
}
func (UnimplementedHiroServer) InstanceUpdate(context.Context, *InstanceUpdateRequest) (*Instance, error) {
	return nil, status.Errorf(codes.Unimplemented, "method InstanceUpdate not implemented")
}
func (UnimplementedHiroServer) InstanceGet(context.Context, *InstanceGetRequest) (*Instance, error) {
	return nil, status.Errorf(codes.Unimplemented, "method InstanceGet not implemented")
}
func (UnimplementedHiroServer) InstanceList(*InstanceListRequest, Hiro_InstanceListServer) error {
	return status.Errorf(codes.Unimplemented, "method InstanceList not implemented")
}
func (UnimplementedHiroServer) InstanceDelete(context.Context, *InstanceDeleteRequest) (*empty.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method InstanceDelete not implemented")
}
func (UnimplementedHiroServer) ApplicationCreate(context.Context, *ApplicationCreateRequest) (*Application, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ApplicationCreate not implemented")
}
func (UnimplementedHiroServer) ApplicationUpdate(context.Context, *ApplicationUpdateRequest) (*Application, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ApplicationUpdate not implemented")
}
func (UnimplementedHiroServer) ApplicationGet(context.Context, *ApplicationGetRequest) (*Application, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ApplicationGet not implemented")
}
func (UnimplementedHiroServer) ApplicationList(*ApplicationListRequest, Hiro_ApplicationListServer) error {
	return status.Errorf(codes.Unimplemented, "method ApplicationList not implemented")
}
func (UnimplementedHiroServer) ApplicationDelete(context.Context, *ApplicationDeleteRequest) (*empty.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ApplicationDelete not implemented")
}
func (UnimplementedHiroServer) SecretCreate(context.Context, *SecretCreateRequest) (*Secret, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SecretCreate not implemented")
}
func (UnimplementedHiroServer) SecreteDelete(context.Context, *SecretDeleteRequest) (*empty.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SecreteDelete not implemented")
}
func (UnimplementedHiroServer) mustEmbedUnimplementedHiroServer() {}

// UnsafeHiroServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to HiroServer will
// result in compilation errors.
type UnsafeHiroServer interface {
	mustEmbedUnimplementedHiroServer()
}

func RegisterHiroServer(s grpc.ServiceRegistrar, srv HiroServer) {
	s.RegisterService(&_Hiro_serviceDesc, srv)
}

func _Hiro_InstanceCreate_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(InstanceCreateRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(HiroServer).InstanceCreate(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/hiro.Hiro/InstanceCreate",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(HiroServer).InstanceCreate(ctx, req.(*InstanceCreateRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Hiro_InstanceUpdate_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(InstanceUpdateRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(HiroServer).InstanceUpdate(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/hiro.Hiro/InstanceUpdate",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(HiroServer).InstanceUpdate(ctx, req.(*InstanceUpdateRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Hiro_InstanceGet_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(InstanceGetRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(HiroServer).InstanceGet(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/hiro.Hiro/InstanceGet",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(HiroServer).InstanceGet(ctx, req.(*InstanceGetRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Hiro_InstanceList_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(InstanceListRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(HiroServer).InstanceList(m, &hiroInstanceListServer{stream})
}

type Hiro_InstanceListServer interface {
	Send(*Instance) error
	grpc.ServerStream
}

type hiroInstanceListServer struct {
	grpc.ServerStream
}

func (x *hiroInstanceListServer) Send(m *Instance) error {
	return x.ServerStream.SendMsg(m)
}

func _Hiro_InstanceDelete_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(InstanceDeleteRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(HiroServer).InstanceDelete(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/hiro.Hiro/InstanceDelete",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(HiroServer).InstanceDelete(ctx, req.(*InstanceDeleteRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Hiro_ApplicationCreate_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ApplicationCreateRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(HiroServer).ApplicationCreate(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/hiro.Hiro/ApplicationCreate",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(HiroServer).ApplicationCreate(ctx, req.(*ApplicationCreateRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Hiro_ApplicationUpdate_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ApplicationUpdateRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(HiroServer).ApplicationUpdate(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/hiro.Hiro/ApplicationUpdate",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(HiroServer).ApplicationUpdate(ctx, req.(*ApplicationUpdateRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Hiro_ApplicationGet_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ApplicationGetRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(HiroServer).ApplicationGet(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/hiro.Hiro/ApplicationGet",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(HiroServer).ApplicationGet(ctx, req.(*ApplicationGetRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Hiro_ApplicationList_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(ApplicationListRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(HiroServer).ApplicationList(m, &hiroApplicationListServer{stream})
}

type Hiro_ApplicationListServer interface {
	Send(*Application) error
	grpc.ServerStream
}

type hiroApplicationListServer struct {
	grpc.ServerStream
}

func (x *hiroApplicationListServer) Send(m *Application) error {
	return x.ServerStream.SendMsg(m)
}

func _Hiro_ApplicationDelete_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ApplicationDeleteRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(HiroServer).ApplicationDelete(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/hiro.Hiro/ApplicationDelete",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(HiroServer).ApplicationDelete(ctx, req.(*ApplicationDeleteRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Hiro_SecretCreate_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SecretCreateRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(HiroServer).SecretCreate(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/hiro.Hiro/SecretCreate",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(HiroServer).SecretCreate(ctx, req.(*SecretCreateRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Hiro_SecreteDelete_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SecretDeleteRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(HiroServer).SecreteDelete(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/hiro.Hiro/SecreteDelete",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(HiroServer).SecreteDelete(ctx, req.(*SecretDeleteRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _Hiro_serviceDesc = grpc.ServiceDesc{
	ServiceName: "hiro.Hiro",
	HandlerType: (*HiroServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "InstanceCreate",
			Handler:    _Hiro_InstanceCreate_Handler,
		},
		{
			MethodName: "InstanceUpdate",
			Handler:    _Hiro_InstanceUpdate_Handler,
		},
		{
			MethodName: "InstanceGet",
			Handler:    _Hiro_InstanceGet_Handler,
		},
		{
			MethodName: "InstanceDelete",
			Handler:    _Hiro_InstanceDelete_Handler,
		},
		{
			MethodName: "ApplicationCreate",
			Handler:    _Hiro_ApplicationCreate_Handler,
		},
		{
			MethodName: "ApplicationUpdate",
			Handler:    _Hiro_ApplicationUpdate_Handler,
		},
		{
			MethodName: "ApplicationGet",
			Handler:    _Hiro_ApplicationGet_Handler,
		},
		{
			MethodName: "ApplicationDelete",
			Handler:    _Hiro_ApplicationDelete_Handler,
		},
		{
			MethodName: "SecretCreate",
			Handler:    _Hiro_SecretCreate_Handler,
		},
		{
			MethodName: "SecreteDelete",
			Handler:    _Hiro_SecreteDelete_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "InstanceList",
			Handler:       _Hiro_InstanceList_Handler,
			ServerStreams: true,
		},
		{
			StreamName:    "ApplicationList",
			Handler:       _Hiro_ApplicationList_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "hiro.proto",
}
