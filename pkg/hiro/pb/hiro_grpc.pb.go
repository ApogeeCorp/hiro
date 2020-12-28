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
	AudienceCreate(ctx context.Context, in *AudienceCreateRequest, opts ...grpc.CallOption) (*Audience, error)
	AudienceUpdate(ctx context.Context, in *AudienceUpdateRequest, opts ...grpc.CallOption) (*Audience, error)
	AudienceGet(ctx context.Context, in *AudienceGetRequest, opts ...grpc.CallOption) (*Audience, error)
	AudienceList(ctx context.Context, in *AudienceListRequest, opts ...grpc.CallOption) (Hiro_AudienceListClient, error)
	AudienceDelete(ctx context.Context, in *AudienceDeleteRequest, opts ...grpc.CallOption) (*empty.Empty, error)
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

func (c *hiroClient) AudienceCreate(ctx context.Context, in *AudienceCreateRequest, opts ...grpc.CallOption) (*Audience, error) {
	out := new(Audience)
	err := c.cc.Invoke(ctx, "/hiro.Hiro/AudienceCreate", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *hiroClient) AudienceUpdate(ctx context.Context, in *AudienceUpdateRequest, opts ...grpc.CallOption) (*Audience, error) {
	out := new(Audience)
	err := c.cc.Invoke(ctx, "/hiro.Hiro/AudienceUpdate", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *hiroClient) AudienceGet(ctx context.Context, in *AudienceGetRequest, opts ...grpc.CallOption) (*Audience, error) {
	out := new(Audience)
	err := c.cc.Invoke(ctx, "/hiro.Hiro/AudienceGet", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *hiroClient) AudienceList(ctx context.Context, in *AudienceListRequest, opts ...grpc.CallOption) (Hiro_AudienceListClient, error) {
	stream, err := c.cc.NewStream(ctx, &_Hiro_serviceDesc.Streams[0], "/hiro.Hiro/AudienceList", opts...)
	if err != nil {
		return nil, err
	}
	x := &hiroAudienceListClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type Hiro_AudienceListClient interface {
	Recv() (*Audience, error)
	grpc.ClientStream
}

type hiroAudienceListClient struct {
	grpc.ClientStream
}

func (x *hiroAudienceListClient) Recv() (*Audience, error) {
	m := new(Audience)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *hiroClient) AudienceDelete(ctx context.Context, in *AudienceDeleteRequest, opts ...grpc.CallOption) (*empty.Empty, error) {
	out := new(empty.Empty)
	err := c.cc.Invoke(ctx, "/hiro.Hiro/AudienceDelete", in, out, opts...)
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
	AudienceCreate(context.Context, *AudienceCreateRequest) (*Audience, error)
	AudienceUpdate(context.Context, *AudienceUpdateRequest) (*Audience, error)
	AudienceGet(context.Context, *AudienceGetRequest) (*Audience, error)
	AudienceList(*AudienceListRequest, Hiro_AudienceListServer) error
	AudienceDelete(context.Context, *AudienceDeleteRequest) (*empty.Empty, error)
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

func (UnimplementedHiroServer) AudienceCreate(context.Context, *AudienceCreateRequest) (*Audience, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AudienceCreate not implemented")
}
func (UnimplementedHiroServer) AudienceUpdate(context.Context, *AudienceUpdateRequest) (*Audience, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AudienceUpdate not implemented")
}
func (UnimplementedHiroServer) AudienceGet(context.Context, *AudienceGetRequest) (*Audience, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AudienceGet not implemented")
}
func (UnimplementedHiroServer) AudienceList(*AudienceListRequest, Hiro_AudienceListServer) error {
	return status.Errorf(codes.Unimplemented, "method AudienceList not implemented")
}
func (UnimplementedHiroServer) AudienceDelete(context.Context, *AudienceDeleteRequest) (*empty.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AudienceDelete not implemented")
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

func _Hiro_AudienceCreate_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AudienceCreateRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(HiroServer).AudienceCreate(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/hiro.Hiro/AudienceCreate",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(HiroServer).AudienceCreate(ctx, req.(*AudienceCreateRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Hiro_AudienceUpdate_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AudienceUpdateRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(HiroServer).AudienceUpdate(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/hiro.Hiro/AudienceUpdate",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(HiroServer).AudienceUpdate(ctx, req.(*AudienceUpdateRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Hiro_AudienceGet_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AudienceGetRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(HiroServer).AudienceGet(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/hiro.Hiro/AudienceGet",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(HiroServer).AudienceGet(ctx, req.(*AudienceGetRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Hiro_AudienceList_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(AudienceListRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(HiroServer).AudienceList(m, &hiroAudienceListServer{stream})
}

type Hiro_AudienceListServer interface {
	Send(*Audience) error
	grpc.ServerStream
}

type hiroAudienceListServer struct {
	grpc.ServerStream
}

func (x *hiroAudienceListServer) Send(m *Audience) error {
	return x.ServerStream.SendMsg(m)
}

func _Hiro_AudienceDelete_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AudienceDeleteRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(HiroServer).AudienceDelete(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/hiro.Hiro/AudienceDelete",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(HiroServer).AudienceDelete(ctx, req.(*AudienceDeleteRequest))
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
			MethodName: "AudienceCreate",
			Handler:    _Hiro_AudienceCreate_Handler,
		},
		{
			MethodName: "AudienceUpdate",
			Handler:    _Hiro_AudienceUpdate_Handler,
		},
		{
			MethodName: "AudienceGet",
			Handler:    _Hiro_AudienceGet_Handler,
		},
		{
			MethodName: "AudienceDelete",
			Handler:    _Hiro_AudienceDelete_Handler,
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
			StreamName:    "AudienceList",
			Handler:       _Hiro_AudienceList_Handler,
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
