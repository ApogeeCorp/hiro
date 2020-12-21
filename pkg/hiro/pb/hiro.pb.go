// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0
// 	protoc        v3.6.1
// source: hiro.proto

package pb

import (
	proto "github.com/golang/protobuf/proto"
	_struct "github.com/golang/protobuf/ptypes/struct"
	timestamp "github.com/golang/protobuf/ptypes/timestamp"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// This is a compile-time assertion that a sufficiently up-to-date version
// of the legacy proto package is being used.
const _ = proto.ProtoPackageIsVersion4

type AudienceGetRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to Query:
	//	*AudienceGetRequest_Id
	//	*AudienceGetRequest_Name
	Query isAudienceGetRequest_Query `protobuf_oneof:"query"`
}

func (x *AudienceGetRequest) Reset() {
	*x = AudienceGetRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_hiro_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AudienceGetRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AudienceGetRequest) ProtoMessage() {}

func (x *AudienceGetRequest) ProtoReflect() protoreflect.Message {
	mi := &file_hiro_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AudienceGetRequest.ProtoReflect.Descriptor instead.
func (*AudienceGetRequest) Descriptor() ([]byte, []int) {
	return file_hiro_proto_rawDescGZIP(), []int{0}
}

func (m *AudienceGetRequest) GetQuery() isAudienceGetRequest_Query {
	if m != nil {
		return m.Query
	}
	return nil
}

func (x *AudienceGetRequest) GetId() string {
	if x, ok := x.GetQuery().(*AudienceGetRequest_Id); ok {
		return x.Id
	}
	return ""
}

func (x *AudienceGetRequest) GetName() string {
	if x, ok := x.GetQuery().(*AudienceGetRequest_Name); ok {
		return x.Name
	}
	return ""
}

type isAudienceGetRequest_Query interface {
	isAudienceGetRequest_Query()
}

type AudienceGetRequest_Id struct {
	Id string `protobuf:"bytes,1,opt,name=id,proto3,oneof"`
}

type AudienceGetRequest_Name struct {
	Name string `protobuf:"bytes,2,opt,name=name,proto3,oneof"`
}

func (*AudienceGetRequest_Id) isAudienceGetRequest_Query() {}

func (*AudienceGetRequest_Name) isAudienceGetRequest_Query() {}

type Audience struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id              string               `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Name            string               `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
	Description     string               `protobuf:"bytes,3,opt,name=description,proto3" json:"description,omitempty"`
	CreatedAt       *timestamp.Timestamp `protobuf:"bytes,4,opt,name=created_at,json=createdAt,proto3" json:"created_at,omitempty"`
	UpdatedAt       *timestamp.Timestamp `protobuf:"bytes,5,opt,name=updated_at,json=updatedAt,proto3" json:"updated_at,omitempty"`
	Permissions     []string             `protobuf:"bytes,6,rep,name=permissions,proto3" json:"permissions,omitempty"`
	Metadata        *_struct.Struct      `protobuf:"bytes,7,opt,name=metadata,proto3" json:"metadata,omitempty"`
	SessionLifetime int64                `protobuf:"varint,8,opt,name=session_lifetime,json=sessionLifetime,proto3" json:"session_lifetime,omitempty"`
}

func (x *Audience) Reset() {
	*x = Audience{}
	if protoimpl.UnsafeEnabled {
		mi := &file_hiro_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Audience) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Audience) ProtoMessage() {}

func (x *Audience) ProtoReflect() protoreflect.Message {
	mi := &file_hiro_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Audience.ProtoReflect.Descriptor instead.
func (*Audience) Descriptor() ([]byte, []int) {
	return file_hiro_proto_rawDescGZIP(), []int{1}
}

func (x *Audience) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *Audience) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *Audience) GetDescription() string {
	if x != nil {
		return x.Description
	}
	return ""
}

func (x *Audience) GetCreatedAt() *timestamp.Timestamp {
	if x != nil {
		return x.CreatedAt
	}
	return nil
}

func (x *Audience) GetUpdatedAt() *timestamp.Timestamp {
	if x != nil {
		return x.UpdatedAt
	}
	return nil
}

func (x *Audience) GetPermissions() []string {
	if x != nil {
		return x.Permissions
	}
	return nil
}

func (x *Audience) GetMetadata() *_struct.Struct {
	if x != nil {
		return x.Metadata
	}
	return nil
}

func (x *Audience) GetSessionLifetime() int64 {
	if x != nil {
		return x.SessionLifetime
	}
	return 0
}

var File_hiro_proto protoreflect.FileDescriptor

var file_hiro_proto_rawDesc = []byte{
	0x0a, 0x0a, 0x68, 0x69, 0x72, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x04, 0x68, 0x69,
	0x72, 0x6f, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x62, 0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x1a, 0x1c, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x62, 0x75, 0x66, 0x2f, 0x73, 0x74, 0x72, 0x75, 0x63, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x22, 0x45, 0x0a, 0x12, 0x41, 0x75, 0x64, 0x69, 0x65, 0x6e, 0x63, 0x65, 0x47, 0x65, 0x74,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x10, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x48, 0x00, 0x52, 0x02, 0x69, 0x64, 0x12, 0x14, 0x0a, 0x04, 0x6e, 0x61, 0x6d,
	0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x48, 0x00, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x42,
	0x07, 0x0a, 0x05, 0x71, 0x75, 0x65, 0x72, 0x79, 0x22, 0xc8, 0x02, 0x0a, 0x08, 0x41, 0x75, 0x64,
	0x69, 0x65, 0x6e, 0x63, 0x65, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x02, 0x69, 0x64, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x20, 0x0a, 0x0b, 0x64, 0x65, 0x73,
	0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b,
	0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x39, 0x0a, 0x0a, 0x63,
	0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x61, 0x74, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75,
	0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x09, 0x63, 0x72, 0x65,
	0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x12, 0x39, 0x0a, 0x0a, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65,
	0x64, 0x5f, 0x61, 0x74, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d,
	0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x09, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x41,
	0x74, 0x12, 0x20, 0x0a, 0x0b, 0x70, 0x65, 0x72, 0x6d, 0x69, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x73,
	0x18, 0x06, 0x20, 0x03, 0x28, 0x09, 0x52, 0x0b, 0x70, 0x65, 0x72, 0x6d, 0x69, 0x73, 0x73, 0x69,
	0x6f, 0x6e, 0x73, 0x12, 0x33, 0x0a, 0x08, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x18,
	0x07, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x17, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x53, 0x74, 0x72, 0x75, 0x63, 0x74, 0x52, 0x08,
	0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x12, 0x29, 0x0a, 0x10, 0x73, 0x65, 0x73, 0x73,
	0x69, 0x6f, 0x6e, 0x5f, 0x6c, 0x69, 0x66, 0x65, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x08, 0x20, 0x01,
	0x28, 0x03, 0x52, 0x0f, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x4c, 0x69, 0x66, 0x65, 0x74,
	0x69, 0x6d, 0x65, 0x32, 0x3f, 0x0a, 0x04, 0x48, 0x69, 0x72, 0x6f, 0x12, 0x37, 0x0a, 0x0b, 0x41,
	0x75, 0x64, 0x69, 0x65, 0x6e, 0x63, 0x65, 0x47, 0x65, 0x74, 0x12, 0x18, 0x2e, 0x68, 0x69, 0x72,
	0x6f, 0x2e, 0x41, 0x75, 0x64, 0x69, 0x65, 0x6e, 0x63, 0x65, 0x47, 0x65, 0x74, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x1a, 0x0e, 0x2e, 0x68, 0x69, 0x72, 0x6f, 0x2e, 0x41, 0x75, 0x64, 0x69,
	0x65, 0x6e, 0x63, 0x65, 0x42, 0x29, 0x5a, 0x27, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63,
	0x6f, 0x6d, 0x2f, 0x4d, 0x6f, 0x64, 0x65, 0x6c, 0x52, 0x6f, 0x63, 0x6b, 0x65, 0x74, 0x2f, 0x68,
	0x69, 0x72, 0x6f, 0x2f, 0x70, 0x6b, 0x67, 0x2f, 0x68, 0x69, 0x72, 0x6f, 0x2f, 0x70, 0x62, 0x62,
	0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_hiro_proto_rawDescOnce sync.Once
	file_hiro_proto_rawDescData = file_hiro_proto_rawDesc
)

func file_hiro_proto_rawDescGZIP() []byte {
	file_hiro_proto_rawDescOnce.Do(func() {
		file_hiro_proto_rawDescData = protoimpl.X.CompressGZIP(file_hiro_proto_rawDescData)
	})
	return file_hiro_proto_rawDescData
}

var file_hiro_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_hiro_proto_goTypes = []interface{}{
	(*AudienceGetRequest)(nil),  // 0: hiro.AudienceGetRequest
	(*Audience)(nil),            // 1: hiro.Audience
	(*timestamp.Timestamp)(nil), // 2: google.protobuf.Timestamp
	(*_struct.Struct)(nil),      // 3: google.protobuf.Struct
}
var file_hiro_proto_depIdxs = []int32{
	2, // 0: hiro.Audience.created_at:type_name -> google.protobuf.Timestamp
	2, // 1: hiro.Audience.updated_at:type_name -> google.protobuf.Timestamp
	3, // 2: hiro.Audience.metadata:type_name -> google.protobuf.Struct
	0, // 3: hiro.Hiro.AudienceGet:input_type -> hiro.AudienceGetRequest
	1, // 4: hiro.Hiro.AudienceGet:output_type -> hiro.Audience
	4, // [4:5] is the sub-list for method output_type
	3, // [3:4] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_hiro_proto_init() }
func file_hiro_proto_init() {
	if File_hiro_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_hiro_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AudienceGetRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_hiro_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Audience); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	file_hiro_proto_msgTypes[0].OneofWrappers = []interface{}{
		(*AudienceGetRequest_Id)(nil),
		(*AudienceGetRequest_Name)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_hiro_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_hiro_proto_goTypes,
		DependencyIndexes: file_hiro_proto_depIdxs,
		MessageInfos:      file_hiro_proto_msgTypes,
	}.Build()
	File_hiro_proto = out.File
	file_hiro_proto_rawDesc = nil
	file_hiro_proto_goTypes = nil
	file_hiro_proto_depIdxs = nil
}
