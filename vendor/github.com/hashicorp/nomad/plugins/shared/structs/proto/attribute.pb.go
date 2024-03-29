// Code generated by protoc-gen-go. DO NOT EDIT.
// source: plugins/shared/structs/proto/attribute.proto

package proto

import (
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

// Attribute is used to describe the value of an attribute, optionally
// specifying units
type Attribute struct {
	// Types that are valid to be assigned to Value:
	//
	//	*Attribute_FloatVal
	//	*Attribute_IntVal
	//	*Attribute_StringVal
	//	*Attribute_BoolVal
	Value isAttribute_Value `protobuf_oneof:"value"`
	// unit gives the unit type: MHz, MB, etc.
	Unit                 string   `protobuf:"bytes,5,opt,name=unit,proto3" json:"unit,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Attribute) Reset()         { *m = Attribute{} }
func (m *Attribute) String() string { return proto.CompactTextString(m) }
func (*Attribute) ProtoMessage()    {}
func (*Attribute) Descriptor() ([]byte, []int) {
	return fileDescriptor_5b30c64b64565493, []int{0}
}

func (m *Attribute) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Attribute.Unmarshal(m, b)
}
func (m *Attribute) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Attribute.Marshal(b, m, deterministic)
}
func (m *Attribute) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Attribute.Merge(m, src)
}
func (m *Attribute) XXX_Size() int {
	return xxx_messageInfo_Attribute.Size(m)
}
func (m *Attribute) XXX_DiscardUnknown() {
	xxx_messageInfo_Attribute.DiscardUnknown(m)
}

var xxx_messageInfo_Attribute proto.InternalMessageInfo

type isAttribute_Value interface {
	isAttribute_Value()
}

type Attribute_FloatVal struct {
	FloatVal float64 `protobuf:"fixed64,1,opt,name=float_val,json=floatVal,proto3,oneof"`
}

type Attribute_IntVal struct {
	IntVal int64 `protobuf:"varint,2,opt,name=int_val,json=intVal,proto3,oneof"`
}

type Attribute_StringVal struct {
	StringVal string `protobuf:"bytes,3,opt,name=string_val,json=stringVal,proto3,oneof"`
}

type Attribute_BoolVal struct {
	BoolVal bool `protobuf:"varint,4,opt,name=bool_val,json=boolVal,proto3,oneof"`
}

func (*Attribute_FloatVal) isAttribute_Value() {}

func (*Attribute_IntVal) isAttribute_Value() {}

func (*Attribute_StringVal) isAttribute_Value() {}

func (*Attribute_BoolVal) isAttribute_Value() {}

func (m *Attribute) GetValue() isAttribute_Value {
	if m != nil {
		return m.Value
	}
	return nil
}

func (m *Attribute) GetFloatVal() float64 {
	if x, ok := m.GetValue().(*Attribute_FloatVal); ok {
		return x.FloatVal
	}
	return 0
}

func (m *Attribute) GetIntVal() int64 {
	if x, ok := m.GetValue().(*Attribute_IntVal); ok {
		return x.IntVal
	}
	return 0
}

func (m *Attribute) GetStringVal() string {
	if x, ok := m.GetValue().(*Attribute_StringVal); ok {
		return x.StringVal
	}
	return ""
}

func (m *Attribute) GetBoolVal() bool {
	if x, ok := m.GetValue().(*Attribute_BoolVal); ok {
		return x.BoolVal
	}
	return false
}

func (m *Attribute) GetUnit() string {
	if m != nil {
		return m.Unit
	}
	return ""
}

// XXX_OneofWrappers is for the internal use of the proto package.
func (*Attribute) XXX_OneofWrappers() []interface{} {
	return []interface{}{
		(*Attribute_FloatVal)(nil),
		(*Attribute_IntVal)(nil),
		(*Attribute_StringVal)(nil),
		(*Attribute_BoolVal)(nil),
	}
}

func init() {
	proto.RegisterType((*Attribute)(nil), "hashicorp.nomad.plugins.shared.structs.Attribute")
}

func init() {
	proto.RegisterFile("plugins/shared/structs/proto/attribute.proto", fileDescriptor_5b30c64b64565493)
}

var fileDescriptor_5b30c64b64565493 = []byte{
	// 218 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x34, 0x8f, 0xb1, 0x4e, 0xc3, 0x30,
	0x10, 0x40, 0x63, 0xda, 0x34, 0xc9, 0x8d, 0x99, 0x8a, 0x10, 0x22, 0x62, 0x40, 0x19, 0x90, 0x33,
	0xf0, 0x05, 0x74, 0xf2, 0xec, 0x81, 0x81, 0x05, 0x5d, 0xda, 0xd0, 0x58, 0x32, 0x76, 0x64, 0x9f,
	0xfb, 0x3d, 0x7c, 0x2a, 0xf2, 0x25, 0x4c, 0xf6, 0xbd, 0x77, 0x6f, 0x38, 0x78, 0x5d, 0x6c, 0xba,
	0x1a, 0x17, 0x87, 0x38, 0x63, 0x98, 0x2e, 0x43, 0xa4, 0x90, 0xce, 0x14, 0x87, 0x25, 0x78, 0xf2,
	0x03, 0x12, 0x05, 0x33, 0x26, 0x9a, 0x24, 0xcf, 0xed, 0xcb, 0x8c, 0x71, 0x36, 0x67, 0x1f, 0x16,
	0xe9, 0xfc, 0x0f, 0x5e, 0xe4, 0x56, 0xcb, 0xb5, 0x96, 0x5b, 0xfd, 0xfc, 0x2b, 0xa0, 0x79, 0xff,
	0x6f, 0xdb, 0x47, 0x68, 0xbe, 0xad, 0x47, 0xfa, 0xba, 0xa1, 0x3d, 0x8a, 0x4e, 0xf4, 0x42, 0x15,
	0xba, 0x66, 0xf4, 0x81, 0xb6, 0xbd, 0x87, 0xca, 0xb8, 0x55, 0xde, 0x75, 0xa2, 0xdf, 0xa9, 0x42,
	0x1f, 0x8c, 0x63, 0xf5, 0x04, 0x10, 0x29, 0x18, 0x77, 0x65, 0xbb, 0xeb, 0x44, 0xdf, 0xa8, 0x42,
	0x37, 0x2b, 0xcb, 0x0b, 0x0f, 0x50, 0x8f, 0xde, 0x5b, 0xd6, 0xfb, 0x4e, 0xf4, 0xb5, 0x2a, 0x74,
	0x95, 0x49, 0x96, 0x2d, 0xec, 0x93, 0x33, 0x74, 0x2c, 0x73, 0xa7, 0xf9, 0x7f, 0xaa, 0xa0, 0xbc,
	0xa1, 0x4d, 0xd3, 0xa9, 0xfa, 0x2c, 0xf9, 0xa6, 0xf1, 0xc0, 0xcf, 0xdb, 0x5f, 0x00, 0x00, 0x00,
	0xff, 0xff, 0x77, 0x2b, 0x7a, 0x7c, 0x0a, 0x01, 0x00, 0x00,
}
