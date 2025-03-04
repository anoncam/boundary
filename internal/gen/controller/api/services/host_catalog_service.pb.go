// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.27.1
// 	protoc        (unknown)
// source: controller/api/services/v1/host_catalog_service.proto

package services

import (
	_ "github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2/options"
	hostcatalogs "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostcatalogs"
	_ "github.com/hashicorp/boundary/sdk/pbs/controller/protooptions"
	_ "google.golang.org/genproto/googleapis/api/annotations"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	fieldmaskpb "google.golang.org/protobuf/types/known/fieldmaskpb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type GetHostCatalogRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty" class:"public"` // @gotags: `class:"public"`
}

func (x *GetHostCatalogRequest) Reset() {
	*x = GetHostCatalogRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_services_v1_host_catalog_service_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetHostCatalogRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetHostCatalogRequest) ProtoMessage() {}

func (x *GetHostCatalogRequest) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_services_v1_host_catalog_service_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetHostCatalogRequest.ProtoReflect.Descriptor instead.
func (*GetHostCatalogRequest) Descriptor() ([]byte, []int) {
	return file_controller_api_services_v1_host_catalog_service_proto_rawDescGZIP(), []int{0}
}

func (x *GetHostCatalogRequest) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

type GetHostCatalogResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Item *hostcatalogs.HostCatalog `protobuf:"bytes,1,opt,name=item,proto3" json:"item,omitempty"`
}

func (x *GetHostCatalogResponse) Reset() {
	*x = GetHostCatalogResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_services_v1_host_catalog_service_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetHostCatalogResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetHostCatalogResponse) ProtoMessage() {}

func (x *GetHostCatalogResponse) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_services_v1_host_catalog_service_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetHostCatalogResponse.ProtoReflect.Descriptor instead.
func (*GetHostCatalogResponse) Descriptor() ([]byte, []int) {
	return file_controller_api_services_v1_host_catalog_service_proto_rawDescGZIP(), []int{1}
}

func (x *GetHostCatalogResponse) GetItem() *hostcatalogs.HostCatalog {
	if x != nil {
		return x.Item
	}
	return nil
}

type ListHostCatalogsRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ScopeId   string `protobuf:"bytes,1,opt,name=scope_id,proto3" json:"scope_id,omitempty" class:"public"`     // @gotags: `class:"public"`
	Recursive bool   `protobuf:"varint,20,opt,name=recursive,proto3" json:"recursive,omitempty" class:"public"` // @gotags: `class:"public"`
	Filter    string `protobuf:"bytes,30,opt,name=filter,proto3" json:"filter,omitempty" class:"public"`        // @gotags: `class:"public"`
}

func (x *ListHostCatalogsRequest) Reset() {
	*x = ListHostCatalogsRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_services_v1_host_catalog_service_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ListHostCatalogsRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ListHostCatalogsRequest) ProtoMessage() {}

func (x *ListHostCatalogsRequest) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_services_v1_host_catalog_service_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ListHostCatalogsRequest.ProtoReflect.Descriptor instead.
func (*ListHostCatalogsRequest) Descriptor() ([]byte, []int) {
	return file_controller_api_services_v1_host_catalog_service_proto_rawDescGZIP(), []int{2}
}

func (x *ListHostCatalogsRequest) GetScopeId() string {
	if x != nil {
		return x.ScopeId
	}
	return ""
}

func (x *ListHostCatalogsRequest) GetRecursive() bool {
	if x != nil {
		return x.Recursive
	}
	return false
}

func (x *ListHostCatalogsRequest) GetFilter() string {
	if x != nil {
		return x.Filter
	}
	return ""
}

type ListHostCatalogsResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Items []*hostcatalogs.HostCatalog `protobuf:"bytes,1,rep,name=items,proto3" json:"items,omitempty"`
}

func (x *ListHostCatalogsResponse) Reset() {
	*x = ListHostCatalogsResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_services_v1_host_catalog_service_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ListHostCatalogsResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ListHostCatalogsResponse) ProtoMessage() {}

func (x *ListHostCatalogsResponse) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_services_v1_host_catalog_service_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ListHostCatalogsResponse.ProtoReflect.Descriptor instead.
func (*ListHostCatalogsResponse) Descriptor() ([]byte, []int) {
	return file_controller_api_services_v1_host_catalog_service_proto_rawDescGZIP(), []int{3}
}

func (x *ListHostCatalogsResponse) GetItems() []*hostcatalogs.HostCatalog {
	if x != nil {
		return x.Items
	}
	return nil
}

type CreateHostCatalogRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Item *hostcatalogs.HostCatalog `protobuf:"bytes,1,opt,name=item,proto3" json:"item,omitempty"`
	// As an alternative to providing the plugin id in the provided HostCatalog,
	// this field can be used to lookup the plugin using its name.
	PluginName string `protobuf:"bytes,2,opt,name=plugin_name,proto3" json:"plugin_name,omitempty" class:"public"` // @gotags: `class:"public"`
}

func (x *CreateHostCatalogRequest) Reset() {
	*x = CreateHostCatalogRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_services_v1_host_catalog_service_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CreateHostCatalogRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CreateHostCatalogRequest) ProtoMessage() {}

func (x *CreateHostCatalogRequest) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_services_v1_host_catalog_service_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CreateHostCatalogRequest.ProtoReflect.Descriptor instead.
func (*CreateHostCatalogRequest) Descriptor() ([]byte, []int) {
	return file_controller_api_services_v1_host_catalog_service_proto_rawDescGZIP(), []int{4}
}

func (x *CreateHostCatalogRequest) GetItem() *hostcatalogs.HostCatalog {
	if x != nil {
		return x.Item
	}
	return nil
}

func (x *CreateHostCatalogRequest) GetPluginName() string {
	if x != nil {
		return x.PluginName
	}
	return ""
}

type CreateHostCatalogResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Uri  string                    `protobuf:"bytes,1,opt,name=uri,proto3" json:"uri,omitempty" class:"public"` // @gotags: `class:"public"`
	Item *hostcatalogs.HostCatalog `protobuf:"bytes,2,opt,name=item,proto3" json:"item,omitempty"`
}

func (x *CreateHostCatalogResponse) Reset() {
	*x = CreateHostCatalogResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_services_v1_host_catalog_service_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CreateHostCatalogResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CreateHostCatalogResponse) ProtoMessage() {}

func (x *CreateHostCatalogResponse) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_services_v1_host_catalog_service_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CreateHostCatalogResponse.ProtoReflect.Descriptor instead.
func (*CreateHostCatalogResponse) Descriptor() ([]byte, []int) {
	return file_controller_api_services_v1_host_catalog_service_proto_rawDescGZIP(), []int{5}
}

func (x *CreateHostCatalogResponse) GetUri() string {
	if x != nil {
		return x.Uri
	}
	return ""
}

func (x *CreateHostCatalogResponse) GetItem() *hostcatalogs.HostCatalog {
	if x != nil {
		return x.Item
	}
	return nil
}

type UpdateHostCatalogRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id         string                    `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty" class:"public"` // @gotags: `class:"public"`
	Item       *hostcatalogs.HostCatalog `protobuf:"bytes,2,opt,name=item,proto3" json:"item,omitempty"`
	UpdateMask *fieldmaskpb.FieldMask    `protobuf:"bytes,3,opt,name=update_mask,json=updateMask,proto3" json:"update_mask,omitempty"`
}

func (x *UpdateHostCatalogRequest) Reset() {
	*x = UpdateHostCatalogRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_services_v1_host_catalog_service_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UpdateHostCatalogRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UpdateHostCatalogRequest) ProtoMessage() {}

func (x *UpdateHostCatalogRequest) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_services_v1_host_catalog_service_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UpdateHostCatalogRequest.ProtoReflect.Descriptor instead.
func (*UpdateHostCatalogRequest) Descriptor() ([]byte, []int) {
	return file_controller_api_services_v1_host_catalog_service_proto_rawDescGZIP(), []int{6}
}

func (x *UpdateHostCatalogRequest) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *UpdateHostCatalogRequest) GetItem() *hostcatalogs.HostCatalog {
	if x != nil {
		return x.Item
	}
	return nil
}

func (x *UpdateHostCatalogRequest) GetUpdateMask() *fieldmaskpb.FieldMask {
	if x != nil {
		return x.UpdateMask
	}
	return nil
}

type UpdateHostCatalogResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Item *hostcatalogs.HostCatalog `protobuf:"bytes,1,opt,name=item,proto3" json:"item,omitempty"`
}

func (x *UpdateHostCatalogResponse) Reset() {
	*x = UpdateHostCatalogResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_services_v1_host_catalog_service_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UpdateHostCatalogResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UpdateHostCatalogResponse) ProtoMessage() {}

func (x *UpdateHostCatalogResponse) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_services_v1_host_catalog_service_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UpdateHostCatalogResponse.ProtoReflect.Descriptor instead.
func (*UpdateHostCatalogResponse) Descriptor() ([]byte, []int) {
	return file_controller_api_services_v1_host_catalog_service_proto_rawDescGZIP(), []int{7}
}

func (x *UpdateHostCatalogResponse) GetItem() *hostcatalogs.HostCatalog {
	if x != nil {
		return x.Item
	}
	return nil
}

type DeleteHostCatalogRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty" class:"public"` // @gotags: `class:"public"`
}

func (x *DeleteHostCatalogRequest) Reset() {
	*x = DeleteHostCatalogRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_services_v1_host_catalog_service_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DeleteHostCatalogRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DeleteHostCatalogRequest) ProtoMessage() {}

func (x *DeleteHostCatalogRequest) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_services_v1_host_catalog_service_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DeleteHostCatalogRequest.ProtoReflect.Descriptor instead.
func (*DeleteHostCatalogRequest) Descriptor() ([]byte, []int) {
	return file_controller_api_services_v1_host_catalog_service_proto_rawDescGZIP(), []int{8}
}

func (x *DeleteHostCatalogRequest) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

type DeleteHostCatalogResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *DeleteHostCatalogResponse) Reset() {
	*x = DeleteHostCatalogResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_services_v1_host_catalog_service_proto_msgTypes[9]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DeleteHostCatalogResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DeleteHostCatalogResponse) ProtoMessage() {}

func (x *DeleteHostCatalogResponse) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_services_v1_host_catalog_service_proto_msgTypes[9]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DeleteHostCatalogResponse.ProtoReflect.Descriptor instead.
func (*DeleteHostCatalogResponse) Descriptor() ([]byte, []int) {
	return file_controller_api_services_v1_host_catalog_service_proto_rawDescGZIP(), []int{9}
}

var File_controller_api_services_v1_host_catalog_service_proto protoreflect.FileDescriptor

var file_controller_api_services_v1_host_catalog_service_proto_rawDesc = []byte{
	0x0a, 0x35, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x61, 0x70, 0x69,
	0x2f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x2f, 0x76, 0x31, 0x2f, 0x68, 0x6f, 0x73,
	0x74, 0x5f, 0x63, 0x61, 0x74, 0x61, 0x6c, 0x6f, 0x67, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63,
	0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x1a, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c,
	0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73,
	0x2e, 0x76, 0x31, 0x1a, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x2d, 0x67, 0x65, 0x6e, 0x2d,
	0x6f, 0x70, 0x65, 0x6e, 0x61, 0x70, 0x69, 0x76, 0x32, 0x2f, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e,
	0x73, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x1a, 0x1c, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f,
	0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x1a, 0x20, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62,
	0x75, 0x66, 0x2f, 0x66, 0x69, 0x65, 0x6c, 0x64, 0x5f, 0x6d, 0x61, 0x73, 0x6b, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x1a, 0x3b, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f,
	0x61, 0x70, 0x69, 0x2f, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2f, 0x68, 0x6f,
	0x73, 0x74, 0x63, 0x61, 0x74, 0x61, 0x6c, 0x6f, 0x67, 0x73, 0x2f, 0x76, 0x31, 0x2f, 0x68, 0x6f,
	0x73, 0x74, 0x5f, 0x63, 0x61, 0x74, 0x61, 0x6c, 0x6f, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x1a, 0x2a, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x63, 0x75, 0x73,
	0x74, 0x6f, 0x6d, 0x5f, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x76, 0x31, 0x2f, 0x6f,
	0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x27, 0x0a, 0x15,
	0x47, 0x65, 0x74, 0x48, 0x6f, 0x73, 0x74, 0x43, 0x61, 0x74, 0x61, 0x6c, 0x6f, 0x67, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x02, 0x69, 0x64, 0x22, 0x63, 0x0a, 0x16, 0x47, 0x65, 0x74, 0x48, 0x6f, 0x73, 0x74,
	0x43, 0x61, 0x74, 0x61, 0x6c, 0x6f, 0x67, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12,
	0x49, 0x0a, 0x04, 0x69, 0x74, 0x65, 0x6d, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x35, 0x2e,
	0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x72,
	0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2e, 0x68, 0x6f, 0x73, 0x74, 0x63, 0x61, 0x74,
	0x61, 0x6c, 0x6f, 0x67, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x48, 0x6f, 0x73, 0x74, 0x43, 0x61, 0x74,
	0x61, 0x6c, 0x6f, 0x67, 0x52, 0x04, 0x69, 0x74, 0x65, 0x6d, 0x22, 0x6b, 0x0a, 0x17, 0x4c, 0x69,
	0x73, 0x74, 0x48, 0x6f, 0x73, 0x74, 0x43, 0x61, 0x74, 0x61, 0x6c, 0x6f, 0x67, 0x73, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x1a, 0x0a, 0x08, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x5f, 0x69,
	0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x5f, 0x69,
	0x64, 0x12, 0x1c, 0x0a, 0x09, 0x72, 0x65, 0x63, 0x75, 0x72, 0x73, 0x69, 0x76, 0x65, 0x18, 0x14,
	0x20, 0x01, 0x28, 0x08, 0x52, 0x09, 0x72, 0x65, 0x63, 0x75, 0x72, 0x73, 0x69, 0x76, 0x65, 0x12,
	0x16, 0x0a, 0x06, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x18, 0x1e, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x06, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x22, 0x67, 0x0a, 0x18, 0x4c, 0x69, 0x73, 0x74, 0x48,
	0x6f, 0x73, 0x74, 0x43, 0x61, 0x74, 0x61, 0x6c, 0x6f, 0x67, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x12, 0x4b, 0x0a, 0x05, 0x69, 0x74, 0x65, 0x6d, 0x73, 0x18, 0x01, 0x20, 0x03,
	0x28, 0x0b, 0x32, 0x35, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e,
	0x61, 0x70, 0x69, 0x2e, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2e, 0x68, 0x6f,
	0x73, 0x74, 0x63, 0x61, 0x74, 0x61, 0x6c, 0x6f, 0x67, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x48, 0x6f,
	0x73, 0x74, 0x43, 0x61, 0x74, 0x61, 0x6c, 0x6f, 0x67, 0x52, 0x05, 0x69, 0x74, 0x65, 0x6d, 0x73,
	0x22, 0x87, 0x01, 0x0a, 0x18, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x48, 0x6f, 0x73, 0x74, 0x43,
	0x61, 0x74, 0x61, 0x6c, 0x6f, 0x67, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x49, 0x0a,
	0x04, 0x69, 0x74, 0x65, 0x6d, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x35, 0x2e, 0x63, 0x6f,
	0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x72, 0x65, 0x73,
	0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2e, 0x68, 0x6f, 0x73, 0x74, 0x63, 0x61, 0x74, 0x61, 0x6c,
	0x6f, 0x67, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x48, 0x6f, 0x73, 0x74, 0x43, 0x61, 0x74, 0x61, 0x6c,
	0x6f, 0x67, 0x52, 0x04, 0x69, 0x74, 0x65, 0x6d, 0x12, 0x20, 0x0a, 0x0b, 0x70, 0x6c, 0x75, 0x67,
	0x69, 0x6e, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x70,
	0x6c, 0x75, 0x67, 0x69, 0x6e, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x22, 0x78, 0x0a, 0x19, 0x43, 0x72,
	0x65, 0x61, 0x74, 0x65, 0x48, 0x6f, 0x73, 0x74, 0x43, 0x61, 0x74, 0x61, 0x6c, 0x6f, 0x67, 0x52,
	0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x10, 0x0a, 0x03, 0x75, 0x72, 0x69, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x75, 0x72, 0x69, 0x12, 0x49, 0x0a, 0x04, 0x69, 0x74, 0x65,
	0x6d, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x35, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f,
	0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63,
	0x65, 0x73, 0x2e, 0x68, 0x6f, 0x73, 0x74, 0x63, 0x61, 0x74, 0x61, 0x6c, 0x6f, 0x67, 0x73, 0x2e,
	0x76, 0x31, 0x2e, 0x48, 0x6f, 0x73, 0x74, 0x43, 0x61, 0x74, 0x61, 0x6c, 0x6f, 0x67, 0x52, 0x04,
	0x69, 0x74, 0x65, 0x6d, 0x22, 0xb2, 0x01, 0x0a, 0x18, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x48,
	0x6f, 0x73, 0x74, 0x43, 0x61, 0x74, 0x61, 0x6c, 0x6f, 0x67, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69,
	0x64, 0x12, 0x49, 0x0a, 0x04, 0x69, 0x74, 0x65, 0x6d, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x35, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69,
	0x2e, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2e, 0x68, 0x6f, 0x73, 0x74, 0x63,
	0x61, 0x74, 0x61, 0x6c, 0x6f, 0x67, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x48, 0x6f, 0x73, 0x74, 0x43,
	0x61, 0x74, 0x61, 0x6c, 0x6f, 0x67, 0x52, 0x04, 0x69, 0x74, 0x65, 0x6d, 0x12, 0x3b, 0x0a, 0x0b,
	0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x5f, 0x6d, 0x61, 0x73, 0x6b, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x62, 0x75, 0x66, 0x2e, 0x46, 0x69, 0x65, 0x6c, 0x64, 0x4d, 0x61, 0x73, 0x6b, 0x52, 0x0a, 0x75,
	0x70, 0x64, 0x61, 0x74, 0x65, 0x4d, 0x61, 0x73, 0x6b, 0x22, 0x66, 0x0a, 0x19, 0x55, 0x70, 0x64,
	0x61, 0x74, 0x65, 0x48, 0x6f, 0x73, 0x74, 0x43, 0x61, 0x74, 0x61, 0x6c, 0x6f, 0x67, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x49, 0x0a, 0x04, 0x69, 0x74, 0x65, 0x6d, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x35, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65,
	0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2e,
	0x68, 0x6f, 0x73, 0x74, 0x63, 0x61, 0x74, 0x61, 0x6c, 0x6f, 0x67, 0x73, 0x2e, 0x76, 0x31, 0x2e,
	0x48, 0x6f, 0x73, 0x74, 0x43, 0x61, 0x74, 0x61, 0x6c, 0x6f, 0x67, 0x52, 0x04, 0x69, 0x74, 0x65,
	0x6d, 0x22, 0x2a, 0x0a, 0x18, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x48, 0x6f, 0x73, 0x74, 0x43,
	0x61, 0x74, 0x61, 0x6c, 0x6f, 0x67, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x0e, 0x0a,
	0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x22, 0x1b, 0x0a,
	0x19, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x48, 0x6f, 0x73, 0x74, 0x43, 0x61, 0x74, 0x61, 0x6c,
	0x6f, 0x67, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x32, 0xde, 0x07, 0x0a, 0x12, 0x48,
	0x6f, 0x73, 0x74, 0x43, 0x61, 0x74, 0x61, 0x6c, 0x6f, 0x67, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63,
	0x65, 0x12, 0xbd, 0x01, 0x0a, 0x0e, 0x47, 0x65, 0x74, 0x48, 0x6f, 0x73, 0x74, 0x43, 0x61, 0x74,
	0x61, 0x6c, 0x6f, 0x67, 0x12, 0x31, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65,
	0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x2e, 0x76,
	0x31, 0x2e, 0x47, 0x65, 0x74, 0x48, 0x6f, 0x73, 0x74, 0x43, 0x61, 0x74, 0x61, 0x6c, 0x6f, 0x67,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x32, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f,
	0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65,
	0x73, 0x2e, 0x76, 0x31, 0x2e, 0x47, 0x65, 0x74, 0x48, 0x6f, 0x73, 0x74, 0x43, 0x61, 0x74, 0x61,
	0x6c, 0x6f, 0x67, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x44, 0x92, 0x41, 0x1d,
	0x12, 0x1b, 0x47, 0x65, 0x74, 0x73, 0x20, 0x61, 0x20, 0x73, 0x69, 0x6e, 0x67, 0x6c, 0x65, 0x20,
	0x48, 0x6f, 0x73, 0x74, 0x20, 0x43, 0x61, 0x74, 0x61, 0x6c, 0x6f, 0x67, 0x2e, 0x82, 0xd3, 0xe4,
	0x93, 0x02, 0x1e, 0x12, 0x16, 0x2f, 0x76, 0x31, 0x2f, 0x68, 0x6f, 0x73, 0x74, 0x2d, 0x63, 0x61,
	0x74, 0x61, 0x6c, 0x6f, 0x67, 0x73, 0x2f, 0x7b, 0x69, 0x64, 0x7d, 0x62, 0x04, 0x69, 0x74, 0x65,
	0x6d, 0x12, 0xba, 0x01, 0x0a, 0x10, 0x4c, 0x69, 0x73, 0x74, 0x48, 0x6f, 0x73, 0x74, 0x43, 0x61,
	0x74, 0x61, 0x6c, 0x6f, 0x67, 0x73, 0x12, 0x33, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c,
	0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73,
	0x2e, 0x76, 0x31, 0x2e, 0x4c, 0x69, 0x73, 0x74, 0x48, 0x6f, 0x73, 0x74, 0x43, 0x61, 0x74, 0x61,
	0x6c, 0x6f, 0x67, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x34, 0x2e, 0x63, 0x6f,
	0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x73, 0x65, 0x72,
	0x76, 0x69, 0x63, 0x65, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x4c, 0x69, 0x73, 0x74, 0x48, 0x6f, 0x73,
	0x74, 0x43, 0x61, 0x74, 0x61, 0x6c, 0x6f, 0x67, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x22, 0x3b, 0x92, 0x41, 0x1f, 0x12, 0x1d, 0x47, 0x65, 0x74, 0x73, 0x20, 0x61, 0x20, 0x6c,
	0x69, 0x73, 0x74, 0x20, 0x6f, 0x66, 0x20, 0x48, 0x6f, 0x73, 0x74, 0x20, 0x43, 0x61, 0x74, 0x61,
	0x6c, 0x6f, 0x67, 0x73, 0x2e, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x13, 0x12, 0x11, 0x2f, 0x76, 0x31,
	0x2f, 0x68, 0x6f, 0x73, 0x74, 0x2d, 0x63, 0x61, 0x74, 0x61, 0x6c, 0x6f, 0x67, 0x73, 0x12, 0xc2,
	0x01, 0x0a, 0x11, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x48, 0x6f, 0x73, 0x74, 0x43, 0x61, 0x74,
	0x61, 0x6c, 0x6f, 0x67, 0x12, 0x34, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65,
	0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x2e, 0x76,
	0x31, 0x2e, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x48, 0x6f, 0x73, 0x74, 0x43, 0x61, 0x74, 0x61,
	0x6c, 0x6f, 0x67, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x35, 0x2e, 0x63, 0x6f, 0x6e,
	0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x73, 0x65, 0x72, 0x76,
	0x69, 0x63, 0x65, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x48, 0x6f,
	0x73, 0x74, 0x43, 0x61, 0x74, 0x61, 0x6c, 0x6f, 0x67, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x22, 0x40, 0x92, 0x41, 0x18, 0x12, 0x16, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x73, 0x20,
	0x61, 0x20, 0x48, 0x6f, 0x73, 0x74, 0x20, 0x43, 0x61, 0x74, 0x61, 0x6c, 0x6f, 0x67, 0x82, 0xd3,
	0xe4, 0x93, 0x02, 0x1f, 0x22, 0x11, 0x2f, 0x76, 0x31, 0x2f, 0x68, 0x6f, 0x73, 0x74, 0x2d, 0x63,
	0x61, 0x74, 0x61, 0x6c, 0x6f, 0x67, 0x73, 0x3a, 0x04, 0x69, 0x74, 0x65, 0x6d, 0x62, 0x04, 0x69,
	0x74, 0x65, 0x6d, 0x12, 0xc7, 0x01, 0x0a, 0x11, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x48, 0x6f,
	0x73, 0x74, 0x43, 0x61, 0x74, 0x61, 0x6c, 0x6f, 0x67, 0x12, 0x34, 0x2e, 0x63, 0x6f, 0x6e, 0x74,
	0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69,
	0x63, 0x65, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x48, 0x6f, 0x73,
	0x74, 0x43, 0x61, 0x74, 0x61, 0x6c, 0x6f, 0x67, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a,
	0x35, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69,
	0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x55, 0x70, 0x64,
	0x61, 0x74, 0x65, 0x48, 0x6f, 0x73, 0x74, 0x43, 0x61, 0x74, 0x61, 0x6c, 0x6f, 0x67, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x45, 0x92, 0x41, 0x18, 0x12, 0x16, 0x55, 0x70, 0x64,
	0x61, 0x74, 0x65, 0x73, 0x20, 0x61, 0x20, 0x48, 0x6f, 0x73, 0x74, 0x20, 0x43, 0x61, 0x74, 0x61,
	0x6c, 0x6f, 0x67, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x24, 0x32, 0x16, 0x2f, 0x76, 0x31, 0x2f, 0x68,
	0x6f, 0x73, 0x74, 0x2d, 0x63, 0x61, 0x74, 0x61, 0x6c, 0x6f, 0x67, 0x73, 0x2f, 0x7b, 0x69, 0x64,
	0x7d, 0x3a, 0x04, 0x69, 0x74, 0x65, 0x6d, 0x62, 0x04, 0x69, 0x74, 0x65, 0x6d, 0x12, 0xbb, 0x01,
	0x0a, 0x11, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x48, 0x6f, 0x73, 0x74, 0x43, 0x61, 0x74, 0x61,
	0x6c, 0x6f, 0x67, 0x12, 0x34, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72,
	0x2e, 0x61, 0x70, 0x69, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x2e, 0x76, 0x31,
	0x2e, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x48, 0x6f, 0x73, 0x74, 0x43, 0x61, 0x74, 0x61, 0x6c,
	0x6f, 0x67, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x35, 0x2e, 0x63, 0x6f, 0x6e, 0x74,
	0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69,
	0x63, 0x65, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x48, 0x6f, 0x73,
	0x74, 0x43, 0x61, 0x74, 0x61, 0x6c, 0x6f, 0x67, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x22, 0x39, 0x92, 0x41, 0x18, 0x12, 0x16, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x73, 0x20, 0x61,
	0x20, 0x48, 0x6f, 0x73, 0x74, 0x20, 0x43, 0x61, 0x74, 0x61, 0x6c, 0x6f, 0x67, 0x82, 0xd3, 0xe4,
	0x93, 0x02, 0x18, 0x2a, 0x16, 0x2f, 0x76, 0x31, 0x2f, 0x68, 0x6f, 0x73, 0x74, 0x2d, 0x63, 0x61,
	0x74, 0x61, 0x6c, 0x6f, 0x67, 0x73, 0x2f, 0x7b, 0x69, 0x64, 0x7d, 0x42, 0x55, 0x5a, 0x4b, 0x67,
	0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x68, 0x61, 0x73, 0x68, 0x69, 0x63,
	0x6f, 0x72, 0x70, 0x2f, 0x62, 0x6f, 0x75, 0x6e, 0x64, 0x61, 0x72, 0x79, 0x2f, 0x69, 0x6e, 0x74,
	0x65, 0x72, 0x6e, 0x61, 0x6c, 0x2f, 0x67, 0x65, 0x6e, 0x2f, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f,
	0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65,
	0x73, 0x3b, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0xa2, 0xe3, 0x29, 0x04, 0x68, 0x6f,
	0x73, 0x74, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_controller_api_services_v1_host_catalog_service_proto_rawDescOnce sync.Once
	file_controller_api_services_v1_host_catalog_service_proto_rawDescData = file_controller_api_services_v1_host_catalog_service_proto_rawDesc
)

func file_controller_api_services_v1_host_catalog_service_proto_rawDescGZIP() []byte {
	file_controller_api_services_v1_host_catalog_service_proto_rawDescOnce.Do(func() {
		file_controller_api_services_v1_host_catalog_service_proto_rawDescData = protoimpl.X.CompressGZIP(file_controller_api_services_v1_host_catalog_service_proto_rawDescData)
	})
	return file_controller_api_services_v1_host_catalog_service_proto_rawDescData
}

var file_controller_api_services_v1_host_catalog_service_proto_msgTypes = make([]protoimpl.MessageInfo, 10)
var file_controller_api_services_v1_host_catalog_service_proto_goTypes = []interface{}{
	(*GetHostCatalogRequest)(nil),     // 0: controller.api.services.v1.GetHostCatalogRequest
	(*GetHostCatalogResponse)(nil),    // 1: controller.api.services.v1.GetHostCatalogResponse
	(*ListHostCatalogsRequest)(nil),   // 2: controller.api.services.v1.ListHostCatalogsRequest
	(*ListHostCatalogsResponse)(nil),  // 3: controller.api.services.v1.ListHostCatalogsResponse
	(*CreateHostCatalogRequest)(nil),  // 4: controller.api.services.v1.CreateHostCatalogRequest
	(*CreateHostCatalogResponse)(nil), // 5: controller.api.services.v1.CreateHostCatalogResponse
	(*UpdateHostCatalogRequest)(nil),  // 6: controller.api.services.v1.UpdateHostCatalogRequest
	(*UpdateHostCatalogResponse)(nil), // 7: controller.api.services.v1.UpdateHostCatalogResponse
	(*DeleteHostCatalogRequest)(nil),  // 8: controller.api.services.v1.DeleteHostCatalogRequest
	(*DeleteHostCatalogResponse)(nil), // 9: controller.api.services.v1.DeleteHostCatalogResponse
	(*hostcatalogs.HostCatalog)(nil),  // 10: controller.api.resources.hostcatalogs.v1.HostCatalog
	(*fieldmaskpb.FieldMask)(nil),     // 11: google.protobuf.FieldMask
}
var file_controller_api_services_v1_host_catalog_service_proto_depIdxs = []int32{
	10, // 0: controller.api.services.v1.GetHostCatalogResponse.item:type_name -> controller.api.resources.hostcatalogs.v1.HostCatalog
	10, // 1: controller.api.services.v1.ListHostCatalogsResponse.items:type_name -> controller.api.resources.hostcatalogs.v1.HostCatalog
	10, // 2: controller.api.services.v1.CreateHostCatalogRequest.item:type_name -> controller.api.resources.hostcatalogs.v1.HostCatalog
	10, // 3: controller.api.services.v1.CreateHostCatalogResponse.item:type_name -> controller.api.resources.hostcatalogs.v1.HostCatalog
	10, // 4: controller.api.services.v1.UpdateHostCatalogRequest.item:type_name -> controller.api.resources.hostcatalogs.v1.HostCatalog
	11, // 5: controller.api.services.v1.UpdateHostCatalogRequest.update_mask:type_name -> google.protobuf.FieldMask
	10, // 6: controller.api.services.v1.UpdateHostCatalogResponse.item:type_name -> controller.api.resources.hostcatalogs.v1.HostCatalog
	0,  // 7: controller.api.services.v1.HostCatalogService.GetHostCatalog:input_type -> controller.api.services.v1.GetHostCatalogRequest
	2,  // 8: controller.api.services.v1.HostCatalogService.ListHostCatalogs:input_type -> controller.api.services.v1.ListHostCatalogsRequest
	4,  // 9: controller.api.services.v1.HostCatalogService.CreateHostCatalog:input_type -> controller.api.services.v1.CreateHostCatalogRequest
	6,  // 10: controller.api.services.v1.HostCatalogService.UpdateHostCatalog:input_type -> controller.api.services.v1.UpdateHostCatalogRequest
	8,  // 11: controller.api.services.v1.HostCatalogService.DeleteHostCatalog:input_type -> controller.api.services.v1.DeleteHostCatalogRequest
	1,  // 12: controller.api.services.v1.HostCatalogService.GetHostCatalog:output_type -> controller.api.services.v1.GetHostCatalogResponse
	3,  // 13: controller.api.services.v1.HostCatalogService.ListHostCatalogs:output_type -> controller.api.services.v1.ListHostCatalogsResponse
	5,  // 14: controller.api.services.v1.HostCatalogService.CreateHostCatalog:output_type -> controller.api.services.v1.CreateHostCatalogResponse
	7,  // 15: controller.api.services.v1.HostCatalogService.UpdateHostCatalog:output_type -> controller.api.services.v1.UpdateHostCatalogResponse
	9,  // 16: controller.api.services.v1.HostCatalogService.DeleteHostCatalog:output_type -> controller.api.services.v1.DeleteHostCatalogResponse
	12, // [12:17] is the sub-list for method output_type
	7,  // [7:12] is the sub-list for method input_type
	7,  // [7:7] is the sub-list for extension type_name
	7,  // [7:7] is the sub-list for extension extendee
	0,  // [0:7] is the sub-list for field type_name
}

func init() { file_controller_api_services_v1_host_catalog_service_proto_init() }
func file_controller_api_services_v1_host_catalog_service_proto_init() {
	if File_controller_api_services_v1_host_catalog_service_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_controller_api_services_v1_host_catalog_service_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetHostCatalogRequest); i {
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
		file_controller_api_services_v1_host_catalog_service_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetHostCatalogResponse); i {
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
		file_controller_api_services_v1_host_catalog_service_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ListHostCatalogsRequest); i {
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
		file_controller_api_services_v1_host_catalog_service_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ListHostCatalogsResponse); i {
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
		file_controller_api_services_v1_host_catalog_service_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CreateHostCatalogRequest); i {
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
		file_controller_api_services_v1_host_catalog_service_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CreateHostCatalogResponse); i {
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
		file_controller_api_services_v1_host_catalog_service_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UpdateHostCatalogRequest); i {
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
		file_controller_api_services_v1_host_catalog_service_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UpdateHostCatalogResponse); i {
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
		file_controller_api_services_v1_host_catalog_service_proto_msgTypes[8].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DeleteHostCatalogRequest); i {
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
		file_controller_api_services_v1_host_catalog_service_proto_msgTypes[9].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DeleteHostCatalogResponse); i {
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
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_controller_api_services_v1_host_catalog_service_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   10,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_controller_api_services_v1_host_catalog_service_proto_goTypes,
		DependencyIndexes: file_controller_api_services_v1_host_catalog_service_proto_depIdxs,
		MessageInfos:      file_controller_api_services_v1_host_catalog_service_proto_msgTypes,
	}.Build()
	File_controller_api_services_v1_host_catalog_service_proto = out.File
	file_controller_api_services_v1_host_catalog_service_proto_rawDesc = nil
	file_controller_api_services_v1_host_catalog_service_proto_goTypes = nil
	file_controller_api_services_v1_host_catalog_service_proto_depIdxs = nil
}
