// Generated by the protocol buffer compiler.  DO NOT EDIT!

#define INTERNAL_SUPPRESS_PROTOBUF_FIELD_DEPRECATION
#include "vlanstack.pb.h"

#include <algorithm>

#include <google/protobuf/stubs/once.h>
#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/wire_format_lite_inl.h>
#include <google/protobuf/descriptor.h>
#include <google/protobuf/reflection_ops.h>
#include <google/protobuf/wire_format.h>
// @@protoc_insertion_point(includes)

namespace OstProto {

namespace {

const ::google::protobuf::Descriptor* VlanStack_descriptor_ = NULL;
const ::google::protobuf::internal::GeneratedMessageReflection*
  VlanStack_reflection_ = NULL;

}  // namespace


void protobuf_AssignDesc_vlanstack_2eproto() {
  protobuf_AddDesc_vlanstack_2eproto();
  const ::google::protobuf::FileDescriptor* file =
    ::google::protobuf::DescriptorPool::generated_pool()->FindFileByName(
      "vlanstack.proto");
  GOOGLE_CHECK(file != NULL);
  VlanStack_descriptor_ = file->message_type(0);
  static const int VlanStack_offsets_[1] = {
  };
  VlanStack_reflection_ =
    new ::google::protobuf::internal::GeneratedMessageReflection(
      VlanStack_descriptor_,
      VlanStack::default_instance_,
      VlanStack_offsets_,
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(VlanStack, _has_bits_[0]),
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(VlanStack, _unknown_fields_),
      -1,
      ::google::protobuf::DescriptorPool::generated_pool(),
      ::google::protobuf::MessageFactory::generated_factory(),
      sizeof(VlanStack));
}

namespace {

GOOGLE_PROTOBUF_DECLARE_ONCE(protobuf_AssignDescriptors_once_);
inline void protobuf_AssignDescriptorsOnce() {
  ::google::protobuf::GoogleOnceInit(&protobuf_AssignDescriptors_once_,
                 &protobuf_AssignDesc_vlanstack_2eproto);
}

void protobuf_RegisterTypes(const ::std::string&) {
  protobuf_AssignDescriptorsOnce();
  ::google::protobuf::MessageFactory::InternalRegisterGeneratedMessage(
    VlanStack_descriptor_, &VlanStack::default_instance());
}

}  // namespace

void protobuf_ShutdownFile_vlanstack_2eproto() {
  delete VlanStack::default_instance_;
  delete VlanStack_reflection_;
}

void protobuf_AddDesc_vlanstack_2eproto() {
  static bool already_here = false;
  if (already_here) return;
  already_here = true;
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  ::OstProto::protobuf_AddDesc_protocol_2eproto();
  ::google::protobuf::DescriptorPool::InternalAddGeneratedFile(
    "\n\017vlanstack.proto\022\010OstProto\032\016protocol.pr"
    "oto\"\013\n\tVlanStack:;\n\tvlanStack\022\022.OstProto"
    ".Protocol\030\320\001 \001(\0132\023.OstProto.VlanStack", 117);
  ::google::protobuf::MessageFactory::InternalRegisterGeneratedFile(
    "vlanstack.proto", &protobuf_RegisterTypes);
  VlanStack::default_instance_ = new VlanStack();
  ::google::protobuf::internal::ExtensionSet::RegisterMessageExtension(
    &::OstProto::Protocol::default_instance(),
    208, 11, false, false,
    &::OstProto::VlanStack::default_instance());
  VlanStack::default_instance_->InitAsDefaultInstance();
  ::google::protobuf::internal::OnShutdown(&protobuf_ShutdownFile_vlanstack_2eproto);
}

// Force AddDescriptors() to be called at static initialization time.
struct StaticDescriptorInitializer_vlanstack_2eproto {
  StaticDescriptorInitializer_vlanstack_2eproto() {
    protobuf_AddDesc_vlanstack_2eproto();
  }
} static_descriptor_initializer_vlanstack_2eproto_;


// ===================================================================

#ifndef _MSC_VER
#endif  // !_MSC_VER

VlanStack::VlanStack()
  : ::google::protobuf::Message() {
  SharedCtor();
}

void VlanStack::InitAsDefaultInstance() {
}

VlanStack::VlanStack(const VlanStack& from)
  : ::google::protobuf::Message() {
  SharedCtor();
  MergeFrom(from);
}

void VlanStack::SharedCtor() {
  _cached_size_ = 0;
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
}

VlanStack::~VlanStack() {
  SharedDtor();
}

void VlanStack::SharedDtor() {
  if (this != default_instance_) {
  }
}

void VlanStack::SetCachedSize(int size) const {
  GOOGLE_SAFE_CONCURRENT_WRITES_BEGIN();
  _cached_size_ = size;
  GOOGLE_SAFE_CONCURRENT_WRITES_END();
}
const ::google::protobuf::Descriptor* VlanStack::descriptor() {
  protobuf_AssignDescriptorsOnce();
  return VlanStack_descriptor_;
}

const VlanStack& VlanStack::default_instance() {
  if (default_instance_ == NULL) protobuf_AddDesc_vlanstack_2eproto();  return *default_instance_;
}

VlanStack* VlanStack::default_instance_ = NULL;

VlanStack* VlanStack::New() const {
  return new VlanStack;
}

void VlanStack::Clear() {
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
  mutable_unknown_fields()->Clear();
}

bool VlanStack::MergePartialFromCodedStream(
    ::google::protobuf::io::CodedInputStream* input) {
#define DO_(EXPRESSION) if (!(EXPRESSION)) return false
  ::google::protobuf::uint32 tag;
  while ((tag = input->ReadTag()) != 0) {
    if (::google::protobuf::internal::WireFormatLite::GetTagWireType(tag) ==
        ::google::protobuf::internal::WireFormatLite::WIRETYPE_END_GROUP) {
      return true;
    }
    DO_(::google::protobuf::internal::WireFormat::SkipField(
          input, tag, mutable_unknown_fields()));
  }
  return true;
#undef DO_
}

void VlanStack::SerializeWithCachedSizes(
    ::google::protobuf::io::CodedOutputStream* output) const {
  if (!unknown_fields().empty()) {
    ::google::protobuf::internal::WireFormat::SerializeUnknownFields(
        unknown_fields(), output);
  }
}

::google::protobuf::uint8* VlanStack::SerializeWithCachedSizesToArray(
    ::google::protobuf::uint8* target) const {
  if (!unknown_fields().empty()) {
    target = ::google::protobuf::internal::WireFormat::SerializeUnknownFieldsToArray(
        unknown_fields(), target);
  }
  return target;
}

int VlanStack::ByteSize() const {
  int total_size = 0;
  
  if (!unknown_fields().empty()) {
    total_size +=
      ::google::protobuf::internal::WireFormat::ComputeUnknownFieldsSize(
        unknown_fields());
  }
  GOOGLE_SAFE_CONCURRENT_WRITES_BEGIN();
  _cached_size_ = total_size;
  GOOGLE_SAFE_CONCURRENT_WRITES_END();
  return total_size;
}

void VlanStack::MergeFrom(const ::google::protobuf::Message& from) {
  GOOGLE_CHECK_NE(&from, this);
  const VlanStack* source =
    ::google::protobuf::internal::dynamic_cast_if_available<const VlanStack*>(
      &from);
  if (source == NULL) {
    ::google::protobuf::internal::ReflectionOps::Merge(from, this);
  } else {
    MergeFrom(*source);
  }
}

void VlanStack::MergeFrom(const VlanStack& from) {
  GOOGLE_CHECK_NE(&from, this);
  mutable_unknown_fields()->MergeFrom(from.unknown_fields());
}

void VlanStack::CopyFrom(const ::google::protobuf::Message& from) {
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

void VlanStack::CopyFrom(const VlanStack& from) {
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool VlanStack::IsInitialized() const {
  
  return true;
}

void VlanStack::Swap(VlanStack* other) {
  if (other != this) {
    _unknown_fields_.Swap(&other->_unknown_fields_);
    std::swap(_cached_size_, other->_cached_size_);
  }
}

::google::protobuf::Metadata VlanStack::GetMetadata() const {
  protobuf_AssignDescriptorsOnce();
  ::google::protobuf::Metadata metadata;
  metadata.descriptor = VlanStack_descriptor_;
  metadata.reflection = VlanStack_reflection_;
  return metadata;
}

::google::protobuf::internal::ExtensionIdentifier< ::OstProto::Protocol,
    ::google::protobuf::internal::MessageTypeTraits< ::OstProto::VlanStack >, 11, false >
  vlanStack(kVlanStackFieldNumber, ::OstProto::VlanStack::default_instance());

// @@protoc_insertion_point(namespace_scope)

}  // namespace OstProto

// @@protoc_insertion_point(global_scope)
