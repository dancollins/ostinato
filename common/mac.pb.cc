// Generated by the protocol buffer compiler.  DO NOT EDIT!

#define INTERNAL_SUPPRESS_PROTOBUF_FIELD_DEPRECATION
#include "mac.pb.h"

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

const ::google::protobuf::Descriptor* Mac_descriptor_ = NULL;
const ::google::protobuf::internal::GeneratedMessageReflection*
  Mac_reflection_ = NULL;
const ::google::protobuf::EnumDescriptor* Mac_MacAddrMode_descriptor_ = NULL;

}  // namespace


void protobuf_AssignDesc_mac_2eproto() {
  protobuf_AddDesc_mac_2eproto();
  const ::google::protobuf::FileDescriptor* file =
    ::google::protobuf::DescriptorPool::generated_pool()->FindFileByName(
      "mac.proto");
  GOOGLE_CHECK(file != NULL);
  Mac_descriptor_ = file->message_type(0);
  static const int Mac_offsets_[8] = {
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(Mac, dst_mac_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(Mac, dst_mac_mode_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(Mac, dst_mac_count_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(Mac, dst_mac_step_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(Mac, src_mac_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(Mac, src_mac_mode_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(Mac, src_mac_count_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(Mac, src_mac_step_),
  };
  Mac_reflection_ =
    new ::google::protobuf::internal::GeneratedMessageReflection(
      Mac_descriptor_,
      Mac::default_instance_,
      Mac_offsets_,
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(Mac, _has_bits_[0]),
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(Mac, _unknown_fields_),
      -1,
      ::google::protobuf::DescriptorPool::generated_pool(),
      ::google::protobuf::MessageFactory::generated_factory(),
      sizeof(Mac));
  Mac_MacAddrMode_descriptor_ = Mac_descriptor_->enum_type(0);
}

namespace {

GOOGLE_PROTOBUF_DECLARE_ONCE(protobuf_AssignDescriptors_once_);
inline void protobuf_AssignDescriptorsOnce() {
  ::google::protobuf::GoogleOnceInit(&protobuf_AssignDescriptors_once_,
                 &protobuf_AssignDesc_mac_2eproto);
}

void protobuf_RegisterTypes(const ::std::string&) {
  protobuf_AssignDescriptorsOnce();
  ::google::protobuf::MessageFactory::InternalRegisterGeneratedMessage(
    Mac_descriptor_, &Mac::default_instance());
}

}  // namespace

void protobuf_ShutdownFile_mac_2eproto() {
  delete Mac::default_instance_;
  delete Mac_reflection_;
}

void protobuf_AddDesc_mac_2eproto() {
  static bool already_here = false;
  if (already_here) return;
  already_here = true;
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  ::OstProto::protobuf_AddDesc_protocol_2eproto();
  ::google::protobuf::DescriptorPool::InternalAddGeneratedFile(
    "\n\tmac.proto\022\010OstProto\032\016protocol.proto\"\304\002"
    "\n\003Mac\022\017\n\007dst_mac\030\001 \001(\004\022;\n\014dst_mac_mode\030\002"
    " \001(\0162\031.OstProto.Mac.MacAddrMode:\ne_mm_fi"
    "xed\022\031\n\rdst_mac_count\030\003 \001(\r:\00216\022\027\n\014dst_ma"
    "c_step\030\004 \001(\r:\0011\022\017\n\007src_mac\030\005 \001(\004\022;\n\014src_"
    "mac_mode\030\006 \001(\0162\031.OstProto.Mac.MacAddrMod"
    "e:\ne_mm_fixed\022\031\n\rsrc_mac_count\030\007 \001(\r:\00216"
    "\022\027\n\014src_mac_step\030\010 \001(\r:\0011\"9\n\013MacAddrMode"
    "\022\016\n\ne_mm_fixed\020\000\022\014\n\010e_mm_inc\020\001\022\014\n\010e_mm_d"
    "ec\020\002:.\n\003mac\022\022.OstProto.Protocol\030d \001(\0132\r."
    "OstProto.Mac", 412);
  ::google::protobuf::MessageFactory::InternalRegisterGeneratedFile(
    "mac.proto", &protobuf_RegisterTypes);
  Mac::default_instance_ = new Mac();
  ::google::protobuf::internal::ExtensionSet::RegisterMessageExtension(
    &::OstProto::Protocol::default_instance(),
    100, 11, false, false,
    &::OstProto::Mac::default_instance());
  Mac::default_instance_->InitAsDefaultInstance();
  ::google::protobuf::internal::OnShutdown(&protobuf_ShutdownFile_mac_2eproto);
}

// Force AddDescriptors() to be called at static initialization time.
struct StaticDescriptorInitializer_mac_2eproto {
  StaticDescriptorInitializer_mac_2eproto() {
    protobuf_AddDesc_mac_2eproto();
  }
} static_descriptor_initializer_mac_2eproto_;


// ===================================================================

const ::google::protobuf::EnumDescriptor* Mac_MacAddrMode_descriptor() {
  protobuf_AssignDescriptorsOnce();
  return Mac_MacAddrMode_descriptor_;
}
bool Mac_MacAddrMode_IsValid(int value) {
  switch(value) {
    case 0:
    case 1:
    case 2:
      return true;
    default:
      return false;
  }
}

#ifndef _MSC_VER
const Mac_MacAddrMode Mac::e_mm_fixed;
const Mac_MacAddrMode Mac::e_mm_inc;
const Mac_MacAddrMode Mac::e_mm_dec;
const Mac_MacAddrMode Mac::MacAddrMode_MIN;
const Mac_MacAddrMode Mac::MacAddrMode_MAX;
const int Mac::MacAddrMode_ARRAYSIZE;
#endif  // _MSC_VER
#ifndef _MSC_VER
const int Mac::kDstMacFieldNumber;
const int Mac::kDstMacModeFieldNumber;
const int Mac::kDstMacCountFieldNumber;
const int Mac::kDstMacStepFieldNumber;
const int Mac::kSrcMacFieldNumber;
const int Mac::kSrcMacModeFieldNumber;
const int Mac::kSrcMacCountFieldNumber;
const int Mac::kSrcMacStepFieldNumber;
#endif  // !_MSC_VER

Mac::Mac()
  : ::google::protobuf::Message() {
  SharedCtor();
}

void Mac::InitAsDefaultInstance() {
}

Mac::Mac(const Mac& from)
  : ::google::protobuf::Message() {
  SharedCtor();
  MergeFrom(from);
}

void Mac::SharedCtor() {
  _cached_size_ = 0;
  dst_mac_ = GOOGLE_ULONGLONG(0);
  dst_mac_mode_ = 0;
  dst_mac_count_ = 16u;
  dst_mac_step_ = 1u;
  src_mac_ = GOOGLE_ULONGLONG(0);
  src_mac_mode_ = 0;
  src_mac_count_ = 16u;
  src_mac_step_ = 1u;
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
}

Mac::~Mac() {
  SharedDtor();
}

void Mac::SharedDtor() {
  if (this != default_instance_) {
  }
}

void Mac::SetCachedSize(int size) const {
  GOOGLE_SAFE_CONCURRENT_WRITES_BEGIN();
  _cached_size_ = size;
  GOOGLE_SAFE_CONCURRENT_WRITES_END();
}
const ::google::protobuf::Descriptor* Mac::descriptor() {
  protobuf_AssignDescriptorsOnce();
  return Mac_descriptor_;
}

const Mac& Mac::default_instance() {
  if (default_instance_ == NULL) protobuf_AddDesc_mac_2eproto();  return *default_instance_;
}

Mac* Mac::default_instance_ = NULL;

Mac* Mac::New() const {
  return new Mac;
}

void Mac::Clear() {
  if (_has_bits_[0 / 32] & (0xffu << (0 % 32))) {
    dst_mac_ = GOOGLE_ULONGLONG(0);
    dst_mac_mode_ = 0;
    dst_mac_count_ = 16u;
    dst_mac_step_ = 1u;
    src_mac_ = GOOGLE_ULONGLONG(0);
    src_mac_mode_ = 0;
    src_mac_count_ = 16u;
    src_mac_step_ = 1u;
  }
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
  mutable_unknown_fields()->Clear();
}

bool Mac::MergePartialFromCodedStream(
    ::google::protobuf::io::CodedInputStream* input) {
#define DO_(EXPRESSION) if (!(EXPRESSION)) return false
  ::google::protobuf::uint32 tag;
  while ((tag = input->ReadTag()) != 0) {
    switch (::google::protobuf::internal::WireFormatLite::GetTagFieldNumber(tag)) {
      // optional uint64 dst_mac = 1;
      case 1: {
        if (::google::protobuf::internal::WireFormatLite::GetTagWireType(tag) ==
            ::google::protobuf::internal::WireFormatLite::WIRETYPE_VARINT) {
          DO_((::google::protobuf::internal::WireFormatLite::ReadPrimitive<
                   ::google::protobuf::uint64, ::google::protobuf::internal::WireFormatLite::TYPE_UINT64>(
                 input, &dst_mac_)));
          set_has_dst_mac();
        } else {
          goto handle_uninterpreted;
        }
        if (input->ExpectTag(16)) goto parse_dst_mac_mode;
        break;
      }
      
      // optional .OstProto.Mac.MacAddrMode dst_mac_mode = 2 [default = e_mm_fixed];
      case 2: {
        if (::google::protobuf::internal::WireFormatLite::GetTagWireType(tag) ==
            ::google::protobuf::internal::WireFormatLite::WIRETYPE_VARINT) {
         parse_dst_mac_mode:
          int value;
          DO_((::google::protobuf::internal::WireFormatLite::ReadPrimitive<
                   int, ::google::protobuf::internal::WireFormatLite::TYPE_ENUM>(
                 input, &value)));
          if (::OstProto::Mac_MacAddrMode_IsValid(value)) {
            set_dst_mac_mode(static_cast< ::OstProto::Mac_MacAddrMode >(value));
          } else {
            mutable_unknown_fields()->AddVarint(2, value);
          }
        } else {
          goto handle_uninterpreted;
        }
        if (input->ExpectTag(24)) goto parse_dst_mac_count;
        break;
      }
      
      // optional uint32 dst_mac_count = 3 [default = 16];
      case 3: {
        if (::google::protobuf::internal::WireFormatLite::GetTagWireType(tag) ==
            ::google::protobuf::internal::WireFormatLite::WIRETYPE_VARINT) {
         parse_dst_mac_count:
          DO_((::google::protobuf::internal::WireFormatLite::ReadPrimitive<
                   ::google::protobuf::uint32, ::google::protobuf::internal::WireFormatLite::TYPE_UINT32>(
                 input, &dst_mac_count_)));
          set_has_dst_mac_count();
        } else {
          goto handle_uninterpreted;
        }
        if (input->ExpectTag(32)) goto parse_dst_mac_step;
        break;
      }
      
      // optional uint32 dst_mac_step = 4 [default = 1];
      case 4: {
        if (::google::protobuf::internal::WireFormatLite::GetTagWireType(tag) ==
            ::google::protobuf::internal::WireFormatLite::WIRETYPE_VARINT) {
         parse_dst_mac_step:
          DO_((::google::protobuf::internal::WireFormatLite::ReadPrimitive<
                   ::google::protobuf::uint32, ::google::protobuf::internal::WireFormatLite::TYPE_UINT32>(
                 input, &dst_mac_step_)));
          set_has_dst_mac_step();
        } else {
          goto handle_uninterpreted;
        }
        if (input->ExpectTag(40)) goto parse_src_mac;
        break;
      }
      
      // optional uint64 src_mac = 5;
      case 5: {
        if (::google::protobuf::internal::WireFormatLite::GetTagWireType(tag) ==
            ::google::protobuf::internal::WireFormatLite::WIRETYPE_VARINT) {
         parse_src_mac:
          DO_((::google::protobuf::internal::WireFormatLite::ReadPrimitive<
                   ::google::protobuf::uint64, ::google::protobuf::internal::WireFormatLite::TYPE_UINT64>(
                 input, &src_mac_)));
          set_has_src_mac();
        } else {
          goto handle_uninterpreted;
        }
        if (input->ExpectTag(48)) goto parse_src_mac_mode;
        break;
      }
      
      // optional .OstProto.Mac.MacAddrMode src_mac_mode = 6 [default = e_mm_fixed];
      case 6: {
        if (::google::protobuf::internal::WireFormatLite::GetTagWireType(tag) ==
            ::google::protobuf::internal::WireFormatLite::WIRETYPE_VARINT) {
         parse_src_mac_mode:
          int value;
          DO_((::google::protobuf::internal::WireFormatLite::ReadPrimitive<
                   int, ::google::protobuf::internal::WireFormatLite::TYPE_ENUM>(
                 input, &value)));
          if (::OstProto::Mac_MacAddrMode_IsValid(value)) {
            set_src_mac_mode(static_cast< ::OstProto::Mac_MacAddrMode >(value));
          } else {
            mutable_unknown_fields()->AddVarint(6, value);
          }
        } else {
          goto handle_uninterpreted;
        }
        if (input->ExpectTag(56)) goto parse_src_mac_count;
        break;
      }
      
      // optional uint32 src_mac_count = 7 [default = 16];
      case 7: {
        if (::google::protobuf::internal::WireFormatLite::GetTagWireType(tag) ==
            ::google::protobuf::internal::WireFormatLite::WIRETYPE_VARINT) {
         parse_src_mac_count:
          DO_((::google::protobuf::internal::WireFormatLite::ReadPrimitive<
                   ::google::protobuf::uint32, ::google::protobuf::internal::WireFormatLite::TYPE_UINT32>(
                 input, &src_mac_count_)));
          set_has_src_mac_count();
        } else {
          goto handle_uninterpreted;
        }
        if (input->ExpectTag(64)) goto parse_src_mac_step;
        break;
      }
      
      // optional uint32 src_mac_step = 8 [default = 1];
      case 8: {
        if (::google::protobuf::internal::WireFormatLite::GetTagWireType(tag) ==
            ::google::protobuf::internal::WireFormatLite::WIRETYPE_VARINT) {
         parse_src_mac_step:
          DO_((::google::protobuf::internal::WireFormatLite::ReadPrimitive<
                   ::google::protobuf::uint32, ::google::protobuf::internal::WireFormatLite::TYPE_UINT32>(
                 input, &src_mac_step_)));
          set_has_src_mac_step();
        } else {
          goto handle_uninterpreted;
        }
        if (input->ExpectAtEnd()) return true;
        break;
      }
      
      default: {
      handle_uninterpreted:
        if (::google::protobuf::internal::WireFormatLite::GetTagWireType(tag) ==
            ::google::protobuf::internal::WireFormatLite::WIRETYPE_END_GROUP) {
          return true;
        }
        DO_(::google::protobuf::internal::WireFormat::SkipField(
              input, tag, mutable_unknown_fields()));
        break;
      }
    }
  }
  return true;
#undef DO_
}

void Mac::SerializeWithCachedSizes(
    ::google::protobuf::io::CodedOutputStream* output) const {
  // optional uint64 dst_mac = 1;
  if (has_dst_mac()) {
    ::google::protobuf::internal::WireFormatLite::WriteUInt64(1, this->dst_mac(), output);
  }
  
  // optional .OstProto.Mac.MacAddrMode dst_mac_mode = 2 [default = e_mm_fixed];
  if (has_dst_mac_mode()) {
    ::google::protobuf::internal::WireFormatLite::WriteEnum(
      2, this->dst_mac_mode(), output);
  }
  
  // optional uint32 dst_mac_count = 3 [default = 16];
  if (has_dst_mac_count()) {
    ::google::protobuf::internal::WireFormatLite::WriteUInt32(3, this->dst_mac_count(), output);
  }
  
  // optional uint32 dst_mac_step = 4 [default = 1];
  if (has_dst_mac_step()) {
    ::google::protobuf::internal::WireFormatLite::WriteUInt32(4, this->dst_mac_step(), output);
  }
  
  // optional uint64 src_mac = 5;
  if (has_src_mac()) {
    ::google::protobuf::internal::WireFormatLite::WriteUInt64(5, this->src_mac(), output);
  }
  
  // optional .OstProto.Mac.MacAddrMode src_mac_mode = 6 [default = e_mm_fixed];
  if (has_src_mac_mode()) {
    ::google::protobuf::internal::WireFormatLite::WriteEnum(
      6, this->src_mac_mode(), output);
  }
  
  // optional uint32 src_mac_count = 7 [default = 16];
  if (has_src_mac_count()) {
    ::google::protobuf::internal::WireFormatLite::WriteUInt32(7, this->src_mac_count(), output);
  }
  
  // optional uint32 src_mac_step = 8 [default = 1];
  if (has_src_mac_step()) {
    ::google::protobuf::internal::WireFormatLite::WriteUInt32(8, this->src_mac_step(), output);
  }
  
  if (!unknown_fields().empty()) {
    ::google::protobuf::internal::WireFormat::SerializeUnknownFields(
        unknown_fields(), output);
  }
}

::google::protobuf::uint8* Mac::SerializeWithCachedSizesToArray(
    ::google::protobuf::uint8* target) const {
  // optional uint64 dst_mac = 1;
  if (has_dst_mac()) {
    target = ::google::protobuf::internal::WireFormatLite::WriteUInt64ToArray(1, this->dst_mac(), target);
  }
  
  // optional .OstProto.Mac.MacAddrMode dst_mac_mode = 2 [default = e_mm_fixed];
  if (has_dst_mac_mode()) {
    target = ::google::protobuf::internal::WireFormatLite::WriteEnumToArray(
      2, this->dst_mac_mode(), target);
  }
  
  // optional uint32 dst_mac_count = 3 [default = 16];
  if (has_dst_mac_count()) {
    target = ::google::protobuf::internal::WireFormatLite::WriteUInt32ToArray(3, this->dst_mac_count(), target);
  }
  
  // optional uint32 dst_mac_step = 4 [default = 1];
  if (has_dst_mac_step()) {
    target = ::google::protobuf::internal::WireFormatLite::WriteUInt32ToArray(4, this->dst_mac_step(), target);
  }
  
  // optional uint64 src_mac = 5;
  if (has_src_mac()) {
    target = ::google::protobuf::internal::WireFormatLite::WriteUInt64ToArray(5, this->src_mac(), target);
  }
  
  // optional .OstProto.Mac.MacAddrMode src_mac_mode = 6 [default = e_mm_fixed];
  if (has_src_mac_mode()) {
    target = ::google::protobuf::internal::WireFormatLite::WriteEnumToArray(
      6, this->src_mac_mode(), target);
  }
  
  // optional uint32 src_mac_count = 7 [default = 16];
  if (has_src_mac_count()) {
    target = ::google::protobuf::internal::WireFormatLite::WriteUInt32ToArray(7, this->src_mac_count(), target);
  }
  
  // optional uint32 src_mac_step = 8 [default = 1];
  if (has_src_mac_step()) {
    target = ::google::protobuf::internal::WireFormatLite::WriteUInt32ToArray(8, this->src_mac_step(), target);
  }
  
  if (!unknown_fields().empty()) {
    target = ::google::protobuf::internal::WireFormat::SerializeUnknownFieldsToArray(
        unknown_fields(), target);
  }
  return target;
}

int Mac::ByteSize() const {
  int total_size = 0;
  
  if (_has_bits_[0 / 32] & (0xffu << (0 % 32))) {
    // optional uint64 dst_mac = 1;
    if (has_dst_mac()) {
      total_size += 1 +
        ::google::protobuf::internal::WireFormatLite::UInt64Size(
          this->dst_mac());
    }
    
    // optional .OstProto.Mac.MacAddrMode dst_mac_mode = 2 [default = e_mm_fixed];
    if (has_dst_mac_mode()) {
      total_size += 1 +
        ::google::protobuf::internal::WireFormatLite::EnumSize(this->dst_mac_mode());
    }
    
    // optional uint32 dst_mac_count = 3 [default = 16];
    if (has_dst_mac_count()) {
      total_size += 1 +
        ::google::protobuf::internal::WireFormatLite::UInt32Size(
          this->dst_mac_count());
    }
    
    // optional uint32 dst_mac_step = 4 [default = 1];
    if (has_dst_mac_step()) {
      total_size += 1 +
        ::google::protobuf::internal::WireFormatLite::UInt32Size(
          this->dst_mac_step());
    }
    
    // optional uint64 src_mac = 5;
    if (has_src_mac()) {
      total_size += 1 +
        ::google::protobuf::internal::WireFormatLite::UInt64Size(
          this->src_mac());
    }
    
    // optional .OstProto.Mac.MacAddrMode src_mac_mode = 6 [default = e_mm_fixed];
    if (has_src_mac_mode()) {
      total_size += 1 +
        ::google::protobuf::internal::WireFormatLite::EnumSize(this->src_mac_mode());
    }
    
    // optional uint32 src_mac_count = 7 [default = 16];
    if (has_src_mac_count()) {
      total_size += 1 +
        ::google::protobuf::internal::WireFormatLite::UInt32Size(
          this->src_mac_count());
    }
    
    // optional uint32 src_mac_step = 8 [default = 1];
    if (has_src_mac_step()) {
      total_size += 1 +
        ::google::protobuf::internal::WireFormatLite::UInt32Size(
          this->src_mac_step());
    }
    
  }
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

void Mac::MergeFrom(const ::google::protobuf::Message& from) {
  GOOGLE_CHECK_NE(&from, this);
  const Mac* source =
    ::google::protobuf::internal::dynamic_cast_if_available<const Mac*>(
      &from);
  if (source == NULL) {
    ::google::protobuf::internal::ReflectionOps::Merge(from, this);
  } else {
    MergeFrom(*source);
  }
}

void Mac::MergeFrom(const Mac& from) {
  GOOGLE_CHECK_NE(&from, this);
  if (from._has_bits_[0 / 32] & (0xffu << (0 % 32))) {
    if (from.has_dst_mac()) {
      set_dst_mac(from.dst_mac());
    }
    if (from.has_dst_mac_mode()) {
      set_dst_mac_mode(from.dst_mac_mode());
    }
    if (from.has_dst_mac_count()) {
      set_dst_mac_count(from.dst_mac_count());
    }
    if (from.has_dst_mac_step()) {
      set_dst_mac_step(from.dst_mac_step());
    }
    if (from.has_src_mac()) {
      set_src_mac(from.src_mac());
    }
    if (from.has_src_mac_mode()) {
      set_src_mac_mode(from.src_mac_mode());
    }
    if (from.has_src_mac_count()) {
      set_src_mac_count(from.src_mac_count());
    }
    if (from.has_src_mac_step()) {
      set_src_mac_step(from.src_mac_step());
    }
  }
  mutable_unknown_fields()->MergeFrom(from.unknown_fields());
}

void Mac::CopyFrom(const ::google::protobuf::Message& from) {
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

void Mac::CopyFrom(const Mac& from) {
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool Mac::IsInitialized() const {
  
  return true;
}

void Mac::Swap(Mac* other) {
  if (other != this) {
    std::swap(dst_mac_, other->dst_mac_);
    std::swap(dst_mac_mode_, other->dst_mac_mode_);
    std::swap(dst_mac_count_, other->dst_mac_count_);
    std::swap(dst_mac_step_, other->dst_mac_step_);
    std::swap(src_mac_, other->src_mac_);
    std::swap(src_mac_mode_, other->src_mac_mode_);
    std::swap(src_mac_count_, other->src_mac_count_);
    std::swap(src_mac_step_, other->src_mac_step_);
    std::swap(_has_bits_[0], other->_has_bits_[0]);
    _unknown_fields_.Swap(&other->_unknown_fields_);
    std::swap(_cached_size_, other->_cached_size_);
  }
}

::google::protobuf::Metadata Mac::GetMetadata() const {
  protobuf_AssignDescriptorsOnce();
  ::google::protobuf::Metadata metadata;
  metadata.descriptor = Mac_descriptor_;
  metadata.reflection = Mac_reflection_;
  return metadata;
}

::google::protobuf::internal::ExtensionIdentifier< ::OstProto::Protocol,
    ::google::protobuf::internal::MessageTypeTraits< ::OstProto::Mac >, 11, false >
  mac(kMacFieldNumber, ::OstProto::Mac::default_instance());

// @@protoc_insertion_point(namespace_scope)

}  // namespace OstProto

// @@protoc_insertion_point(global_scope)
