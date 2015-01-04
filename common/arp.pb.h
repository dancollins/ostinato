// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: arp.proto

#ifndef PROTOBUF_arp_2eproto__INCLUDED
#define PROTOBUF_arp_2eproto__INCLUDED

#include <string>

#include <google/protobuf/stubs/common.h>

#if GOOGLE_PROTOBUF_VERSION < 2004000
#error This file was generated by a newer version of protoc which is
#error incompatible with your Protocol Buffer headers.  Please update
#error your headers.
#endif
#if 2004001 < GOOGLE_PROTOBUF_MIN_PROTOC_VERSION
#error This file was generated by an older version of protoc which is
#error incompatible with your Protocol Buffer headers.  Please
#error regenerate this file with a newer version of protoc.
#endif

#include <google/protobuf/generated_message_util.h>
#include <google/protobuf/repeated_field.h>
#include <google/protobuf/extension_set.h>
#include <google/protobuf/generated_message_reflection.h>
#include "protocol.pb.h"
// @@protoc_insertion_point(includes)

namespace OstProto {

// Internal implementation detail -- do not call these.
void  protobuf_AddDesc_arp_2eproto();
void protobuf_AssignDesc_arp_2eproto();
void protobuf_ShutdownFile_arp_2eproto();

class Arp;

enum Arp_HwAddrMode {
  Arp_HwAddrMode_kFixed = 0,
  Arp_HwAddrMode_kIncrement = 1,
  Arp_HwAddrMode_kDecrement = 2
};
bool Arp_HwAddrMode_IsValid(int value);
const Arp_HwAddrMode Arp_HwAddrMode_HwAddrMode_MIN = Arp_HwAddrMode_kFixed;
const Arp_HwAddrMode Arp_HwAddrMode_HwAddrMode_MAX = Arp_HwAddrMode_kDecrement;
const int Arp_HwAddrMode_HwAddrMode_ARRAYSIZE = Arp_HwAddrMode_HwAddrMode_MAX + 1;

const ::google::protobuf::EnumDescriptor* Arp_HwAddrMode_descriptor();
inline const ::std::string& Arp_HwAddrMode_Name(Arp_HwAddrMode value) {
  return ::google::protobuf::internal::NameOfEnum(
    Arp_HwAddrMode_descriptor(), value);
}
inline bool Arp_HwAddrMode_Parse(
    const ::std::string& name, Arp_HwAddrMode* value) {
  return ::google::protobuf::internal::ParseNamedEnum<Arp_HwAddrMode>(
    Arp_HwAddrMode_descriptor(), name, value);
}
enum Arp_ProtoAddrMode {
  Arp_ProtoAddrMode_kFixedHost = 0,
  Arp_ProtoAddrMode_kIncrementHost = 1,
  Arp_ProtoAddrMode_kDecrementHost = 2,
  Arp_ProtoAddrMode_kRandomHost = 3
};
bool Arp_ProtoAddrMode_IsValid(int value);
const Arp_ProtoAddrMode Arp_ProtoAddrMode_ProtoAddrMode_MIN = Arp_ProtoAddrMode_kFixedHost;
const Arp_ProtoAddrMode Arp_ProtoAddrMode_ProtoAddrMode_MAX = Arp_ProtoAddrMode_kRandomHost;
const int Arp_ProtoAddrMode_ProtoAddrMode_ARRAYSIZE = Arp_ProtoAddrMode_ProtoAddrMode_MAX + 1;

const ::google::protobuf::EnumDescriptor* Arp_ProtoAddrMode_descriptor();
inline const ::std::string& Arp_ProtoAddrMode_Name(Arp_ProtoAddrMode value) {
  return ::google::protobuf::internal::NameOfEnum(
    Arp_ProtoAddrMode_descriptor(), value);
}
inline bool Arp_ProtoAddrMode_Parse(
    const ::std::string& name, Arp_ProtoAddrMode* value) {
  return ::google::protobuf::internal::ParseNamedEnum<Arp_ProtoAddrMode>(
    Arp_ProtoAddrMode_descriptor(), name, value);
}
// ===================================================================

class Arp : public ::google::protobuf::Message {
 public:
  Arp();
  virtual ~Arp();
  
  Arp(const Arp& from);
  
  inline Arp& operator=(const Arp& from) {
    CopyFrom(from);
    return *this;
  }
  
  inline const ::google::protobuf::UnknownFieldSet& unknown_fields() const {
    return _unknown_fields_;
  }
  
  inline ::google::protobuf::UnknownFieldSet* mutable_unknown_fields() {
    return &_unknown_fields_;
  }
  
  static const ::google::protobuf::Descriptor* descriptor();
  static const Arp& default_instance();
  
  void Swap(Arp* other);
  
  // implements Message ----------------------------------------------
  
  Arp* New() const;
  void CopyFrom(const ::google::protobuf::Message& from);
  void MergeFrom(const ::google::protobuf::Message& from);
  void CopyFrom(const Arp& from);
  void MergeFrom(const Arp& from);
  void Clear();
  bool IsInitialized() const;
  
  int ByteSize() const;
  bool MergePartialFromCodedStream(
      ::google::protobuf::io::CodedInputStream* input);
  void SerializeWithCachedSizes(
      ::google::protobuf::io::CodedOutputStream* output) const;
  ::google::protobuf::uint8* SerializeWithCachedSizesToArray(::google::protobuf::uint8* output) const;
  int GetCachedSize() const { return _cached_size_; }
  private:
  void SharedCtor();
  void SharedDtor();
  void SetCachedSize(int size) const;
  public:
  
  ::google::protobuf::Metadata GetMetadata() const;
  
  // nested types ----------------------------------------------------
  
  typedef Arp_HwAddrMode HwAddrMode;
  static const HwAddrMode kFixed = Arp_HwAddrMode_kFixed;
  static const HwAddrMode kIncrement = Arp_HwAddrMode_kIncrement;
  static const HwAddrMode kDecrement = Arp_HwAddrMode_kDecrement;
  static inline bool HwAddrMode_IsValid(int value) {
    return Arp_HwAddrMode_IsValid(value);
  }
  static const HwAddrMode HwAddrMode_MIN =
    Arp_HwAddrMode_HwAddrMode_MIN;
  static const HwAddrMode HwAddrMode_MAX =
    Arp_HwAddrMode_HwAddrMode_MAX;
  static const int HwAddrMode_ARRAYSIZE =
    Arp_HwAddrMode_HwAddrMode_ARRAYSIZE;
  static inline const ::google::protobuf::EnumDescriptor*
  HwAddrMode_descriptor() {
    return Arp_HwAddrMode_descriptor();
  }
  static inline const ::std::string& HwAddrMode_Name(HwAddrMode value) {
    return Arp_HwAddrMode_Name(value);
  }
  static inline bool HwAddrMode_Parse(const ::std::string& name,
      HwAddrMode* value) {
    return Arp_HwAddrMode_Parse(name, value);
  }
  
  typedef Arp_ProtoAddrMode ProtoAddrMode;
  static const ProtoAddrMode kFixedHost = Arp_ProtoAddrMode_kFixedHost;
  static const ProtoAddrMode kIncrementHost = Arp_ProtoAddrMode_kIncrementHost;
  static const ProtoAddrMode kDecrementHost = Arp_ProtoAddrMode_kDecrementHost;
  static const ProtoAddrMode kRandomHost = Arp_ProtoAddrMode_kRandomHost;
  static inline bool ProtoAddrMode_IsValid(int value) {
    return Arp_ProtoAddrMode_IsValid(value);
  }
  static const ProtoAddrMode ProtoAddrMode_MIN =
    Arp_ProtoAddrMode_ProtoAddrMode_MIN;
  static const ProtoAddrMode ProtoAddrMode_MAX =
    Arp_ProtoAddrMode_ProtoAddrMode_MAX;
  static const int ProtoAddrMode_ARRAYSIZE =
    Arp_ProtoAddrMode_ProtoAddrMode_ARRAYSIZE;
  static inline const ::google::protobuf::EnumDescriptor*
  ProtoAddrMode_descriptor() {
    return Arp_ProtoAddrMode_descriptor();
  }
  static inline const ::std::string& ProtoAddrMode_Name(ProtoAddrMode value) {
    return Arp_ProtoAddrMode_Name(value);
  }
  static inline bool ProtoAddrMode_Parse(const ::std::string& name,
      ProtoAddrMode* value) {
    return Arp_ProtoAddrMode_Parse(name, value);
  }
  
  // accessors -------------------------------------------------------
  
  // optional uint32 hw_type = 1 [default = 1];
  inline bool has_hw_type() const;
  inline void clear_hw_type();
  static const int kHwTypeFieldNumber = 1;
  inline ::google::protobuf::uint32 hw_type() const;
  inline void set_hw_type(::google::protobuf::uint32 value);
  
  // optional uint32 proto_type = 2 [default = 2048];
  inline bool has_proto_type() const;
  inline void clear_proto_type();
  static const int kProtoTypeFieldNumber = 2;
  inline ::google::protobuf::uint32 proto_type() const;
  inline void set_proto_type(::google::protobuf::uint32 value);
  
  // optional uint32 hw_addr_len = 3 [default = 6];
  inline bool has_hw_addr_len() const;
  inline void clear_hw_addr_len();
  static const int kHwAddrLenFieldNumber = 3;
  inline ::google::protobuf::uint32 hw_addr_len() const;
  inline void set_hw_addr_len(::google::protobuf::uint32 value);
  
  // optional uint32 proto_addr_len = 4 [default = 4];
  inline bool has_proto_addr_len() const;
  inline void clear_proto_addr_len();
  static const int kProtoAddrLenFieldNumber = 4;
  inline ::google::protobuf::uint32 proto_addr_len() const;
  inline void set_proto_addr_len(::google::protobuf::uint32 value);
  
  // optional uint32 op_code = 5 [default = 1];
  inline bool has_op_code() const;
  inline void clear_op_code();
  static const int kOpCodeFieldNumber = 5;
  inline ::google::protobuf::uint32 op_code() const;
  inline void set_op_code(::google::protobuf::uint32 value);
  
  // optional uint64 sender_hw_addr = 6;
  inline bool has_sender_hw_addr() const;
  inline void clear_sender_hw_addr();
  static const int kSenderHwAddrFieldNumber = 6;
  inline ::google::protobuf::uint64 sender_hw_addr() const;
  inline void set_sender_hw_addr(::google::protobuf::uint64 value);
  
  // optional .OstProto.Arp.HwAddrMode sender_hw_addr_mode = 7 [default = kFixed];
  inline bool has_sender_hw_addr_mode() const;
  inline void clear_sender_hw_addr_mode();
  static const int kSenderHwAddrModeFieldNumber = 7;
  inline ::OstProto::Arp_HwAddrMode sender_hw_addr_mode() const;
  inline void set_sender_hw_addr_mode(::OstProto::Arp_HwAddrMode value);
  
  // optional uint32 sender_hw_addr_count = 8 [default = 16];
  inline bool has_sender_hw_addr_count() const;
  inline void clear_sender_hw_addr_count();
  static const int kSenderHwAddrCountFieldNumber = 8;
  inline ::google::protobuf::uint32 sender_hw_addr_count() const;
  inline void set_sender_hw_addr_count(::google::protobuf::uint32 value);
  
  // optional uint32 sender_proto_addr = 9;
  inline bool has_sender_proto_addr() const;
  inline void clear_sender_proto_addr();
  static const int kSenderProtoAddrFieldNumber = 9;
  inline ::google::protobuf::uint32 sender_proto_addr() const;
  inline void set_sender_proto_addr(::google::protobuf::uint32 value);
  
  // optional .OstProto.Arp.ProtoAddrMode sender_proto_addr_mode = 10 [default = kFixedHost];
  inline bool has_sender_proto_addr_mode() const;
  inline void clear_sender_proto_addr_mode();
  static const int kSenderProtoAddrModeFieldNumber = 10;
  inline ::OstProto::Arp_ProtoAddrMode sender_proto_addr_mode() const;
  inline void set_sender_proto_addr_mode(::OstProto::Arp_ProtoAddrMode value);
  
  // optional uint32 sender_proto_addr_count = 11 [default = 16];
  inline bool has_sender_proto_addr_count() const;
  inline void clear_sender_proto_addr_count();
  static const int kSenderProtoAddrCountFieldNumber = 11;
  inline ::google::protobuf::uint32 sender_proto_addr_count() const;
  inline void set_sender_proto_addr_count(::google::protobuf::uint32 value);
  
  // optional fixed32 sender_proto_addr_mask = 12 [default = 4294967040];
  inline bool has_sender_proto_addr_mask() const;
  inline void clear_sender_proto_addr_mask();
  static const int kSenderProtoAddrMaskFieldNumber = 12;
  inline ::google::protobuf::uint32 sender_proto_addr_mask() const;
  inline void set_sender_proto_addr_mask(::google::protobuf::uint32 value);
  
  // optional uint64 target_hw_addr = 13;
  inline bool has_target_hw_addr() const;
  inline void clear_target_hw_addr();
  static const int kTargetHwAddrFieldNumber = 13;
  inline ::google::protobuf::uint64 target_hw_addr() const;
  inline void set_target_hw_addr(::google::protobuf::uint64 value);
  
  // optional .OstProto.Arp.HwAddrMode target_hw_addr_mode = 14 [default = kFixed];
  inline bool has_target_hw_addr_mode() const;
  inline void clear_target_hw_addr_mode();
  static const int kTargetHwAddrModeFieldNumber = 14;
  inline ::OstProto::Arp_HwAddrMode target_hw_addr_mode() const;
  inline void set_target_hw_addr_mode(::OstProto::Arp_HwAddrMode value);
  
  // optional uint32 target_hw_addr_count = 15 [default = 16];
  inline bool has_target_hw_addr_count() const;
  inline void clear_target_hw_addr_count();
  static const int kTargetHwAddrCountFieldNumber = 15;
  inline ::google::protobuf::uint32 target_hw_addr_count() const;
  inline void set_target_hw_addr_count(::google::protobuf::uint32 value);
  
  // optional uint32 target_proto_addr = 16;
  inline bool has_target_proto_addr() const;
  inline void clear_target_proto_addr();
  static const int kTargetProtoAddrFieldNumber = 16;
  inline ::google::protobuf::uint32 target_proto_addr() const;
  inline void set_target_proto_addr(::google::protobuf::uint32 value);
  
  // optional .OstProto.Arp.ProtoAddrMode target_proto_addr_mode = 17 [default = kFixedHost];
  inline bool has_target_proto_addr_mode() const;
  inline void clear_target_proto_addr_mode();
  static const int kTargetProtoAddrModeFieldNumber = 17;
  inline ::OstProto::Arp_ProtoAddrMode target_proto_addr_mode() const;
  inline void set_target_proto_addr_mode(::OstProto::Arp_ProtoAddrMode value);
  
  // optional uint32 target_proto_addr_count = 18 [default = 16];
  inline bool has_target_proto_addr_count() const;
  inline void clear_target_proto_addr_count();
  static const int kTargetProtoAddrCountFieldNumber = 18;
  inline ::google::protobuf::uint32 target_proto_addr_count() const;
  inline void set_target_proto_addr_count(::google::protobuf::uint32 value);
  
  // optional fixed32 target_proto_addr_mask = 19 [default = 4294967040];
  inline bool has_target_proto_addr_mask() const;
  inline void clear_target_proto_addr_mask();
  static const int kTargetProtoAddrMaskFieldNumber = 19;
  inline ::google::protobuf::uint32 target_proto_addr_mask() const;
  inline void set_target_proto_addr_mask(::google::protobuf::uint32 value);
  
  // @@protoc_insertion_point(class_scope:OstProto.Arp)
 private:
  inline void set_has_hw_type();
  inline void clear_has_hw_type();
  inline void set_has_proto_type();
  inline void clear_has_proto_type();
  inline void set_has_hw_addr_len();
  inline void clear_has_hw_addr_len();
  inline void set_has_proto_addr_len();
  inline void clear_has_proto_addr_len();
  inline void set_has_op_code();
  inline void clear_has_op_code();
  inline void set_has_sender_hw_addr();
  inline void clear_has_sender_hw_addr();
  inline void set_has_sender_hw_addr_mode();
  inline void clear_has_sender_hw_addr_mode();
  inline void set_has_sender_hw_addr_count();
  inline void clear_has_sender_hw_addr_count();
  inline void set_has_sender_proto_addr();
  inline void clear_has_sender_proto_addr();
  inline void set_has_sender_proto_addr_mode();
  inline void clear_has_sender_proto_addr_mode();
  inline void set_has_sender_proto_addr_count();
  inline void clear_has_sender_proto_addr_count();
  inline void set_has_sender_proto_addr_mask();
  inline void clear_has_sender_proto_addr_mask();
  inline void set_has_target_hw_addr();
  inline void clear_has_target_hw_addr();
  inline void set_has_target_hw_addr_mode();
  inline void clear_has_target_hw_addr_mode();
  inline void set_has_target_hw_addr_count();
  inline void clear_has_target_hw_addr_count();
  inline void set_has_target_proto_addr();
  inline void clear_has_target_proto_addr();
  inline void set_has_target_proto_addr_mode();
  inline void clear_has_target_proto_addr_mode();
  inline void set_has_target_proto_addr_count();
  inline void clear_has_target_proto_addr_count();
  inline void set_has_target_proto_addr_mask();
  inline void clear_has_target_proto_addr_mask();
  
  ::google::protobuf::UnknownFieldSet _unknown_fields_;
  
  ::google::protobuf::uint32 hw_type_;
  ::google::protobuf::uint32 proto_type_;
  ::google::protobuf::uint32 hw_addr_len_;
  ::google::protobuf::uint32 proto_addr_len_;
  ::google::protobuf::uint64 sender_hw_addr_;
  ::google::protobuf::uint32 op_code_;
  int sender_hw_addr_mode_;
  ::google::protobuf::uint32 sender_hw_addr_count_;
  ::google::protobuf::uint32 sender_proto_addr_;
  int sender_proto_addr_mode_;
  ::google::protobuf::uint32 sender_proto_addr_count_;
  ::google::protobuf::uint64 target_hw_addr_;
  ::google::protobuf::uint32 sender_proto_addr_mask_;
  int target_hw_addr_mode_;
  ::google::protobuf::uint32 target_hw_addr_count_;
  ::google::protobuf::uint32 target_proto_addr_;
  int target_proto_addr_mode_;
  ::google::protobuf::uint32 target_proto_addr_count_;
  ::google::protobuf::uint32 target_proto_addr_mask_;
  
  mutable int _cached_size_;
  ::google::protobuf::uint32 _has_bits_[(19 + 31) / 32];
  
  friend void  protobuf_AddDesc_arp_2eproto();
  friend void protobuf_AssignDesc_arp_2eproto();
  friend void protobuf_ShutdownFile_arp_2eproto();
  
  void InitAsDefaultInstance();
  static Arp* default_instance_;
};
// ===================================================================

static const int kArpFieldNumber = 300;
extern ::google::protobuf::internal::ExtensionIdentifier< ::OstProto::Protocol,
    ::google::protobuf::internal::MessageTypeTraits< ::OstProto::Arp >, 11, false >
  arp;

// ===================================================================

// Arp

// optional uint32 hw_type = 1 [default = 1];
inline bool Arp::has_hw_type() const {
  return (_has_bits_[0] & 0x00000001u) != 0;
}
inline void Arp::set_has_hw_type() {
  _has_bits_[0] |= 0x00000001u;
}
inline void Arp::clear_has_hw_type() {
  _has_bits_[0] &= ~0x00000001u;
}
inline void Arp::clear_hw_type() {
  hw_type_ = 1u;
  clear_has_hw_type();
}
inline ::google::protobuf::uint32 Arp::hw_type() const {
  return hw_type_;
}
inline void Arp::set_hw_type(::google::protobuf::uint32 value) {
  set_has_hw_type();
  hw_type_ = value;
}

// optional uint32 proto_type = 2 [default = 2048];
inline bool Arp::has_proto_type() const {
  return (_has_bits_[0] & 0x00000002u) != 0;
}
inline void Arp::set_has_proto_type() {
  _has_bits_[0] |= 0x00000002u;
}
inline void Arp::clear_has_proto_type() {
  _has_bits_[0] &= ~0x00000002u;
}
inline void Arp::clear_proto_type() {
  proto_type_ = 2048u;
  clear_has_proto_type();
}
inline ::google::protobuf::uint32 Arp::proto_type() const {
  return proto_type_;
}
inline void Arp::set_proto_type(::google::protobuf::uint32 value) {
  set_has_proto_type();
  proto_type_ = value;
}

// optional uint32 hw_addr_len = 3 [default = 6];
inline bool Arp::has_hw_addr_len() const {
  return (_has_bits_[0] & 0x00000004u) != 0;
}
inline void Arp::set_has_hw_addr_len() {
  _has_bits_[0] |= 0x00000004u;
}
inline void Arp::clear_has_hw_addr_len() {
  _has_bits_[0] &= ~0x00000004u;
}
inline void Arp::clear_hw_addr_len() {
  hw_addr_len_ = 6u;
  clear_has_hw_addr_len();
}
inline ::google::protobuf::uint32 Arp::hw_addr_len() const {
  return hw_addr_len_;
}
inline void Arp::set_hw_addr_len(::google::protobuf::uint32 value) {
  set_has_hw_addr_len();
  hw_addr_len_ = value;
}

// optional uint32 proto_addr_len = 4 [default = 4];
inline bool Arp::has_proto_addr_len() const {
  return (_has_bits_[0] & 0x00000008u) != 0;
}
inline void Arp::set_has_proto_addr_len() {
  _has_bits_[0] |= 0x00000008u;
}
inline void Arp::clear_has_proto_addr_len() {
  _has_bits_[0] &= ~0x00000008u;
}
inline void Arp::clear_proto_addr_len() {
  proto_addr_len_ = 4u;
  clear_has_proto_addr_len();
}
inline ::google::protobuf::uint32 Arp::proto_addr_len() const {
  return proto_addr_len_;
}
inline void Arp::set_proto_addr_len(::google::protobuf::uint32 value) {
  set_has_proto_addr_len();
  proto_addr_len_ = value;
}

// optional uint32 op_code = 5 [default = 1];
inline bool Arp::has_op_code() const {
  return (_has_bits_[0] & 0x00000010u) != 0;
}
inline void Arp::set_has_op_code() {
  _has_bits_[0] |= 0x00000010u;
}
inline void Arp::clear_has_op_code() {
  _has_bits_[0] &= ~0x00000010u;
}
inline void Arp::clear_op_code() {
  op_code_ = 1u;
  clear_has_op_code();
}
inline ::google::protobuf::uint32 Arp::op_code() const {
  return op_code_;
}
inline void Arp::set_op_code(::google::protobuf::uint32 value) {
  set_has_op_code();
  op_code_ = value;
}

// optional uint64 sender_hw_addr = 6;
inline bool Arp::has_sender_hw_addr() const {
  return (_has_bits_[0] & 0x00000020u) != 0;
}
inline void Arp::set_has_sender_hw_addr() {
  _has_bits_[0] |= 0x00000020u;
}
inline void Arp::clear_has_sender_hw_addr() {
  _has_bits_[0] &= ~0x00000020u;
}
inline void Arp::clear_sender_hw_addr() {
  sender_hw_addr_ = GOOGLE_ULONGLONG(0);
  clear_has_sender_hw_addr();
}
inline ::google::protobuf::uint64 Arp::sender_hw_addr() const {
  return sender_hw_addr_;
}
inline void Arp::set_sender_hw_addr(::google::protobuf::uint64 value) {
  set_has_sender_hw_addr();
  sender_hw_addr_ = value;
}

// optional .OstProto.Arp.HwAddrMode sender_hw_addr_mode = 7 [default = kFixed];
inline bool Arp::has_sender_hw_addr_mode() const {
  return (_has_bits_[0] & 0x00000040u) != 0;
}
inline void Arp::set_has_sender_hw_addr_mode() {
  _has_bits_[0] |= 0x00000040u;
}
inline void Arp::clear_has_sender_hw_addr_mode() {
  _has_bits_[0] &= ~0x00000040u;
}
inline void Arp::clear_sender_hw_addr_mode() {
  sender_hw_addr_mode_ = 0;
  clear_has_sender_hw_addr_mode();
}
inline ::OstProto::Arp_HwAddrMode Arp::sender_hw_addr_mode() const {
  return static_cast< ::OstProto::Arp_HwAddrMode >(sender_hw_addr_mode_);
}
inline void Arp::set_sender_hw_addr_mode(::OstProto::Arp_HwAddrMode value) {
  GOOGLE_DCHECK(::OstProto::Arp_HwAddrMode_IsValid(value));
  set_has_sender_hw_addr_mode();
  sender_hw_addr_mode_ = value;
}

// optional uint32 sender_hw_addr_count = 8 [default = 16];
inline bool Arp::has_sender_hw_addr_count() const {
  return (_has_bits_[0] & 0x00000080u) != 0;
}
inline void Arp::set_has_sender_hw_addr_count() {
  _has_bits_[0] |= 0x00000080u;
}
inline void Arp::clear_has_sender_hw_addr_count() {
  _has_bits_[0] &= ~0x00000080u;
}
inline void Arp::clear_sender_hw_addr_count() {
  sender_hw_addr_count_ = 16u;
  clear_has_sender_hw_addr_count();
}
inline ::google::protobuf::uint32 Arp::sender_hw_addr_count() const {
  return sender_hw_addr_count_;
}
inline void Arp::set_sender_hw_addr_count(::google::protobuf::uint32 value) {
  set_has_sender_hw_addr_count();
  sender_hw_addr_count_ = value;
}

// optional uint32 sender_proto_addr = 9;
inline bool Arp::has_sender_proto_addr() const {
  return (_has_bits_[0] & 0x00000100u) != 0;
}
inline void Arp::set_has_sender_proto_addr() {
  _has_bits_[0] |= 0x00000100u;
}
inline void Arp::clear_has_sender_proto_addr() {
  _has_bits_[0] &= ~0x00000100u;
}
inline void Arp::clear_sender_proto_addr() {
  sender_proto_addr_ = 0u;
  clear_has_sender_proto_addr();
}
inline ::google::protobuf::uint32 Arp::sender_proto_addr() const {
  return sender_proto_addr_;
}
inline void Arp::set_sender_proto_addr(::google::protobuf::uint32 value) {
  set_has_sender_proto_addr();
  sender_proto_addr_ = value;
}

// optional .OstProto.Arp.ProtoAddrMode sender_proto_addr_mode = 10 [default = kFixedHost];
inline bool Arp::has_sender_proto_addr_mode() const {
  return (_has_bits_[0] & 0x00000200u) != 0;
}
inline void Arp::set_has_sender_proto_addr_mode() {
  _has_bits_[0] |= 0x00000200u;
}
inline void Arp::clear_has_sender_proto_addr_mode() {
  _has_bits_[0] &= ~0x00000200u;
}
inline void Arp::clear_sender_proto_addr_mode() {
  sender_proto_addr_mode_ = 0;
  clear_has_sender_proto_addr_mode();
}
inline ::OstProto::Arp_ProtoAddrMode Arp::sender_proto_addr_mode() const {
  return static_cast< ::OstProto::Arp_ProtoAddrMode >(sender_proto_addr_mode_);
}
inline void Arp::set_sender_proto_addr_mode(::OstProto::Arp_ProtoAddrMode value) {
  GOOGLE_DCHECK(::OstProto::Arp_ProtoAddrMode_IsValid(value));
  set_has_sender_proto_addr_mode();
  sender_proto_addr_mode_ = value;
}

// optional uint32 sender_proto_addr_count = 11 [default = 16];
inline bool Arp::has_sender_proto_addr_count() const {
  return (_has_bits_[0] & 0x00000400u) != 0;
}
inline void Arp::set_has_sender_proto_addr_count() {
  _has_bits_[0] |= 0x00000400u;
}
inline void Arp::clear_has_sender_proto_addr_count() {
  _has_bits_[0] &= ~0x00000400u;
}
inline void Arp::clear_sender_proto_addr_count() {
  sender_proto_addr_count_ = 16u;
  clear_has_sender_proto_addr_count();
}
inline ::google::protobuf::uint32 Arp::sender_proto_addr_count() const {
  return sender_proto_addr_count_;
}
inline void Arp::set_sender_proto_addr_count(::google::protobuf::uint32 value) {
  set_has_sender_proto_addr_count();
  sender_proto_addr_count_ = value;
}

// optional fixed32 sender_proto_addr_mask = 12 [default = 4294967040];
inline bool Arp::has_sender_proto_addr_mask() const {
  return (_has_bits_[0] & 0x00000800u) != 0;
}
inline void Arp::set_has_sender_proto_addr_mask() {
  _has_bits_[0] |= 0x00000800u;
}
inline void Arp::clear_has_sender_proto_addr_mask() {
  _has_bits_[0] &= ~0x00000800u;
}
inline void Arp::clear_sender_proto_addr_mask() {
  sender_proto_addr_mask_ = 4294967040u;
  clear_has_sender_proto_addr_mask();
}
inline ::google::protobuf::uint32 Arp::sender_proto_addr_mask() const {
  return sender_proto_addr_mask_;
}
inline void Arp::set_sender_proto_addr_mask(::google::protobuf::uint32 value) {
  set_has_sender_proto_addr_mask();
  sender_proto_addr_mask_ = value;
}

// optional uint64 target_hw_addr = 13;
inline bool Arp::has_target_hw_addr() const {
  return (_has_bits_[0] & 0x00001000u) != 0;
}
inline void Arp::set_has_target_hw_addr() {
  _has_bits_[0] |= 0x00001000u;
}
inline void Arp::clear_has_target_hw_addr() {
  _has_bits_[0] &= ~0x00001000u;
}
inline void Arp::clear_target_hw_addr() {
  target_hw_addr_ = GOOGLE_ULONGLONG(0);
  clear_has_target_hw_addr();
}
inline ::google::protobuf::uint64 Arp::target_hw_addr() const {
  return target_hw_addr_;
}
inline void Arp::set_target_hw_addr(::google::protobuf::uint64 value) {
  set_has_target_hw_addr();
  target_hw_addr_ = value;
}

// optional .OstProto.Arp.HwAddrMode target_hw_addr_mode = 14 [default = kFixed];
inline bool Arp::has_target_hw_addr_mode() const {
  return (_has_bits_[0] & 0x00002000u) != 0;
}
inline void Arp::set_has_target_hw_addr_mode() {
  _has_bits_[0] |= 0x00002000u;
}
inline void Arp::clear_has_target_hw_addr_mode() {
  _has_bits_[0] &= ~0x00002000u;
}
inline void Arp::clear_target_hw_addr_mode() {
  target_hw_addr_mode_ = 0;
  clear_has_target_hw_addr_mode();
}
inline ::OstProto::Arp_HwAddrMode Arp::target_hw_addr_mode() const {
  return static_cast< ::OstProto::Arp_HwAddrMode >(target_hw_addr_mode_);
}
inline void Arp::set_target_hw_addr_mode(::OstProto::Arp_HwAddrMode value) {
  GOOGLE_DCHECK(::OstProto::Arp_HwAddrMode_IsValid(value));
  set_has_target_hw_addr_mode();
  target_hw_addr_mode_ = value;
}

// optional uint32 target_hw_addr_count = 15 [default = 16];
inline bool Arp::has_target_hw_addr_count() const {
  return (_has_bits_[0] & 0x00004000u) != 0;
}
inline void Arp::set_has_target_hw_addr_count() {
  _has_bits_[0] |= 0x00004000u;
}
inline void Arp::clear_has_target_hw_addr_count() {
  _has_bits_[0] &= ~0x00004000u;
}
inline void Arp::clear_target_hw_addr_count() {
  target_hw_addr_count_ = 16u;
  clear_has_target_hw_addr_count();
}
inline ::google::protobuf::uint32 Arp::target_hw_addr_count() const {
  return target_hw_addr_count_;
}
inline void Arp::set_target_hw_addr_count(::google::protobuf::uint32 value) {
  set_has_target_hw_addr_count();
  target_hw_addr_count_ = value;
}

// optional uint32 target_proto_addr = 16;
inline bool Arp::has_target_proto_addr() const {
  return (_has_bits_[0] & 0x00008000u) != 0;
}
inline void Arp::set_has_target_proto_addr() {
  _has_bits_[0] |= 0x00008000u;
}
inline void Arp::clear_has_target_proto_addr() {
  _has_bits_[0] &= ~0x00008000u;
}
inline void Arp::clear_target_proto_addr() {
  target_proto_addr_ = 0u;
  clear_has_target_proto_addr();
}
inline ::google::protobuf::uint32 Arp::target_proto_addr() const {
  return target_proto_addr_;
}
inline void Arp::set_target_proto_addr(::google::protobuf::uint32 value) {
  set_has_target_proto_addr();
  target_proto_addr_ = value;
}

// optional .OstProto.Arp.ProtoAddrMode target_proto_addr_mode = 17 [default = kFixedHost];
inline bool Arp::has_target_proto_addr_mode() const {
  return (_has_bits_[0] & 0x00010000u) != 0;
}
inline void Arp::set_has_target_proto_addr_mode() {
  _has_bits_[0] |= 0x00010000u;
}
inline void Arp::clear_has_target_proto_addr_mode() {
  _has_bits_[0] &= ~0x00010000u;
}
inline void Arp::clear_target_proto_addr_mode() {
  target_proto_addr_mode_ = 0;
  clear_has_target_proto_addr_mode();
}
inline ::OstProto::Arp_ProtoAddrMode Arp::target_proto_addr_mode() const {
  return static_cast< ::OstProto::Arp_ProtoAddrMode >(target_proto_addr_mode_);
}
inline void Arp::set_target_proto_addr_mode(::OstProto::Arp_ProtoAddrMode value) {
  GOOGLE_DCHECK(::OstProto::Arp_ProtoAddrMode_IsValid(value));
  set_has_target_proto_addr_mode();
  target_proto_addr_mode_ = value;
}

// optional uint32 target_proto_addr_count = 18 [default = 16];
inline bool Arp::has_target_proto_addr_count() const {
  return (_has_bits_[0] & 0x00020000u) != 0;
}
inline void Arp::set_has_target_proto_addr_count() {
  _has_bits_[0] |= 0x00020000u;
}
inline void Arp::clear_has_target_proto_addr_count() {
  _has_bits_[0] &= ~0x00020000u;
}
inline void Arp::clear_target_proto_addr_count() {
  target_proto_addr_count_ = 16u;
  clear_has_target_proto_addr_count();
}
inline ::google::protobuf::uint32 Arp::target_proto_addr_count() const {
  return target_proto_addr_count_;
}
inline void Arp::set_target_proto_addr_count(::google::protobuf::uint32 value) {
  set_has_target_proto_addr_count();
  target_proto_addr_count_ = value;
}

// optional fixed32 target_proto_addr_mask = 19 [default = 4294967040];
inline bool Arp::has_target_proto_addr_mask() const {
  return (_has_bits_[0] & 0x00040000u) != 0;
}
inline void Arp::set_has_target_proto_addr_mask() {
  _has_bits_[0] |= 0x00040000u;
}
inline void Arp::clear_has_target_proto_addr_mask() {
  _has_bits_[0] &= ~0x00040000u;
}
inline void Arp::clear_target_proto_addr_mask() {
  target_proto_addr_mask_ = 4294967040u;
  clear_has_target_proto_addr_mask();
}
inline ::google::protobuf::uint32 Arp::target_proto_addr_mask() const {
  return target_proto_addr_mask_;
}
inline void Arp::set_target_proto_addr_mask(::google::protobuf::uint32 value) {
  set_has_target_proto_addr_mask();
  target_proto_addr_mask_ = value;
}


// @@protoc_insertion_point(namespace_scope)

}  // namespace OstProto

#ifndef SWIG
namespace google {
namespace protobuf {

template <>
inline const EnumDescriptor* GetEnumDescriptor< ::OstProto::Arp_HwAddrMode>() {
  return ::OstProto::Arp_HwAddrMode_descriptor();
}
template <>
inline const EnumDescriptor* GetEnumDescriptor< ::OstProto::Arp_ProtoAddrMode>() {
  return ::OstProto::Arp_ProtoAddrMode_descriptor();
}

}  // namespace google
}  // namespace protobuf
#endif  // SWIG

// @@protoc_insertion_point(global_scope)

#endif  // PROTOBUF_arp_2eproto__INCLUDED
