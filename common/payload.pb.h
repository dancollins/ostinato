// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: payload.proto

#ifndef PROTOBUF_payload_2eproto__INCLUDED
#define PROTOBUF_payload_2eproto__INCLUDED

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
void  protobuf_AddDesc_payload_2eproto();
void protobuf_AssignDesc_payload_2eproto();
void protobuf_ShutdownFile_payload_2eproto();

class Payload;

enum Payload_DataPatternMode {
  Payload_DataPatternMode_e_dp_fixed_word = 0,
  Payload_DataPatternMode_e_dp_inc_byte = 1,
  Payload_DataPatternMode_e_dp_dec_byte = 2,
  Payload_DataPatternMode_e_dp_random = 3
};
bool Payload_DataPatternMode_IsValid(int value);
const Payload_DataPatternMode Payload_DataPatternMode_DataPatternMode_MIN = Payload_DataPatternMode_e_dp_fixed_word;
const Payload_DataPatternMode Payload_DataPatternMode_DataPatternMode_MAX = Payload_DataPatternMode_e_dp_random;
const int Payload_DataPatternMode_DataPatternMode_ARRAYSIZE = Payload_DataPatternMode_DataPatternMode_MAX + 1;

const ::google::protobuf::EnumDescriptor* Payload_DataPatternMode_descriptor();
inline const ::std::string& Payload_DataPatternMode_Name(Payload_DataPatternMode value) {
  return ::google::protobuf::internal::NameOfEnum(
    Payload_DataPatternMode_descriptor(), value);
}
inline bool Payload_DataPatternMode_Parse(
    const ::std::string& name, Payload_DataPatternMode* value) {
  return ::google::protobuf::internal::ParseNamedEnum<Payload_DataPatternMode>(
    Payload_DataPatternMode_descriptor(), name, value);
}
// ===================================================================

class Payload : public ::google::protobuf::Message {
 public:
  Payload();
  virtual ~Payload();
  
  Payload(const Payload& from);
  
  inline Payload& operator=(const Payload& from) {
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
  static const Payload& default_instance();
  
  void Swap(Payload* other);
  
  // implements Message ----------------------------------------------
  
  Payload* New() const;
  void CopyFrom(const ::google::protobuf::Message& from);
  void MergeFrom(const ::google::protobuf::Message& from);
  void CopyFrom(const Payload& from);
  void MergeFrom(const Payload& from);
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
  
  typedef Payload_DataPatternMode DataPatternMode;
  static const DataPatternMode e_dp_fixed_word = Payload_DataPatternMode_e_dp_fixed_word;
  static const DataPatternMode e_dp_inc_byte = Payload_DataPatternMode_e_dp_inc_byte;
  static const DataPatternMode e_dp_dec_byte = Payload_DataPatternMode_e_dp_dec_byte;
  static const DataPatternMode e_dp_random = Payload_DataPatternMode_e_dp_random;
  static inline bool DataPatternMode_IsValid(int value) {
    return Payload_DataPatternMode_IsValid(value);
  }
  static const DataPatternMode DataPatternMode_MIN =
    Payload_DataPatternMode_DataPatternMode_MIN;
  static const DataPatternMode DataPatternMode_MAX =
    Payload_DataPatternMode_DataPatternMode_MAX;
  static const int DataPatternMode_ARRAYSIZE =
    Payload_DataPatternMode_DataPatternMode_ARRAYSIZE;
  static inline const ::google::protobuf::EnumDescriptor*
  DataPatternMode_descriptor() {
    return Payload_DataPatternMode_descriptor();
  }
  static inline const ::std::string& DataPatternMode_Name(DataPatternMode value) {
    return Payload_DataPatternMode_Name(value);
  }
  static inline bool DataPatternMode_Parse(const ::std::string& name,
      DataPatternMode* value) {
    return Payload_DataPatternMode_Parse(name, value);
  }
  
  // accessors -------------------------------------------------------
  
  // optional .OstProto.Payload.DataPatternMode pattern_mode = 1;
  inline bool has_pattern_mode() const;
  inline void clear_pattern_mode();
  static const int kPatternModeFieldNumber = 1;
  inline ::OstProto::Payload_DataPatternMode pattern_mode() const;
  inline void set_pattern_mode(::OstProto::Payload_DataPatternMode value);
  
  // optional uint32 pattern = 2;
  inline bool has_pattern() const;
  inline void clear_pattern();
  static const int kPatternFieldNumber = 2;
  inline ::google::protobuf::uint32 pattern() const;
  inline void set_pattern(::google::protobuf::uint32 value);
  
  // @@protoc_insertion_point(class_scope:OstProto.Payload)
 private:
  inline void set_has_pattern_mode();
  inline void clear_has_pattern_mode();
  inline void set_has_pattern();
  inline void clear_has_pattern();
  
  ::google::protobuf::UnknownFieldSet _unknown_fields_;
  
  int pattern_mode_;
  ::google::protobuf::uint32 pattern_;
  
  mutable int _cached_size_;
  ::google::protobuf::uint32 _has_bits_[(2 + 31) / 32];
  
  friend void  protobuf_AddDesc_payload_2eproto();
  friend void protobuf_AssignDesc_payload_2eproto();
  friend void protobuf_ShutdownFile_payload_2eproto();
  
  void InitAsDefaultInstance();
  static Payload* default_instance_;
};
// ===================================================================

static const int kPayloadFieldNumber = 101;
extern ::google::protobuf::internal::ExtensionIdentifier< ::OstProto::Protocol,
    ::google::protobuf::internal::MessageTypeTraits< ::OstProto::Payload >, 11, false >
  payload;

// ===================================================================

// Payload

// optional .OstProto.Payload.DataPatternMode pattern_mode = 1;
inline bool Payload::has_pattern_mode() const {
  return (_has_bits_[0] & 0x00000001u) != 0;
}
inline void Payload::set_has_pattern_mode() {
  _has_bits_[0] |= 0x00000001u;
}
inline void Payload::clear_has_pattern_mode() {
  _has_bits_[0] &= ~0x00000001u;
}
inline void Payload::clear_pattern_mode() {
  pattern_mode_ = 0;
  clear_has_pattern_mode();
}
inline ::OstProto::Payload_DataPatternMode Payload::pattern_mode() const {
  return static_cast< ::OstProto::Payload_DataPatternMode >(pattern_mode_);
}
inline void Payload::set_pattern_mode(::OstProto::Payload_DataPatternMode value) {
  GOOGLE_DCHECK(::OstProto::Payload_DataPatternMode_IsValid(value));
  set_has_pattern_mode();
  pattern_mode_ = value;
}

// optional uint32 pattern = 2;
inline bool Payload::has_pattern() const {
  return (_has_bits_[0] & 0x00000002u) != 0;
}
inline void Payload::set_has_pattern() {
  _has_bits_[0] |= 0x00000002u;
}
inline void Payload::clear_has_pattern() {
  _has_bits_[0] &= ~0x00000002u;
}
inline void Payload::clear_pattern() {
  pattern_ = 0u;
  clear_has_pattern();
}
inline ::google::protobuf::uint32 Payload::pattern() const {
  return pattern_;
}
inline void Payload::set_pattern(::google::protobuf::uint32 value) {
  set_has_pattern();
  pattern_ = value;
}


// @@protoc_insertion_point(namespace_scope)

}  // namespace OstProto

#ifndef SWIG
namespace google {
namespace protobuf {

template <>
inline const EnumDescriptor* GetEnumDescriptor< ::OstProto::Payload_DataPatternMode>() {
  return ::OstProto::Payload_DataPatternMode_descriptor();
}

}  // namespace google
}  // namespace protobuf
#endif  // SWIG

// @@protoc_insertion_point(global_scope)

#endif  // PROTOBUF_payload_2eproto__INCLUDED
