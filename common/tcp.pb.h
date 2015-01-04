// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: tcp.proto

#ifndef PROTOBUF_tcp_2eproto__INCLUDED
#define PROTOBUF_tcp_2eproto__INCLUDED

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
void  protobuf_AddDesc_tcp_2eproto();
void protobuf_AssignDesc_tcp_2eproto();
void protobuf_ShutdownFile_tcp_2eproto();

class Tcp;

// ===================================================================

class Tcp : public ::google::protobuf::Message {
 public:
  Tcp();
  virtual ~Tcp();
  
  Tcp(const Tcp& from);
  
  inline Tcp& operator=(const Tcp& from) {
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
  static const Tcp& default_instance();
  
  void Swap(Tcp* other);
  
  // implements Message ----------------------------------------------
  
  Tcp* New() const;
  void CopyFrom(const ::google::protobuf::Message& from);
  void MergeFrom(const ::google::protobuf::Message& from);
  void CopyFrom(const Tcp& from);
  void MergeFrom(const Tcp& from);
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
  
  // accessors -------------------------------------------------------
  
  // optional bool is_override_src_port = 1;
  inline bool has_is_override_src_port() const;
  inline void clear_is_override_src_port();
  static const int kIsOverrideSrcPortFieldNumber = 1;
  inline bool is_override_src_port() const;
  inline void set_is_override_src_port(bool value);
  
  // optional bool is_override_dst_port = 2;
  inline bool has_is_override_dst_port() const;
  inline void clear_is_override_dst_port();
  static const int kIsOverrideDstPortFieldNumber = 2;
  inline bool is_override_dst_port() const;
  inline void set_is_override_dst_port(bool value);
  
  // optional bool is_override_hdrlen = 3;
  inline bool has_is_override_hdrlen() const;
  inline void clear_is_override_hdrlen();
  static const int kIsOverrideHdrlenFieldNumber = 3;
  inline bool is_override_hdrlen() const;
  inline void set_is_override_hdrlen(bool value);
  
  // optional bool is_override_cksum = 4;
  inline bool has_is_override_cksum() const;
  inline void clear_is_override_cksum();
  static const int kIsOverrideCksumFieldNumber = 4;
  inline bool is_override_cksum() const;
  inline void set_is_override_cksum(bool value);
  
  // optional uint32 src_port = 5 [default = 49152];
  inline bool has_src_port() const;
  inline void clear_src_port();
  static const int kSrcPortFieldNumber = 5;
  inline ::google::protobuf::uint32 src_port() const;
  inline void set_src_port(::google::protobuf::uint32 value);
  
  // optional uint32 dst_port = 6 [default = 49153];
  inline bool has_dst_port() const;
  inline void clear_dst_port();
  static const int kDstPortFieldNumber = 6;
  inline ::google::protobuf::uint32 dst_port() const;
  inline void set_dst_port(::google::protobuf::uint32 value);
  
  // optional uint32 seq_num = 7 [default = 129018];
  inline bool has_seq_num() const;
  inline void clear_seq_num();
  static const int kSeqNumFieldNumber = 7;
  inline ::google::protobuf::uint32 seq_num() const;
  inline void set_seq_num(::google::protobuf::uint32 value);
  
  // optional uint32 ack_num = 8;
  inline bool has_ack_num() const;
  inline void clear_ack_num();
  static const int kAckNumFieldNumber = 8;
  inline ::google::protobuf::uint32 ack_num() const;
  inline void set_ack_num(::google::protobuf::uint32 value);
  
  // optional uint32 hdrlen_rsvd = 9 [default = 80];
  inline bool has_hdrlen_rsvd() const;
  inline void clear_hdrlen_rsvd();
  static const int kHdrlenRsvdFieldNumber = 9;
  inline ::google::protobuf::uint32 hdrlen_rsvd() const;
  inline void set_hdrlen_rsvd(::google::protobuf::uint32 value);
  
  // optional uint32 flags = 10;
  inline bool has_flags() const;
  inline void clear_flags();
  static const int kFlagsFieldNumber = 10;
  inline ::google::protobuf::uint32 flags() const;
  inline void set_flags(::google::protobuf::uint32 value);
  
  // optional uint32 window = 11 [default = 1024];
  inline bool has_window() const;
  inline void clear_window();
  static const int kWindowFieldNumber = 11;
  inline ::google::protobuf::uint32 window() const;
  inline void set_window(::google::protobuf::uint32 value);
  
  // optional uint32 cksum = 12;
  inline bool has_cksum() const;
  inline void clear_cksum();
  static const int kCksumFieldNumber = 12;
  inline ::google::protobuf::uint32 cksum() const;
  inline void set_cksum(::google::protobuf::uint32 value);
  
  // optional uint32 urg_ptr = 13;
  inline bool has_urg_ptr() const;
  inline void clear_urg_ptr();
  static const int kUrgPtrFieldNumber = 13;
  inline ::google::protobuf::uint32 urg_ptr() const;
  inline void set_urg_ptr(::google::protobuf::uint32 value);
  
  // @@protoc_insertion_point(class_scope:OstProto.Tcp)
 private:
  inline void set_has_is_override_src_port();
  inline void clear_has_is_override_src_port();
  inline void set_has_is_override_dst_port();
  inline void clear_has_is_override_dst_port();
  inline void set_has_is_override_hdrlen();
  inline void clear_has_is_override_hdrlen();
  inline void set_has_is_override_cksum();
  inline void clear_has_is_override_cksum();
  inline void set_has_src_port();
  inline void clear_has_src_port();
  inline void set_has_dst_port();
  inline void clear_has_dst_port();
  inline void set_has_seq_num();
  inline void clear_has_seq_num();
  inline void set_has_ack_num();
  inline void clear_has_ack_num();
  inline void set_has_hdrlen_rsvd();
  inline void clear_has_hdrlen_rsvd();
  inline void set_has_flags();
  inline void clear_has_flags();
  inline void set_has_window();
  inline void clear_has_window();
  inline void set_has_cksum();
  inline void clear_has_cksum();
  inline void set_has_urg_ptr();
  inline void clear_has_urg_ptr();
  
  ::google::protobuf::UnknownFieldSet _unknown_fields_;
  
  bool is_override_src_port_;
  bool is_override_dst_port_;
  bool is_override_hdrlen_;
  bool is_override_cksum_;
  ::google::protobuf::uint32 src_port_;
  ::google::protobuf::uint32 dst_port_;
  ::google::protobuf::uint32 seq_num_;
  ::google::protobuf::uint32 ack_num_;
  ::google::protobuf::uint32 hdrlen_rsvd_;
  ::google::protobuf::uint32 flags_;
  ::google::protobuf::uint32 window_;
  ::google::protobuf::uint32 cksum_;
  ::google::protobuf::uint32 urg_ptr_;
  
  mutable int _cached_size_;
  ::google::protobuf::uint32 _has_bits_[(13 + 31) / 32];
  
  friend void  protobuf_AddDesc_tcp_2eproto();
  friend void protobuf_AssignDesc_tcp_2eproto();
  friend void protobuf_ShutdownFile_tcp_2eproto();
  
  void InitAsDefaultInstance();
  static Tcp* default_instance_;
};
// ===================================================================

static const int kTcpFieldNumber = 400;
extern ::google::protobuf::internal::ExtensionIdentifier< ::OstProto::Protocol,
    ::google::protobuf::internal::MessageTypeTraits< ::OstProto::Tcp >, 11, false >
  tcp;

// ===================================================================

// Tcp

// optional bool is_override_src_port = 1;
inline bool Tcp::has_is_override_src_port() const {
  return (_has_bits_[0] & 0x00000001u) != 0;
}
inline void Tcp::set_has_is_override_src_port() {
  _has_bits_[0] |= 0x00000001u;
}
inline void Tcp::clear_has_is_override_src_port() {
  _has_bits_[0] &= ~0x00000001u;
}
inline void Tcp::clear_is_override_src_port() {
  is_override_src_port_ = false;
  clear_has_is_override_src_port();
}
inline bool Tcp::is_override_src_port() const {
  return is_override_src_port_;
}
inline void Tcp::set_is_override_src_port(bool value) {
  set_has_is_override_src_port();
  is_override_src_port_ = value;
}

// optional bool is_override_dst_port = 2;
inline bool Tcp::has_is_override_dst_port() const {
  return (_has_bits_[0] & 0x00000002u) != 0;
}
inline void Tcp::set_has_is_override_dst_port() {
  _has_bits_[0] |= 0x00000002u;
}
inline void Tcp::clear_has_is_override_dst_port() {
  _has_bits_[0] &= ~0x00000002u;
}
inline void Tcp::clear_is_override_dst_port() {
  is_override_dst_port_ = false;
  clear_has_is_override_dst_port();
}
inline bool Tcp::is_override_dst_port() const {
  return is_override_dst_port_;
}
inline void Tcp::set_is_override_dst_port(bool value) {
  set_has_is_override_dst_port();
  is_override_dst_port_ = value;
}

// optional bool is_override_hdrlen = 3;
inline bool Tcp::has_is_override_hdrlen() const {
  return (_has_bits_[0] & 0x00000004u) != 0;
}
inline void Tcp::set_has_is_override_hdrlen() {
  _has_bits_[0] |= 0x00000004u;
}
inline void Tcp::clear_has_is_override_hdrlen() {
  _has_bits_[0] &= ~0x00000004u;
}
inline void Tcp::clear_is_override_hdrlen() {
  is_override_hdrlen_ = false;
  clear_has_is_override_hdrlen();
}
inline bool Tcp::is_override_hdrlen() const {
  return is_override_hdrlen_;
}
inline void Tcp::set_is_override_hdrlen(bool value) {
  set_has_is_override_hdrlen();
  is_override_hdrlen_ = value;
}

// optional bool is_override_cksum = 4;
inline bool Tcp::has_is_override_cksum() const {
  return (_has_bits_[0] & 0x00000008u) != 0;
}
inline void Tcp::set_has_is_override_cksum() {
  _has_bits_[0] |= 0x00000008u;
}
inline void Tcp::clear_has_is_override_cksum() {
  _has_bits_[0] &= ~0x00000008u;
}
inline void Tcp::clear_is_override_cksum() {
  is_override_cksum_ = false;
  clear_has_is_override_cksum();
}
inline bool Tcp::is_override_cksum() const {
  return is_override_cksum_;
}
inline void Tcp::set_is_override_cksum(bool value) {
  set_has_is_override_cksum();
  is_override_cksum_ = value;
}

// optional uint32 src_port = 5 [default = 49152];
inline bool Tcp::has_src_port() const {
  return (_has_bits_[0] & 0x00000010u) != 0;
}
inline void Tcp::set_has_src_port() {
  _has_bits_[0] |= 0x00000010u;
}
inline void Tcp::clear_has_src_port() {
  _has_bits_[0] &= ~0x00000010u;
}
inline void Tcp::clear_src_port() {
  src_port_ = 49152u;
  clear_has_src_port();
}
inline ::google::protobuf::uint32 Tcp::src_port() const {
  return src_port_;
}
inline void Tcp::set_src_port(::google::protobuf::uint32 value) {
  set_has_src_port();
  src_port_ = value;
}

// optional uint32 dst_port = 6 [default = 49153];
inline bool Tcp::has_dst_port() const {
  return (_has_bits_[0] & 0x00000020u) != 0;
}
inline void Tcp::set_has_dst_port() {
  _has_bits_[0] |= 0x00000020u;
}
inline void Tcp::clear_has_dst_port() {
  _has_bits_[0] &= ~0x00000020u;
}
inline void Tcp::clear_dst_port() {
  dst_port_ = 49153u;
  clear_has_dst_port();
}
inline ::google::protobuf::uint32 Tcp::dst_port() const {
  return dst_port_;
}
inline void Tcp::set_dst_port(::google::protobuf::uint32 value) {
  set_has_dst_port();
  dst_port_ = value;
}

// optional uint32 seq_num = 7 [default = 129018];
inline bool Tcp::has_seq_num() const {
  return (_has_bits_[0] & 0x00000040u) != 0;
}
inline void Tcp::set_has_seq_num() {
  _has_bits_[0] |= 0x00000040u;
}
inline void Tcp::clear_has_seq_num() {
  _has_bits_[0] &= ~0x00000040u;
}
inline void Tcp::clear_seq_num() {
  seq_num_ = 129018u;
  clear_has_seq_num();
}
inline ::google::protobuf::uint32 Tcp::seq_num() const {
  return seq_num_;
}
inline void Tcp::set_seq_num(::google::protobuf::uint32 value) {
  set_has_seq_num();
  seq_num_ = value;
}

// optional uint32 ack_num = 8;
inline bool Tcp::has_ack_num() const {
  return (_has_bits_[0] & 0x00000080u) != 0;
}
inline void Tcp::set_has_ack_num() {
  _has_bits_[0] |= 0x00000080u;
}
inline void Tcp::clear_has_ack_num() {
  _has_bits_[0] &= ~0x00000080u;
}
inline void Tcp::clear_ack_num() {
  ack_num_ = 0u;
  clear_has_ack_num();
}
inline ::google::protobuf::uint32 Tcp::ack_num() const {
  return ack_num_;
}
inline void Tcp::set_ack_num(::google::protobuf::uint32 value) {
  set_has_ack_num();
  ack_num_ = value;
}

// optional uint32 hdrlen_rsvd = 9 [default = 80];
inline bool Tcp::has_hdrlen_rsvd() const {
  return (_has_bits_[0] & 0x00000100u) != 0;
}
inline void Tcp::set_has_hdrlen_rsvd() {
  _has_bits_[0] |= 0x00000100u;
}
inline void Tcp::clear_has_hdrlen_rsvd() {
  _has_bits_[0] &= ~0x00000100u;
}
inline void Tcp::clear_hdrlen_rsvd() {
  hdrlen_rsvd_ = 80u;
  clear_has_hdrlen_rsvd();
}
inline ::google::protobuf::uint32 Tcp::hdrlen_rsvd() const {
  return hdrlen_rsvd_;
}
inline void Tcp::set_hdrlen_rsvd(::google::protobuf::uint32 value) {
  set_has_hdrlen_rsvd();
  hdrlen_rsvd_ = value;
}

// optional uint32 flags = 10;
inline bool Tcp::has_flags() const {
  return (_has_bits_[0] & 0x00000200u) != 0;
}
inline void Tcp::set_has_flags() {
  _has_bits_[0] |= 0x00000200u;
}
inline void Tcp::clear_has_flags() {
  _has_bits_[0] &= ~0x00000200u;
}
inline void Tcp::clear_flags() {
  flags_ = 0u;
  clear_has_flags();
}
inline ::google::protobuf::uint32 Tcp::flags() const {
  return flags_;
}
inline void Tcp::set_flags(::google::protobuf::uint32 value) {
  set_has_flags();
  flags_ = value;
}

// optional uint32 window = 11 [default = 1024];
inline bool Tcp::has_window() const {
  return (_has_bits_[0] & 0x00000400u) != 0;
}
inline void Tcp::set_has_window() {
  _has_bits_[0] |= 0x00000400u;
}
inline void Tcp::clear_has_window() {
  _has_bits_[0] &= ~0x00000400u;
}
inline void Tcp::clear_window() {
  window_ = 1024u;
  clear_has_window();
}
inline ::google::protobuf::uint32 Tcp::window() const {
  return window_;
}
inline void Tcp::set_window(::google::protobuf::uint32 value) {
  set_has_window();
  window_ = value;
}

// optional uint32 cksum = 12;
inline bool Tcp::has_cksum() const {
  return (_has_bits_[0] & 0x00000800u) != 0;
}
inline void Tcp::set_has_cksum() {
  _has_bits_[0] |= 0x00000800u;
}
inline void Tcp::clear_has_cksum() {
  _has_bits_[0] &= ~0x00000800u;
}
inline void Tcp::clear_cksum() {
  cksum_ = 0u;
  clear_has_cksum();
}
inline ::google::protobuf::uint32 Tcp::cksum() const {
  return cksum_;
}
inline void Tcp::set_cksum(::google::protobuf::uint32 value) {
  set_has_cksum();
  cksum_ = value;
}

// optional uint32 urg_ptr = 13;
inline bool Tcp::has_urg_ptr() const {
  return (_has_bits_[0] & 0x00001000u) != 0;
}
inline void Tcp::set_has_urg_ptr() {
  _has_bits_[0] |= 0x00001000u;
}
inline void Tcp::clear_has_urg_ptr() {
  _has_bits_[0] &= ~0x00001000u;
}
inline void Tcp::clear_urg_ptr() {
  urg_ptr_ = 0u;
  clear_has_urg_ptr();
}
inline ::google::protobuf::uint32 Tcp::urg_ptr() const {
  return urg_ptr_;
}
inline void Tcp::set_urg_ptr(::google::protobuf::uint32 value) {
  set_has_urg_ptr();
  urg_ptr_ = value;
}


// @@protoc_insertion_point(namespace_scope)

}  // namespace OstProto

#ifndef SWIG
namespace google {
namespace protobuf {


}  // namespace google
}  // namespace protobuf
#endif  // SWIG

// @@protoc_insertion_point(global_scope)

#endif  // PROTOBUF_tcp_2eproto__INCLUDED
