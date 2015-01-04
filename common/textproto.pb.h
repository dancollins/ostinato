// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: textproto.proto

#ifndef PROTOBUF_textproto_2eproto__INCLUDED
#define PROTOBUF_textproto_2eproto__INCLUDED

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
void  protobuf_AddDesc_textproto_2eproto();
void protobuf_AssignDesc_textproto_2eproto();
void protobuf_ShutdownFile_textproto_2eproto();

class TextProtocol;

enum TextProtocol_TextEncoding {
  TextProtocol_TextEncoding_kUtf8 = 0
};
bool TextProtocol_TextEncoding_IsValid(int value);
const TextProtocol_TextEncoding TextProtocol_TextEncoding_TextEncoding_MIN = TextProtocol_TextEncoding_kUtf8;
const TextProtocol_TextEncoding TextProtocol_TextEncoding_TextEncoding_MAX = TextProtocol_TextEncoding_kUtf8;
const int TextProtocol_TextEncoding_TextEncoding_ARRAYSIZE = TextProtocol_TextEncoding_TextEncoding_MAX + 1;

const ::google::protobuf::EnumDescriptor* TextProtocol_TextEncoding_descriptor();
inline const ::std::string& TextProtocol_TextEncoding_Name(TextProtocol_TextEncoding value) {
  return ::google::protobuf::internal::NameOfEnum(
    TextProtocol_TextEncoding_descriptor(), value);
}
inline bool TextProtocol_TextEncoding_Parse(
    const ::std::string& name, TextProtocol_TextEncoding* value) {
  return ::google::protobuf::internal::ParseNamedEnum<TextProtocol_TextEncoding>(
    TextProtocol_TextEncoding_descriptor(), name, value);
}
enum TextProtocol_EndOfLine {
  TextProtocol_EndOfLine_kCr = 0,
  TextProtocol_EndOfLine_kLf = 1,
  TextProtocol_EndOfLine_kCrLf = 2
};
bool TextProtocol_EndOfLine_IsValid(int value);
const TextProtocol_EndOfLine TextProtocol_EndOfLine_EndOfLine_MIN = TextProtocol_EndOfLine_kCr;
const TextProtocol_EndOfLine TextProtocol_EndOfLine_EndOfLine_MAX = TextProtocol_EndOfLine_kCrLf;
const int TextProtocol_EndOfLine_EndOfLine_ARRAYSIZE = TextProtocol_EndOfLine_EndOfLine_MAX + 1;

const ::google::protobuf::EnumDescriptor* TextProtocol_EndOfLine_descriptor();
inline const ::std::string& TextProtocol_EndOfLine_Name(TextProtocol_EndOfLine value) {
  return ::google::protobuf::internal::NameOfEnum(
    TextProtocol_EndOfLine_descriptor(), value);
}
inline bool TextProtocol_EndOfLine_Parse(
    const ::std::string& name, TextProtocol_EndOfLine* value) {
  return ::google::protobuf::internal::ParseNamedEnum<TextProtocol_EndOfLine>(
    TextProtocol_EndOfLine_descriptor(), name, value);
}
// ===================================================================

class TextProtocol : public ::google::protobuf::Message {
 public:
  TextProtocol();
  virtual ~TextProtocol();
  
  TextProtocol(const TextProtocol& from);
  
  inline TextProtocol& operator=(const TextProtocol& from) {
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
  static const TextProtocol& default_instance();
  
  void Swap(TextProtocol* other);
  
  // implements Message ----------------------------------------------
  
  TextProtocol* New() const;
  void CopyFrom(const ::google::protobuf::Message& from);
  void MergeFrom(const ::google::protobuf::Message& from);
  void CopyFrom(const TextProtocol& from);
  void MergeFrom(const TextProtocol& from);
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
  
  typedef TextProtocol_TextEncoding TextEncoding;
  static const TextEncoding kUtf8 = TextProtocol_TextEncoding_kUtf8;
  static inline bool TextEncoding_IsValid(int value) {
    return TextProtocol_TextEncoding_IsValid(value);
  }
  static const TextEncoding TextEncoding_MIN =
    TextProtocol_TextEncoding_TextEncoding_MIN;
  static const TextEncoding TextEncoding_MAX =
    TextProtocol_TextEncoding_TextEncoding_MAX;
  static const int TextEncoding_ARRAYSIZE =
    TextProtocol_TextEncoding_TextEncoding_ARRAYSIZE;
  static inline const ::google::protobuf::EnumDescriptor*
  TextEncoding_descriptor() {
    return TextProtocol_TextEncoding_descriptor();
  }
  static inline const ::std::string& TextEncoding_Name(TextEncoding value) {
    return TextProtocol_TextEncoding_Name(value);
  }
  static inline bool TextEncoding_Parse(const ::std::string& name,
      TextEncoding* value) {
    return TextProtocol_TextEncoding_Parse(name, value);
  }
  
  typedef TextProtocol_EndOfLine EndOfLine;
  static const EndOfLine kCr = TextProtocol_EndOfLine_kCr;
  static const EndOfLine kLf = TextProtocol_EndOfLine_kLf;
  static const EndOfLine kCrLf = TextProtocol_EndOfLine_kCrLf;
  static inline bool EndOfLine_IsValid(int value) {
    return TextProtocol_EndOfLine_IsValid(value);
  }
  static const EndOfLine EndOfLine_MIN =
    TextProtocol_EndOfLine_EndOfLine_MIN;
  static const EndOfLine EndOfLine_MAX =
    TextProtocol_EndOfLine_EndOfLine_MAX;
  static const int EndOfLine_ARRAYSIZE =
    TextProtocol_EndOfLine_EndOfLine_ARRAYSIZE;
  static inline const ::google::protobuf::EnumDescriptor*
  EndOfLine_descriptor() {
    return TextProtocol_EndOfLine_descriptor();
  }
  static inline const ::std::string& EndOfLine_Name(EndOfLine value) {
    return TextProtocol_EndOfLine_Name(value);
  }
  static inline bool EndOfLine_Parse(const ::std::string& name,
      EndOfLine* value) {
    return TextProtocol_EndOfLine_Parse(name, value);
  }
  
  // accessors -------------------------------------------------------
  
  // optional uint32 port_num = 1 [default = 80];
  inline bool has_port_num() const;
  inline void clear_port_num();
  static const int kPortNumFieldNumber = 1;
  inline ::google::protobuf::uint32 port_num() const;
  inline void set_port_num(::google::protobuf::uint32 value);
  
  // optional .OstProto.TextProtocol.TextEncoding encoding = 2 [default = kUtf8];
  inline bool has_encoding() const;
  inline void clear_encoding();
  static const int kEncodingFieldNumber = 2;
  inline ::OstProto::TextProtocol_TextEncoding encoding() const;
  inline void set_encoding(::OstProto::TextProtocol_TextEncoding value);
  
  // optional string text = 3;
  inline bool has_text() const;
  inline void clear_text();
  static const int kTextFieldNumber = 3;
  inline const ::std::string& text() const;
  inline void set_text(const ::std::string& value);
  inline void set_text(const char* value);
  inline void set_text(const char* value, size_t size);
  inline ::std::string* mutable_text();
  inline ::std::string* release_text();
  
  // optional .OstProto.TextProtocol.EndOfLine eol = 4 [default = kLf];
  inline bool has_eol() const;
  inline void clear_eol();
  static const int kEolFieldNumber = 4;
  inline ::OstProto::TextProtocol_EndOfLine eol() const;
  inline void set_eol(::OstProto::TextProtocol_EndOfLine value);
  
  // @@protoc_insertion_point(class_scope:OstProto.TextProtocol)
 private:
  inline void set_has_port_num();
  inline void clear_has_port_num();
  inline void set_has_encoding();
  inline void clear_has_encoding();
  inline void set_has_text();
  inline void clear_has_text();
  inline void set_has_eol();
  inline void clear_has_eol();
  
  ::google::protobuf::UnknownFieldSet _unknown_fields_;
  
  ::google::protobuf::uint32 port_num_;
  int encoding_;
  ::std::string* text_;
  int eol_;
  
  mutable int _cached_size_;
  ::google::protobuf::uint32 _has_bits_[(4 + 31) / 32];
  
  friend void  protobuf_AddDesc_textproto_2eproto();
  friend void protobuf_AssignDesc_textproto_2eproto();
  friend void protobuf_ShutdownFile_textproto_2eproto();
  
  void InitAsDefaultInstance();
  static TextProtocol* default_instance_;
};
// ===================================================================

static const int kTextProtocolFieldNumber = 500;
extern ::google::protobuf::internal::ExtensionIdentifier< ::OstProto::Protocol,
    ::google::protobuf::internal::MessageTypeTraits< ::OstProto::TextProtocol >, 11, false >
  textProtocol;

// ===================================================================

// TextProtocol

// optional uint32 port_num = 1 [default = 80];
inline bool TextProtocol::has_port_num() const {
  return (_has_bits_[0] & 0x00000001u) != 0;
}
inline void TextProtocol::set_has_port_num() {
  _has_bits_[0] |= 0x00000001u;
}
inline void TextProtocol::clear_has_port_num() {
  _has_bits_[0] &= ~0x00000001u;
}
inline void TextProtocol::clear_port_num() {
  port_num_ = 80u;
  clear_has_port_num();
}
inline ::google::protobuf::uint32 TextProtocol::port_num() const {
  return port_num_;
}
inline void TextProtocol::set_port_num(::google::protobuf::uint32 value) {
  set_has_port_num();
  port_num_ = value;
}

// optional .OstProto.TextProtocol.TextEncoding encoding = 2 [default = kUtf8];
inline bool TextProtocol::has_encoding() const {
  return (_has_bits_[0] & 0x00000002u) != 0;
}
inline void TextProtocol::set_has_encoding() {
  _has_bits_[0] |= 0x00000002u;
}
inline void TextProtocol::clear_has_encoding() {
  _has_bits_[0] &= ~0x00000002u;
}
inline void TextProtocol::clear_encoding() {
  encoding_ = 0;
  clear_has_encoding();
}
inline ::OstProto::TextProtocol_TextEncoding TextProtocol::encoding() const {
  return static_cast< ::OstProto::TextProtocol_TextEncoding >(encoding_);
}
inline void TextProtocol::set_encoding(::OstProto::TextProtocol_TextEncoding value) {
  GOOGLE_DCHECK(::OstProto::TextProtocol_TextEncoding_IsValid(value));
  set_has_encoding();
  encoding_ = value;
}

// optional string text = 3;
inline bool TextProtocol::has_text() const {
  return (_has_bits_[0] & 0x00000004u) != 0;
}
inline void TextProtocol::set_has_text() {
  _has_bits_[0] |= 0x00000004u;
}
inline void TextProtocol::clear_has_text() {
  _has_bits_[0] &= ~0x00000004u;
}
inline void TextProtocol::clear_text() {
  if (text_ != &::google::protobuf::internal::kEmptyString) {
    text_->clear();
  }
  clear_has_text();
}
inline const ::std::string& TextProtocol::text() const {
  return *text_;
}
inline void TextProtocol::set_text(const ::std::string& value) {
  set_has_text();
  if (text_ == &::google::protobuf::internal::kEmptyString) {
    text_ = new ::std::string;
  }
  text_->assign(value);
}
inline void TextProtocol::set_text(const char* value) {
  set_has_text();
  if (text_ == &::google::protobuf::internal::kEmptyString) {
    text_ = new ::std::string;
  }
  text_->assign(value);
}
inline void TextProtocol::set_text(const char* value, size_t size) {
  set_has_text();
  if (text_ == &::google::protobuf::internal::kEmptyString) {
    text_ = new ::std::string;
  }
  text_->assign(reinterpret_cast<const char*>(value), size);
}
inline ::std::string* TextProtocol::mutable_text() {
  set_has_text();
  if (text_ == &::google::protobuf::internal::kEmptyString) {
    text_ = new ::std::string;
  }
  return text_;
}
inline ::std::string* TextProtocol::release_text() {
  clear_has_text();
  if (text_ == &::google::protobuf::internal::kEmptyString) {
    return NULL;
  } else {
    ::std::string* temp = text_;
    text_ = const_cast< ::std::string*>(&::google::protobuf::internal::kEmptyString);
    return temp;
  }
}

// optional .OstProto.TextProtocol.EndOfLine eol = 4 [default = kLf];
inline bool TextProtocol::has_eol() const {
  return (_has_bits_[0] & 0x00000008u) != 0;
}
inline void TextProtocol::set_has_eol() {
  _has_bits_[0] |= 0x00000008u;
}
inline void TextProtocol::clear_has_eol() {
  _has_bits_[0] &= ~0x00000008u;
}
inline void TextProtocol::clear_eol() {
  eol_ = 1;
  clear_has_eol();
}
inline ::OstProto::TextProtocol_EndOfLine TextProtocol::eol() const {
  return static_cast< ::OstProto::TextProtocol_EndOfLine >(eol_);
}
inline void TextProtocol::set_eol(::OstProto::TextProtocol_EndOfLine value) {
  GOOGLE_DCHECK(::OstProto::TextProtocol_EndOfLine_IsValid(value));
  set_has_eol();
  eol_ = value;
}


// @@protoc_insertion_point(namespace_scope)

}  // namespace OstProto

#ifndef SWIG
namespace google {
namespace protobuf {

template <>
inline const EnumDescriptor* GetEnumDescriptor< ::OstProto::TextProtocol_TextEncoding>() {
  return ::OstProto::TextProtocol_TextEncoding_descriptor();
}
template <>
inline const EnumDescriptor* GetEnumDescriptor< ::OstProto::TextProtocol_EndOfLine>() {
  return ::OstProto::TextProtocol_EndOfLine_descriptor();
}

}  // namespace google
}  // namespace protobuf
#endif  // SWIG

// @@protoc_insertion_point(global_scope)

#endif  // PROTOBUF_textproto_2eproto__INCLUDED
