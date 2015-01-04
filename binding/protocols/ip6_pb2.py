# Generated by the protocol buffer compiler.  DO NOT EDIT!

from google.protobuf import descriptor
from google.protobuf import message
from google.protobuf import reflection
from google.protobuf import descriptor_pb2
# @@protoc_insertion_point(imports)


import protocol_pb2

DESCRIPTOR = descriptor.FileDescriptor(
  name='ip6.proto',
  package='OstProto',
  serialized_pb='\n\tip6.proto\x12\x08OstProto\x1a\x0eprotocol.proto\"\xe4\x04\n\x03Ip6\x12\x1b\n\x13is_override_version\x18\x01 \x01(\x08\x12\"\n\x1ais_override_payload_length\x18\x02 \x01(\x08\x12\x1f\n\x17is_override_next_header\x18\x03 \x01(\x08\x12\x12\n\x07version\x18\x04 \x01(\r:\x01\x36\x12\x15\n\rtraffic_class\x18\x05 \x01(\r\x12\x12\n\nflow_label\x18\x06 \x01(\r\x12\x16\n\x0epayload_length\x18\x07 \x01(\r\x12\x13\n\x0bnext_header\x18\x08 \x01(\r\x12\x16\n\thop_limit\x18\t \x01(\r:\x03\x31\x32\x37\x12\x13\n\x0bsrc_addr_hi\x18\n \x01(\x04\x12\x13\n\x0bsrc_addr_lo\x18\x0b \x01(\x04\x12\x35\n\rsrc_addr_mode\x18\x0c \x01(\x0e\x32\x16.OstProto.Ip6.AddrMode:\x06kFixed\x12\x1a\n\x0esrc_addr_count\x18\r \x01(\r:\x02\x31\x36\x12\x1b\n\x0fsrc_addr_prefix\x18\x0e \x01(\r:\x02\x36\x34\x12\x13\n\x0b\x64st_addr_hi\x18\x0f \x01(\x04\x12\x13\n\x0b\x64st_addr_lo\x18\x10 \x01(\x04\x12\x35\n\rdst_addr_mode\x18\x11 \x01(\x0e\x32\x16.OstProto.Ip6.AddrMode:\x06kFixed\x12\x1a\n\x0e\x64st_addr_count\x18\x12 \x01(\r:\x02\x31\x36\x12\x1b\n\x0f\x64st_addr_prefix\x18\x13 \x01(\r:\x02\x36\x34\"C\n\x08\x41\x64\x64rMode\x12\n\n\x06kFixed\x10\x00\x12\x0c\n\x08kIncHost\x10\x01\x12\x0c\n\x08kDecHost\x10\x02\x12\x0f\n\x0bkRandomHost\x10\x03:/\n\x03ip6\x12\x12.OstProto.Protocol\x18\xae\x02 \x01(\x0b\x32\r.OstProto.Ip6')


IP6_FIELD_NUMBER = 302
ip6 = descriptor.FieldDescriptor(
  name='ip6', full_name='OstProto.ip6', index=0,
  number=302, type=11, cpp_type=10, label=1,
  has_default_value=False, default_value=None,
  message_type=None, enum_type=None, containing_type=None,
  is_extension=True, extension_scope=None,
  options=None)

_IP6_ADDRMODE = descriptor.EnumDescriptor(
  name='AddrMode',
  full_name='OstProto.Ip6.AddrMode',
  filename=None,
  file=DESCRIPTOR,
  values=[
    descriptor.EnumValueDescriptor(
      name='kFixed', index=0, number=0,
      options=None,
      type=None),
    descriptor.EnumValueDescriptor(
      name='kIncHost', index=1, number=1,
      options=None,
      type=None),
    descriptor.EnumValueDescriptor(
      name='kDecHost', index=2, number=2,
      options=None,
      type=None),
    descriptor.EnumValueDescriptor(
      name='kRandomHost', index=3, number=3,
      options=None,
      type=None),
  ],
  containing_type=None,
  options=None,
  serialized_start=585,
  serialized_end=652,
)


_IP6 = descriptor.Descriptor(
  name='Ip6',
  full_name='OstProto.Ip6',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    descriptor.FieldDescriptor(
      name='is_override_version', full_name='OstProto.Ip6.is_override_version', index=0,
      number=1, type=8, cpp_type=7, label=1,
      has_default_value=False, default_value=False,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    descriptor.FieldDescriptor(
      name='is_override_payload_length', full_name='OstProto.Ip6.is_override_payload_length', index=1,
      number=2, type=8, cpp_type=7, label=1,
      has_default_value=False, default_value=False,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    descriptor.FieldDescriptor(
      name='is_override_next_header', full_name='OstProto.Ip6.is_override_next_header', index=2,
      number=3, type=8, cpp_type=7, label=1,
      has_default_value=False, default_value=False,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    descriptor.FieldDescriptor(
      name='version', full_name='OstProto.Ip6.version', index=3,
      number=4, type=13, cpp_type=3, label=1,
      has_default_value=True, default_value=6,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    descriptor.FieldDescriptor(
      name='traffic_class', full_name='OstProto.Ip6.traffic_class', index=4,
      number=5, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    descriptor.FieldDescriptor(
      name='flow_label', full_name='OstProto.Ip6.flow_label', index=5,
      number=6, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    descriptor.FieldDescriptor(
      name='payload_length', full_name='OstProto.Ip6.payload_length', index=6,
      number=7, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    descriptor.FieldDescriptor(
      name='next_header', full_name='OstProto.Ip6.next_header', index=7,
      number=8, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    descriptor.FieldDescriptor(
      name='hop_limit', full_name='OstProto.Ip6.hop_limit', index=8,
      number=9, type=13, cpp_type=3, label=1,
      has_default_value=True, default_value=127,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    descriptor.FieldDescriptor(
      name='src_addr_hi', full_name='OstProto.Ip6.src_addr_hi', index=9,
      number=10, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    descriptor.FieldDescriptor(
      name='src_addr_lo', full_name='OstProto.Ip6.src_addr_lo', index=10,
      number=11, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    descriptor.FieldDescriptor(
      name='src_addr_mode', full_name='OstProto.Ip6.src_addr_mode', index=11,
      number=12, type=14, cpp_type=8, label=1,
      has_default_value=True, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    descriptor.FieldDescriptor(
      name='src_addr_count', full_name='OstProto.Ip6.src_addr_count', index=12,
      number=13, type=13, cpp_type=3, label=1,
      has_default_value=True, default_value=16,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    descriptor.FieldDescriptor(
      name='src_addr_prefix', full_name='OstProto.Ip6.src_addr_prefix', index=13,
      number=14, type=13, cpp_type=3, label=1,
      has_default_value=True, default_value=64,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    descriptor.FieldDescriptor(
      name='dst_addr_hi', full_name='OstProto.Ip6.dst_addr_hi', index=14,
      number=15, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    descriptor.FieldDescriptor(
      name='dst_addr_lo', full_name='OstProto.Ip6.dst_addr_lo', index=15,
      number=16, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    descriptor.FieldDescriptor(
      name='dst_addr_mode', full_name='OstProto.Ip6.dst_addr_mode', index=16,
      number=17, type=14, cpp_type=8, label=1,
      has_default_value=True, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    descriptor.FieldDescriptor(
      name='dst_addr_count', full_name='OstProto.Ip6.dst_addr_count', index=17,
      number=18, type=13, cpp_type=3, label=1,
      has_default_value=True, default_value=16,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    descriptor.FieldDescriptor(
      name='dst_addr_prefix', full_name='OstProto.Ip6.dst_addr_prefix', index=18,
      number=19, type=13, cpp_type=3, label=1,
      has_default_value=True, default_value=64,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
    _IP6_ADDRMODE,
  ],
  options=None,
  is_extendable=False,
  extension_ranges=[],
  serialized_start=40,
  serialized_end=652,
)

_IP6.fields_by_name['src_addr_mode'].enum_type = _IP6_ADDRMODE
_IP6.fields_by_name['dst_addr_mode'].enum_type = _IP6_ADDRMODE
_IP6_ADDRMODE.containing_type = _IP6;
DESCRIPTOR.message_types_by_name['Ip6'] = _IP6

class Ip6(message.Message):
  __metaclass__ = reflection.GeneratedProtocolMessageType
  DESCRIPTOR = _IP6
  
  # @@protoc_insertion_point(class_scope:OstProto.Ip6)

ip6.message_type = _IP6
protocol_pb2.Protocol.RegisterExtension(ip6)
# @@protoc_insertion_point(module_scope)
