# Generated by the protocol buffer compiler.  DO NOT EDIT!

from google.protobuf import descriptor
from google.protobuf import message
from google.protobuf import reflection
from google.protobuf import descriptor_pb2
# @@protoc_insertion_point(imports)


import protocol_pb2
import vlan_pb2

DESCRIPTOR = descriptor.FileDescriptor(
  name='svlan.proto',
  package='OstProto',
  serialized_pb='\n\x0bsvlan.proto\x12\x08OstProto\x1a\x0eprotocol.proto\x1a\nvlan.proto:2\n\x05svlan\x12\x12.OstProto.Protocol\x18\xcc\x01 \x01(\x0b\x32\x0e.OstProto.Vlan')


SVLAN_FIELD_NUMBER = 204
svlan = descriptor.FieldDescriptor(
  name='svlan', full_name='OstProto.svlan', index=0,
  number=204, type=11, cpp_type=10, label=1,
  has_default_value=False, default_value=None,
  message_type=None, enum_type=None, containing_type=None,
  is_extension=True, extension_scope=None,
  options=None)


svlan.message_type = vlan_pb2._VLAN
protocol_pb2.Protocol.RegisterExtension(svlan)
# @@protoc_insertion_point(module_scope)
