TEMPLATE = lib
CONFIG += qt staticlib
QT += network
LIBS += \
	-lprotobuf
FORMS += \
	mac.ui \
	payload.ui \
	eth2.ui \
	dot3.ui \
	llc.ui \
	snap.ui \
	ip4.ui \
	tcp.ui \
	udp.ui
PROTOS += \
	protocol.proto \
	mac.proto \
	payload.proto \
	eth2.proto \
	dot3.proto \
	llc.proto \
	snap.proto \
	ip4.proto \
	tcp.proto \
	udp.proto
HEADERS += \
	abstractprotocol.h	\
	mac.h \
	payload.h \
	eth2.h \
	dot3.h \
	llc.h \
	snap.h \
	ip4.h \
	tcp.h \
	udp.h
SOURCES += \
	abstractprotocol.cpp \
	mac.cpp \
	payload.cpp \
	eth2.cpp \
	dot3.cpp \
	llc.cpp \
	snap.cpp \
	ip4.cpp \
	tcp.cpp \
	udp.cpp

protobuf_decl.name  = protobuf header
protobuf_decl.input = PROTOS
protobuf_decl.output  = ${QMAKE_FILE_BASE}.pb.h
protobuf_decl.commands = protoc --cpp_out="." ${QMAKE_FILE_NAME}
protobuf_decl.variable_out = GENERATED_FILES 
QMAKE_EXTRA_COMPILERS += protobuf_decl 

protobuf_impl.name  = protobuf implementation
protobuf_impl.input = PROTOS
protobuf_impl.output  = ${QMAKE_FILE_BASE}.pb.cc
protobuf_impl.depends  = ${QMAKE_FILE_BASE}.pb.h
protobuf_impl.commands = $$escape_expand(\n)
protobuf_impl.variable_out = GENERATED_SOURCES
QMAKE_EXTRA_COMPILERS += protobuf_impl 