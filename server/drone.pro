TEMPLATE = app
CONFIG += qt ver_info
QT += network script
QT -= gui
DEFINES += HAVE_REMOTE WPCAP
INCLUDEPATH += "../rpc"
win32 {
    CONFIG += console
    LIBS += -lwpcap -lpacket
    CONFIG(debug, debug|release) {
        LIBS += -L"../common/debug" -lostproto
        LIBS += -L"../rpc/debug" -lpbrpc
        POST_TARGETDEPS += \
            "../common/debug/libostproto.a" \
            "../rpc/debug/libpbrpc.a"
    } else {
        LIBS += -L"../common/release" -lostproto
        LIBS += -L"../rpc/release" -lpbrpc
        POST_TARGETDEPS += \
            "../common/release/libostproto.a" \
            "../rpc/release/libpbrpc.a"
    }
} else {
    LIBS += -lpcap
    LIBS += -L"../common" -lostproto
    LIBS += -L"../rpc" -lpbrpc
    LIBS += -ldl
    POST_TARGETDEPS += "../common/libostproto.a" "../rpc/libpbrpc.a"
}
unix: include(dpdk.pri)
LIBS += -lm
LIBS += -lprotobuf
HEADERS += drone.h 
SOURCES += \
    drone_main.cpp \
    drone.cpp \
    portmanager.cpp \
    dpdk.cpp \
    abstractport.cpp \
    pcapport.cpp \
    bsdport.cpp \
    dpdkport.cpp \
    linuxport.cpp \
    winpcapport.cpp 
SOURCES += myservice.cpp 
SOURCES += pcapextra.cpp 

QMAKE_DISTCLEAN += object_script.*

include (../install.pri)
include (../version.pri)
