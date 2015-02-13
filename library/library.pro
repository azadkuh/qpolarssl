QT       += core
QT       -= gui widget

TARGET    = qpolarssl
TEMPLATE  = lib

PRJDIR    = ..
include($$PRJDIR/commondir.pri)
include(polarssl.pri)

win32:DEFINES += QPOLARSSL_EXPORT


SOURCES  += \
    qpolarsslhash.cpp \
    qpolarsslcipher.cpp

HEADERS  += \
    qpolarssltypes.hpp \
    ../include/qpolarssl/qpolarsslbase.hpp \
    ../include/qpolarssl/qpolarsslhash.hpp \
    ../include/qpolarssl/qpolarsslcipher.hpp


