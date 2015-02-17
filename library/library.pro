QT       += core
QT       -= gui widget

TARGET    = qpolarssl
TEMPLATE  = lib
CONFIG	 += shared

win32:DEFINES += QPOLARSSL_EXPORT

PRJDIR    = ..
include($$PRJDIR/commondir.pri)
include(polarssl.pri)



SOURCES  += \
    qpolarsslhash.cpp \
    qpolarsslcipher.cpp \
    qpolarsslrandom.cpp \
    qpolarsslpki.cpp

HEADERS  += \
    qpolarssltypes.hpp \
    ../include/qpolarssl/qpolarsslbase.hpp \
    ../include/qpolarssl/qpolarsslhash.hpp \
    ../include/qpolarssl/qpolarsslcipher.hpp \
    ../include/qpolarssl/qpolarsslrandom.hpp \
    ../include/qpolarssl/qpolarsslpki.hpp

win32:LIBS += -ladvapi32
