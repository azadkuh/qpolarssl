QT       += core
QT       -= gui widget

TARGET    = qpolarssl
TEMPLATE  = lib
unix:CONFIG   += static
win32:CONFIG  += static

PRJDIR    = ..
include($$PRJDIR/commondir.pri)
include(mbedtls.pri)



SOURCES  += \
    qpolarsslhash.cpp \
    qpolarsslcipher.cpp \
    qpolarsslrandom.cpp \
    qpolarsslpki.cpp

HEADERS  += \
    qpolarssltypes.hpp \
    qpolarsslcipher_priv.hpp \
    qpolarsslhash_priv.hpp \
    qpolarsslpki_priv.hpp \
    qpolarsslrandom_priv.hpp \
    ../include/qpolarssl/qpolarsslbase.hpp \
    ../include/qpolarssl/qpolarsslhash.hpp \
    ../include/qpolarssl/qpolarsslcipher.hpp \
    ../include/qpolarssl/qpolarsslrandom.hpp \
    ../include/qpolarssl/qpolarsslpki.hpp

win32:LIBS += -ladvapi32
