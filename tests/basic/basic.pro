QT          += core
QT          -= gui
CONFIG      += console

TARGET       = test-basic
TEMPLATE     = app
PRJDIR       = ../..
include($$PRJDIR/commondir.pri)
INCLUDEPATH += $$PRJDIR/3rdparty/Catch/single_include

SOURCES     += main.cpp \
    text-generator.cpp \
    hashes.cpp \
    ciphers.cpp \
    random.cpp

HEADERS     += \
    text-generator.hpp

LIBS        += -lqpolarssl

