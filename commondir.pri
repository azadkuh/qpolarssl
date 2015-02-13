# specifying common dirs

unix {
    TEMPDIR         = $$PRJDIR/tmp/unix/$$TARGET
    macx:TEMPDIR    = $$PRJDIR/tmp/osx/$$TARGET
    macx:CONFIG    -= app_bundle
    CONFIG         += c++11
    QMAKE_CFLAGS   += -std=gnu99
    QMAKE_CXXFLAGS +=  -Wall -Wno-unused-parameter
}

win32 {
    TEMPDIR         = $$PRJDIR/tmp/win32/$$TARGET
    CONFIG         += c++11
    DEFINES        += _WINDOWS WIN32_LEAN_AND_MEAN NOMINMAX
}



DESTDIR         = $$PRJDIR/xbin
MOC_DIR         = $$TEMPDIR
OBJECTS_DIR     = $$TEMPDIR
RCC_DIR         = $$TEMPDIR
UI_DIR          = $$TEMPDIR/Ui
LIBS           += -L$$PRJDIR/xbin

INCLUDEPATH     +=  . $$PRJDIR/include/qpolarssl

