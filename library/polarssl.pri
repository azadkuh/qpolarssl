POLARSSLDIR  = $$PRJDIR/3rdparty/polarssl
INCLUDEPATH += $$POLARSSLDIR/include

DEFINES     += POLARSSL_CONFIG_FILE='"\\\"$$PRJDIR/library/polarssl_config.h\\\""'

HEADERS     += $$PRJDIR/library/polarssl_config.h

SOURCES     += \
    $$POLARSSLDIR/library/base64.c \
    $$POLARSSLDIR/library/md4.c \
    $$POLARSSLDIR/library/md5.c \
    $$POLARSSLDIR/library/sha1.c \
    $$POLARSSLDIR/library/sha256.c \
    $$POLARSSLDIR/library/sha512.c \
    $$POLARSSLDIR/library/md_wrap.c \
    $$POLARSSLDIR/library/md.c \
    $$POLARSSLDIR/library/blowfish.c \
    $$POLARSSLDIR/library/aes.c \
    $$POLARSSLDIR/library/aesni.c \
    $$POLARSSLDIR/library/des.c \
    $$POLARSSLDIR/library/padlock.c \
    $$POLARSSLDIR/library/cipher_wrap.c \
    $$POLARSSLDIR/library/cipher.c \
    $$POLARSSLDIR/library/entropy.c \
    $$POLARSSLDIR/library/entropy_poll.c \
    $$POLARSSLDIR/library/ctr_drbg.c \
    $$POLARSSLDIR/library/rsa.c \
    $$POLARSSLDIR/library/pem.c \
    $$POLARSSLDIR/library/bignum.c \
    $$POLARSSLDIR/library/oid.c \
    $$POLARSSLDIR/library/asn1parse.c \
    $$POLARSSLDIR/library/pkparse.c \
    $$POLARSSLDIR/library/pk_wrap.c \
    $$POLARSSLDIR/library/pk.c
