MBEDTLSDIR   = $$PRJDIR/3rdparty/mbedtls
INCLUDEPATH += $$MBEDTLSDIR/include

DEFINES     += MBEDTLS_CONFIG_FILE='"\\\"$$PRJDIR/library/mbedtls_config.h\\\""'

HEADERS     += $$PRJDIR/library/mbedtls_config.h

SOURCES     += \
    $$MBEDTLSDIR/library/base64.c \
    $$MBEDTLSDIR/library/md4.c \
    $$MBEDTLSDIR/library/md5.c \
    $$MBEDTLSDIR/library/sha1.c \
    $$MBEDTLSDIR/library/sha256.c \
    $$MBEDTLSDIR/library/sha512.c \
    $$MBEDTLSDIR/library/md_wrap.c \
    $$MBEDTLSDIR/library/md.c \
    $$MBEDTLSDIR/library/blowfish.c \
    $$MBEDTLSDIR/library/aes.c \
    $$MBEDTLSDIR/library/aesni.c \
    $$MBEDTLSDIR/library/des.c \
    $$MBEDTLSDIR/library/cipher_wrap.c \
    $$MBEDTLSDIR/library/cipher.c \
    $$MBEDTLSDIR/library/entropy.c \
    $$MBEDTLSDIR/library/entropy_poll.c \
    $$MBEDTLSDIR/library/ctr_drbg.c \
    $$MBEDTLSDIR/library/rsa.c \
    $$MBEDTLSDIR/library/pem.c \
    $$MBEDTLSDIR/library/bignum.c \
    $$MBEDTLSDIR/library/oid.c \
    $$MBEDTLSDIR/library/asn1parse.c \
    $$MBEDTLSDIR/library/pkparse.c \
    $$MBEDTLSDIR/library/pk_wrap.c \
    $$MBEDTLSDIR/library/pk.c \
    $$MBEDTLSDIR/library/oid.c \
    $$MBEDTLSDIR/library/platform.c
