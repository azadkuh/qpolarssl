#include "qpolarsslcipher.hpp"
#include "qpolarsslcipher_priv.hpp"
#include "qpolarssltypes.hpp"

#include "mbedtls/aesni.h"
///////////////////////////////////////////////////////////////////////////////
namespace qpolarssl {
///////////////////////////////////////////////////////////////////////////////
bool
Cipher::supports(TCipher type) {
    auto cinfo = mbedtls_cipher_info_from_type(Conversion::toPolar(type));
    return cinfo != nullptr;
}

bool
Cipher::supports(const char *name) {
    return mbedtls_cipher_info_from_string(name) != nullptr;
}

bool
Cipher::supportsAesNi() {
#if defined(MBEDTLS_HAVE_X86_64)    &&    defined(MBEDTLS_AESNI_C)
    return mbedtls_aesni_has_support(MBEDTLS_AESNI_AES) == 1;
#else
    return false;
#endif
}

///////////////////////////////////////////////////////////////////////////////
Cipher::Cipher(TCipher t) : d_ptr(new priv::Cipher(Conversion::toPolar(t))) {
}

Cipher::Cipher(const char* name) : d_ptr(new priv::Cipher(name)) {
}

Cipher::~Cipher() {
}

bool
Cipher::reset() {
    return d_ptr->reset();
}

bool
Cipher::isValid()const {
    return d_ptr->isValid();
}

QByteArray
Cipher::operator()(const QByteArray& message, TPadding padding) {
    return d_ptr->operator ()(message,
                              Conversion::toPolar(padding)
                              );
}

int
Cipher::setEncryptionKey(const QByteArray& key) {
    return d_ptr->setKey(key, MBEDTLS_ENCRYPT);
}

int
Cipher::setDecryptionKey(const QByteArray& key) {
    return d_ptr->setKey(key, MBEDTLS_DECRYPT);
}

int
Cipher::setIv(const QByteArray& nonce) {
    return d_ptr->setIv(nonce);
}


///////////////////////////////////////////////////////////////////////////////
} // namespace qpolarssl
///////////////////////////////////////////////////////////////////////////////
