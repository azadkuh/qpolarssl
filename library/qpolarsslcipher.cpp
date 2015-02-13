#include "qpolarsslcipher.hpp"
#include "qpolarsslcipher_priv.hpp"
#include "qpolarssltypes.hpp"

///////////////////////////////////////////////////////////////////////////////
namespace qpolarssl {
///////////////////////////////////////////////////////////////////////////////
bool
Cipher::supports(TCipher type) {
    auto cinfo = cipher_info_from_type(Conversion::toPolar(type));
    return cinfo != nullptr;
}

bool
Cipher::supports(const char *name) {
    return cipher_info_from_string(name) != nullptr;
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
    return d_ptr->setKey(key, POLARSSL_ENCRYPT);
}

int
Cipher::setDecryptionKey(const QByteArray& key) {
    return d_ptr->setKey(key, POLARSSL_DECRYPT);
}

int
Cipher::setIv(const QByteArray& nonce) {
    return d_ptr->setIv(nonce);
}


///////////////////////////////////////////////////////////////////////////////
} // namespace qpolarssl
///////////////////////////////////////////////////////////////////////////////
