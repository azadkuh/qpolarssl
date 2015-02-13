#include "qpolarsslpki.hpp"
#include "qpolarsslpki_priv.hpp"
#include "qpolarssltypes.hpp"
///////////////////////////////////////////////////////////////////////////////
namespace qpolarssl {
///////////////////////////////////////////////////////////////////////////////
Pki::Pki() : d_ptr(new priv::Pki()) {
}

Pki::~Pki() {
}

bool
Pki::isValid()const {
    return d_ptr->isValid();
}

void
Pki::reset() {
    d_ptr->reset();
}

size_t
Pki::keySizeBits()const {
    return d_ptr->keySizeBits();
}

size_t
Pki::keySizeBytes()const {
    return d_ptr->keySizeBytes();
}

bool
Pki::canDo(TPki type)const {
    return d_ptr->canDo( Conversion::toPolar(type) );
}

TPki
Pki::type() const {
    return Conversion::fromPolar(d_ptr->type());
}

const char*
Pki::name()const {
    return d_ptr->name();
}

int
Pki::parseKey(const QByteArray& keyData, const QByteArray& password) {
    return d_ptr->parseKey(keyData, password);
}

int
Pki::parsePublicKey(const QByteArray& keyData) {
    return d_ptr->parsePublicKey(keyData);
}

int
Pki::parseKeyFrom(const QString& filePath, const QByteArray& password) {
    return d_ptr->parseKeyFrom(filePath, password);
}

int
Pki::parsePublicKeyFrom(const QString& filePath) {
    return d_ptr->parsePublicKeyFrom(filePath);
}

QByteArray
Pki::sign(const QByteArray& message, THash algorithm) {
    return d_ptr->sign(message,
                       Conversion::toPolar(algorithm)
                       );
}

int
Pki::verify(const QByteArray& message, const QByteArray& signature,
                       THash algorithm) {
    return d_ptr->verify(message, signature,
                         Conversion::toPolar(algorithm)
                         );
}

QByteArray
Pki::encrypt(const QByteArray& hash) {
    return d_ptr->encrypt(hash);
}

QByteArray
Pki::decrypt(const QByteArray& hash) {
    return d_ptr->decrypt(hash);
}

///////////////////////////////////////////////////////////////////////////////
} // namespace qpolarssl
///////////////////////////////////////////////////////////////////////////////
