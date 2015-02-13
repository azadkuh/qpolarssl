#include "qpolarsslhash.hpp"
#include "qpolarssltypes.hpp"
#include "qpolarsslhash_priv.hpp"
///////////////////////////////////////////////////////////////////////////////
namespace qpolarssl {
///////////////////////////////////////////////////////////////////////////////
QByteArray
Hash::hash(const QByteArray& in, THash type) {
    return priv::Hash::hash(in,
                            Conversion::toPolar(type)
                            );
}

QByteArray
Hash::hash(const QByteArray &in, const char* name) {
    return priv::Hash::hash(in, name);
}

QByteArray
Hash::fileHash(const QString& filePath, THash type) {
    return priv::Hash::fileHash(filePath,
                                Conversion::toPolar(type)
                                );
}

QByteArray
Hash::fileHash(const QString& filePath, const char* name) {
    return priv::Hash::fileHash(filePath, name);
}

QByteArray
Hash::hmac(const QByteArray& key,
           const QByteArray& message, THash type) {
    return priv::Hash::hmac(key, message,
                            Conversion::toPolar(type)
                            );
}

QByteArray
Hash::hmac(const QByteArray& key,
           const QByteArray& message, const char* name) {
    return priv::Hash::hmac(key, message, name);
}

bool
Hash::supports(THash type) {
    auto ptype      = Conversion::toPolar(type);
    auto minfo      = md_info_from_type(ptype);
    return minfo != nullptr;
}

bool
Hash::supports(const char* name) {
    auto minfo      = md_info_from_string(name);
    return minfo != nullptr;
}

///////////////////////////////////////////////////////////////////////////////

Hash::Hash(THash t) : d_ptr(new priv::Hash(Conversion::toPolar(t))) {
}

Hash::Hash(const char* name) : d_ptr(new priv::Hash(name)) {
}

Hash::~Hash() {
}

bool
Hash::isValid()const {
    return d_ptr->isValid();
}

int
Hash::start() {
    return d_ptr->start();
}

int
Hash::update(const uint8_t* input, size_t length) {
    return d_ptr->update(input, length);
}

int
Hash::update(const QByteArray& input) {
    return d_ptr->update(input);
}

QByteArray
Hash::finish() {
    return d_ptr->finish();
}

int
Hash::hmacStart(const QByteArray& key) {
    return d_ptr->hmacStart(key);
}

int
Hash::hmacUpdate(const uint8_t* input, size_t length) {
    return d_ptr->hmacUpdate(input, length);
}

int
Hash::hmacUpdate(const QByteArray& input) {
    return d_ptr->hmacUpdate(input);
}

QByteArray
Hash::hmacFinish() {
    return d_ptr->hmacFinish();
}

///////////////////////////////////////////////////////////////////////////////
} // namespace qpolarssl
///////////////////////////////////////////////////////////////////////////////
