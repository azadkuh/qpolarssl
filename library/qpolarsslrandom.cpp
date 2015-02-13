#include "qpolarsslrandom.hpp"
#include "qpolarsslrandom_priv.hpp"
///////////////////////////////////////////////////////////////////////////////
namespace qpolarssl {
///////////////////////////////////////////////////////////////////////////////
Random::Random(const uint8_t* custom, size_t len) :
    d_ptr(new priv::Random(custom, len)) {
}

Random::~Random() {
}

QByteArray
Random::operator()(size_t length) {
    return d_ptr->operator ()(length);
}

int
Random::random(uint8_t* output, size_t length) {
    return d_ptr->random(output, length);
}

void
Random::setPredictionResistance(bool resistance) {
    d_ptr->setPredictionResistance(resistance);
}

int
Random::reseed(const uint8_t* additional, size_t len) {
    return d_ptr->reseed(additional, len);
}

int
Random::reseed(const QByteArray& additional) {
    return d_ptr->reseed(additional);
}

void
Random::update(const uint8_t* additional, size_t len) {
    d_ptr->update(additional, len);
}

void
Random::update(const QByteArray& additional) {
    d_ptr->update(additional);
}

///////////////////////////////////////////////////////////////////////////////
} // namespace qpolarssl
///////////////////////////////////////////////////////////////////////////////
