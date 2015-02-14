/** @file qpolarsslrandom.hpp
  * Qt wrapper class around polarssl functions
  *
  * @copyright (C) 2015, azadkuh
  * @date 2015.02.12
  * @version 1.0.0
  * @author amir zamani <azadkuh@live.com>
  *
 */

#ifndef QPOLARSSL_RANDOM_HPP
#define QPOLARSSL_RANDOM_HPP

#include "qpolarsslbase.hpp"
///////////////////////////////////////////////////////////////////////////////
namespace qpolarssl {
///////////////////////////////////////////////////////////////////////////////
/** a wrapper class on polarssl CTR-DRBG (counter mode, deterministic random bit generator) utility.
 * @code
    // psuedo code (no error checking for simplicity)
    qpolarssl::Random rnd(QByteArray("my custom intializer!");

    auto randomData = rnd(20); // random data

    // in combination with qpolarssl::Cipher
    qpolarssl::Cipher cipher("AES-128-CBC");
    cipher.setEncryptionKey(key); // your key
    cipher.setIv(rnd(16));
    auto cipheredData = cipher(plainData);
 * @endcode
 */
class QPOLARSSL_API Random
{
public:
    /// constructs a Random instance by an optional custom initializer.
    explicit        Random(const uint8_t* custom = nullptr, size_t len=0);

    /// constructs a Random instance and optional custom initializer.
    explicit        Random(const QByteArray& custom) :
        Random(reinterpret_cast<const uint8_t*>(custom.constData()),
               custom.length()) {
    }

    virtual        ~Random();

    /** generates some random data in length size.
     * @return an empty array as failure.
     * @sa random() */
    auto            operator()(size_t length) -> QByteArray;

    /// generates some random data in length size, returns non-zero as error.
    int             random(uint8_t* output, size_t length);

    /// set prediction resistance, defualt is false at construction
    void            setPredictionResistance(bool resistance = false);

    /// reseeds generator with additional data
    int             reseed(const uint8_t* additional, size_t len);

    /// reseeds generator with additional data
    int             reseed(const QByteArray& additional);

    /// updates generator with additional data
    void            update(const uint8_t* additional, size_t len);

    /// updates generator with additional data
    void            update(const QByteArray& additional);

protected:
    Q_DISABLE_COPY(Random)

    QScopedPointer<priv::Random>  d_ptr;
};

///////////////////////////////////////////////////////////////////////////////
} // namespace qpolarssl
///////////////////////////////////////////////////////////////////////////////
#endif // QPOLARSSL_RANDOM_HPP
