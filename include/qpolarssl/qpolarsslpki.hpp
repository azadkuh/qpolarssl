/** @file qpolarsslpki.hpp
  * Qt wrapper class around polarssl functions
  *
  * @copyright (C) 2015, azadkuh
  * @date 2015.02.12
  * @version 1.0.0
  * @author amir zamani <azadkuh@live.com>
  *
 */

#ifndef QPOLARSSL_PKI_HPP
#define QPOLARSSL_PKI_HPP

#include <QFile>
#include "polarssl/pk.h"
#include "qpolarsslhash.hpp"
#include "qpolarsslrandom.hpp"
///////////////////////////////////////////////////////////////////////////////
namespace qpolarssl {
///////////////////////////////////////////////////////////////////////////////
/** a wrapper class on polarssl PKI cryptography functions.
 * @code
    // psuedo code (no error checking for simplicity)
 * @endcode
 */
class Pki
{
public:
    /// constructs a Pki instance, actual initialization will be done by key loading.
    explicit        Pki();

    virtual        ~Pki();

    /// checks if this instance has been initialized and is valid
    bool            isValid()const;

    /// reset the context
    void            reset();

    /// returns the key size in bits (1024 / 2048 / ...)
    size_t          keySizeBits()const;

    /// returns the key size in bytes (128 / 256 / ...)
    size_t          keySizeBytes()const;

    /// checks if current operation can be done with this instance.
    bool            canDo(TPki type)const;

    /// returns current PKI type.
    auto            type()const -> TPki;

    /// returns current PKI name.
    auto            name()const -> const char*;

public:
    /// parses a Private key data and initializes the class
    int             parseKey(const QByteArray& keyData,
                             const QByteArray& password = QByteArray());

    /// parses a Public key data and initializes the class.
    ///  (public keys are not protected by password).
    int             parsePublicKey(const QByteArray& keyData);

    /// parses a Private key from a file path.
    int             parseKeyFrom(const QString& filePath,
                                 const QByteArray& password = QByteArray());

    /// parses a Public key from a file path.
    int             parsePublicKeyFrom(const QString& filePath);

public:
    /** signs a message (or hash of that message) with the private key.
     * @param message if message.length() is larger than keySizeBytes(), then
     *  automatically computes over the hash of this message.
     * @param algorithm hash creation method.
     * @return the signature or an empty array as failure.
     */
    auto            sign(const QByteArray& message,
                         THash algorithm) -> QByteArray;

    /** verifies the signature of a message (or hash of that message) with public key.
     * @param message if message.length() is larger than keySizeBytes(), then
     *  automatically computes over the hash of this message.
     * @param signature the signature to be compared with.
     * @param algorithm hash creation method.
     * @return return 0 if the signature has been verfied, a non-zero as error.
     */
    int             verify(const QByteArray& message,
                           const QByteArray& signature,
                           THash algorithm);

    /// encrypts a hash value by public key. returns empty array as failure.
    auto            encrypt(const QByteArray& hash) -> QByteArray;

    /// decrypts an encoded-hash value by private key. returns empty array as failure.
    auto            decrypt(const QByteArray& hash) -> QByteArray;

protected:
    Q_DISABLE_COPY(Pki)

    QScopedPointer<priv::Pki>   d_ptr;
};

///////////////////////////////////////////////////////////////////////////////
} // namespace qpolarssl
///////////////////////////////////////////////////////////////////////////////
#endif // QPOLARSSL_PKI_HPP
