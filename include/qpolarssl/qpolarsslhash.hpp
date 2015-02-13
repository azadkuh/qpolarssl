/** @file qpolarsslhash.hpp
  * Qt wrapper class around polarssl hash functions
  *
  * @copyright (C) 2015, azadkuh
  * @date 2015.02.13
  * @version 1.0.0
  * @author amir zamani <azadkuh@live.com>
  *
 */

#ifndef QPOLARSSL_HASH_HPP
#define QPOLARSSL_HASH_HPP

#include "qpolarsslbase.hpp"
///////////////////////////////////////////////////////////////////////////////
namespace qpolarssl {
///////////////////////////////////////////////////////////////////////////////
/** a wrapper class on polarssl hash (message-digest) functions.
 * by this class, performing hash/hmac on data by polarssl
 *  would be quite simple:
 * @code
    // psuedo code (no error checking for simplicity)

    bool check     = qpolarssl::Hash::supports("SHA512");

    const QByteArray source  = fetchSourceDataFromSomewhere();
    auto hashMd5   = qpolarssl::Hash::hash(source, qpolarssl::THash::MD5);
    auto hashSha1  = qpolarssl::Hash::hash(source, "SHA1");

    // or
    qpolarssl::Hash hash("SHA256");
    hash.start();
    while ( condition ) {
        // ...
        hash.update( chunk );
        // ...
    }
    auto hashSha256 = hash.finish();

    // to start again:
    hash.start();
    // ... and compute another hash value as above.


    // to make hmac message authentication code:
    QByteArray key;     // secret key value in any length.
    QByteArray message; // message to be hmac'ed in any length

    auto hmacSha1 = qpolarssl::Hash::hmac(key, message, "SHA1");
    // that's all!

 * @endcode
 */
class QPOLARSSL_API Hash
{
public:
    /// creates a single-shot hash value from inputs, returns an empty array as failure.
    static auto     hash(const QByteArray& in,
                         THash type = THash::SHA1) -> QByteArray;

    /// creates a single-shot hash value from inputs, returns an empty array as failure.
    /// @param name is a acsii string like "SHA1", "MD5", ...
    static auto     hash(const QByteArray &in,
                         const char* name) -> QByteArray;

    /// creates a single-shot hash value directly from a file, returns an empty array as failure.
    static auto     fileHash(const QString& filePath,
                             THash type = THash::SHA1) -> QByteArray;

    /// creates a single-shot hash value directly from a file, returns an empty array as failure.
    static auto     fileHash(const QString& filePath,
                             const char* name) -> QByteArray;

    /// creates a single-shot hmac value from inputs, returns an empty array as failure.
    static auto     hmac(const QByteArray& key,
                         const QByteArray& message,
                         THash type = THash::SHA1) -> QByteArray;

    /// creates a single-shot hmac value from inputs, returns an empty array as failure.
    static auto     hmac(const QByteArray& key,
                         const QByteArray& message,
                         const char* name) -> QByteArray;

    /// checks if current compilation supports a hash type.
    static bool     supports(THash type);

    /// checks if current compilation supports a hash type by it's name.
    static bool     supports(const char* name);

public:
    /// constructs a Hash instance by a message digest type.
    explicit        Hash(THash t);

    /// constructs a Hash instance by a message digest name.
    explicit        Hash(const char* name);

    virtual        ~Hash();

    /// returns false if current Hash instance is not valid.
    bool            isValid()const;

    /// resets and start a new Hash computation. returns non-zero if fails.
    int             start();

    /// adds some chunk of data to Hash, returns non-zero if fails.
    int             update(const uint8_t* input, size_t length);

    /// adds some chunk of data to Hash, returns non-zero if fails.
    int             update(const QByteArray& input);

    /// finishes and returns the hash result from previous update() calls.
    /// return an empty array as failure.
    auto            finish() -> QByteArray;

    /** resets and starts computing of a hmac value.
     * @param key if key is empty, keeps the previous specified key.
     * @return non-zero as error.
     */
    int             hmacStart(const QByteArray& key = QByteArray());

    /// adds some chunks of data to HMAC, returns non-zero if fails.
    int             hmacUpdate(const uint8_t* input, size_t length);

    /// adds some chunks of data to HMAC, returns non-zero if fails.
    int             hmacUpdate(const QByteArray& input);

    /// finishes and returns the hmac value, returns an empty array as failure.
    auto            hmacFinish() -> QByteArray;

protected:
    Q_DISABLE_COPY(Hash)
    QScopedPointer<priv::Hash>  d_ptr;
};
///////////////////////////////////////////////////////////////////////////////
} // namespace qpolarssl
///////////////////////////////////////////////////////////////////////////////
#endif // QPOLARSSL_HASH_HPP
