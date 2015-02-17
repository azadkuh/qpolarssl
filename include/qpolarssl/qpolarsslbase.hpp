/** @file qpolarsslbase.hpp
  * basic declarations of qpolarssl.
  *
  * @copyright (C) 2015, azadkuh
  * @date 2015.02.13
  * @version 1.0.0
  * @author amir zamani <azadkuh@live.com>
  *
 */

#ifndef QPOLARSSL_BASE_HPP
#define QPOLARSSL_BASE_HPP
///////////////////////////////////////////////////////////////////////////////
#include <QByteArray>
#include <QScopedPointer>
///////////////////////////////////////////////////////////////////////////////
namespace qpolarssl {
///////////////////////////////////////////////////////////////////////////////

/** all possible supported hash (message-digest) types in polarssl.
 *  @warning polarssl is highly configurable, please check
 *   the polarssl_config.h for more information and available (included) modules.
 */
enum class THash {
    NONE,           ///< no (invalid) hash
    MD2,            ///< optional
    MD4,            ///< included by default.
    MD5,            ///< included by default.
    SHA1,           ///< included by default.
    SHA224,         ///< included by default.
    SHA256,         ///< included by default.
    SHA384,         ///< included by default.
    SHA512,         ///< included by default.
    RIPEMD160,      ///< optional.
};


/** all possible supported cipher types in polarssl.
 * by default AES, AESNI and DES are included in build.
 * @warning polarssl is highly configurable, please check
 *  the polarssl_config.h for more information and available (included) modules.
 */
enum class TCipher {
    NONE,
    AES_128_ECB,
    AES_192_ECB,
    AES_256_ECB,
    AES_128_CBC,
    AES_192_CBC,
    AES_256_CBC,
    AES_128_CFB128,
    AES_192_CFB128,
    AES_256_CFB128,
    AES_128_CTR,
    AES_192_CTR,
    AES_256_CTR,
    AES_128_GCM,
    AES_192_GCM,
    AES_256_GCM,
    CAMELLIA_128_ECB,
    CAMELLIA_192_ECB,
    CAMELLIA_256_ECB,
    CAMELLIA_128_CBC,
    CAMELLIA_192_CBC,
    CAMELLIA_256_CBC,
    CAMELLIA_128_CFB128,
    CAMELLIA_192_CFB128,
    CAMELLIA_256_CFB128,
    CAMELLIA_128_CTR,
    CAMELLIA_192_CTR,
    CAMELLIA_256_CTR,
    CAMELLIA_128_GCM,
    CAMELLIA_192_GCM,
    CAMELLIA_256_GCM,
    DES_ECB,
    DES_CBC,
    DES_EDE_ECB,
    DES_EDE_CBC,
    DES_EDE3_ECB,
    DES_EDE3_CBC,
    BLOWFISH_ECB,
    BLOWFISH_CBC,
    BLOWFISH_CFB64,
    BLOWFISH_CTR,
    ARC4_128,
    AES_128_CCM,
    AES_192_CCM,
    AES_256_CCM,
    CAMELLIA_128_CCM,
    CAMELLIA_192_CCM,
    CAMELLIA_256_CCM
};


/** all possible paddings of polarssl.
 *  by default PKCS7 has been included in build.
 * @warning polarssl is highly configurable, please check
 *  the polarssl_config.h for more information and available (included) modules.
 */
enum class TPadding {
    PKCS7 = 0,        ///< PKCS7 padding (default)
    ONE_AND_ZEROS,    ///< ISO/IEC 7816-4 padding
    ZEROS_AND_LEN,    ///< ANSI X.923 padding
    ZEROS,            ///< zero padding (not reversible!)
    NONE,             ///< never pad (full blocks only)
};


/** all possible public key types of polarssl.
 * at the moment, RSA is included in build by default.
 * @warning polarssl is highly configurable, please check
 *  the polarssl_config.h for more information and available (included) modules.
 */
enum class TPki {
    NONE,
    RSA,
    ECKEY,
    ECKEY_DH,
    ECDSA,
    RSA_ALT,
    RSASSA_PSS
};

///////////////////////////////////////////////////////////////////////////////
// forward declarations
class   Hash;
class   Cipher;
class   Random;
class   Pki;
///////////////////////////////////////////////////////////////////////////////
namespace priv {
class   Hash;
class   Cipher;
class   Random;
class   Pki;
} // namespace priv
///////////////////////////////////////////////////////////////////////////////
#ifdef Q_OS_WIN
#   if defined(QPOLARSSL_EXPORT)
#       define QPOLARSSL_API __declspec(dllexport)
#   elif defined(QPOLARSSL_STATIC)
#       define QPOLARSSL_API
#   else
#       define QPOLARSSL_API __declspec(dllimport)
#   endif
#include <stdint.h>
#else
#   define QPOLARSSL_API
#endif
///////////////////////////////////////////////////////////////////////////////
} // namespace qpolarssl
///////////////////////////////////////////////////////////////////////////////
#endif // define QPOLARSSL_BASE_HPP
