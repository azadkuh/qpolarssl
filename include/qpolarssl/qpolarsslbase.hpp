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

/// all possible supported hash (message-digest) types in polarssl.
/// @warning polarssl is highly configurable, please check
///  the polarssl_config.h for more information and available (included) modules.
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
#   else
#       define QPOLARSSL_API __declspec(dllimport)
#   endif
#else
#   define QPOLARSSL_API
#endif
///////////////////////////////////////////////////////////////////////////////
} // namespace qpolarssl
///////////////////////////////////////////////////////////////////////////////
#endif // define QPOLARSSL_BASE_HPP
