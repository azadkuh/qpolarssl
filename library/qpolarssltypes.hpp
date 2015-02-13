/** @file qpolarssltypes.hpp
  * converts between polarssl and qpolarssl types.
  *
  * @copyright (C) 2015, azadkuh
  * @date 2015.02.13
  * @version 1.0.0
  * @author amir zamani <azadkuh@live.com>
  *
 */

#ifndef QPOLARSSL_TYPES_HPP
#define QPOLARSSL_TYPES_HPP
///////////////////////////////////////////////////////////////////////////////
#include "qpolarsslbase.hpp"
#include <polarssl/md.h>
///////////////////////////////////////////////////////////////////////////////
namespace qpolarssl {
///////////////////////////////////////////////////////////////////////////////
class Conversion
{
public:
    static  auto    toPolar(THash h) -> md_type_t {
        switch ( h ) {
        case THash::NONE:
            return POLARSSL_MD_NONE;
            break;
        case THash::MD2:
            return POLARSSL_MD_MD2;
            break;
        case THash::MD4:
            return POLARSSL_MD_MD4;
            break;
        case THash::MD5:
            return POLARSSL_MD_MD5;
            break;
        case THash::SHA1:
            return POLARSSL_MD_SHA1;
            break;
        case THash::SHA224:
            return POLARSSL_MD_SHA224;
            break;
        case THash::SHA256:
            return POLARSSL_MD_SHA256;
            break;
        case THash::SHA384:
            return POLARSSL_MD_SHA384;
            break;
        case THash::SHA512:
            return POLARSSL_MD_SHA512;
            break;
        case THash::RIPEMD160:
            return POLARSSL_MD_RIPEMD160;
            break;
        default:
            break;
        }

        return POLARSSL_MD_NONE;
    }

    static auto     fromPolar(md_type_t t) -> THash {
        switch ( t ) {
        case POLARSSL_MD_NONE:
            return THash::NONE;
            break;
        case POLARSSL_MD_MD2:
            return THash::MD2;
            break;
        case POLARSSL_MD_MD4:
            return THash::MD4;
            break;
        case POLARSSL_MD_MD5:
            return THash::MD5;
            break;
        case POLARSSL_MD_SHA1:
            return THash::SHA1;
            break;
        case POLARSSL_MD_SHA224:
            return THash::SHA224;
            break;
        case POLARSSL_MD_SHA256:
            return THash::SHA256;
            break;
        case POLARSSL_MD_SHA384:
            return THash::SHA384;
            break;
        case POLARSSL_MD_SHA512:
            return THash::SHA512;
            break;
        case POLARSSL_MD_RIPEMD160:
            return THash::RIPEMD160;
            break;
        }

        return THash::NONE;
    }
};

///////////////////////////////////////////////////////////////////////////////
} // namespace qpolarssl
///////////////////////////////////////////////////////////////////////////////
#endif // define QPOLARSSL_TYPES_HPP
