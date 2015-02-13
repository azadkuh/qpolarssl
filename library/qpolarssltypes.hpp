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
#include <polarssl/cipher.h>
///////////////////////////////////////////////////////////////////////////////
namespace qpolarssl {
///////////////////////////////////////////////////////////////////////////////
class Conversion
{
public:
    static auto     toPolar(THash h) -> md_type_t {
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

    static auto     toPolar(TCipher c) -> cipher_type_t {
        switch ( c ) {
        case TCipher::NONE:
            return POLARSSL_CIPHER_NONE;
            break;
        case TCipher::AES_128_ECB:
            return POLARSSL_CIPHER_AES_128_ECB;
            break;
        case TCipher::AES_192_ECB:
            return POLARSSL_CIPHER_AES_192_ECB;
            break;
        case TCipher::AES_256_ECB:
            return POLARSSL_CIPHER_AES_256_ECB;
            break;
        case TCipher::AES_128_CBC:
            return POLARSSL_CIPHER_AES_128_CBC;
            break;
        case TCipher::AES_192_CBC:
            return POLARSSL_CIPHER_AES_192_CBC;
            break;
        case TCipher::AES_256_CBC:
            return POLARSSL_CIPHER_AES_256_CBC;
            break;
        case TCipher::AES_128_CFB128:
            return POLARSSL_CIPHER_AES_128_CFB128;
            break;
        case TCipher::AES_192_CFB128:
            return POLARSSL_CIPHER_AES_192_CFB128;
            break;
        case TCipher::AES_256_CFB128:
            return POLARSSL_CIPHER_AES_256_CFB128;
            break;
        case TCipher::AES_128_CTR:
            return POLARSSL_CIPHER_AES_128_CTR;
            break;
        case TCipher::AES_192_CTR:
            return POLARSSL_CIPHER_AES_192_CTR;
            break;
        case TCipher::AES_256_CTR:
            return POLARSSL_CIPHER_AES_256_CTR;
            break;
        case TCipher::AES_128_GCM:
            return POLARSSL_CIPHER_AES_128_GCM;
            break;
        case TCipher::AES_192_GCM:
            return POLARSSL_CIPHER_AES_192_GCM;
            break;
        case TCipher::AES_256_GCM:
            return POLARSSL_CIPHER_AES_256_GCM;
            break;
        case TCipher::CAMELLIA_128_ECB:
            return POLARSSL_CIPHER_CAMELLIA_128_ECB;
            break;
        case TCipher::CAMELLIA_192_ECB:
            return POLARSSL_CIPHER_CAMELLIA_192_ECB;
            break;
        case TCipher::CAMELLIA_256_ECB:
            return POLARSSL_CIPHER_CAMELLIA_256_ECB;
            break;
        case TCipher::CAMELLIA_128_CBC:
            return POLARSSL_CIPHER_CAMELLIA_128_CBC;
            break;
        case TCipher::CAMELLIA_192_CBC:
            return POLARSSL_CIPHER_CAMELLIA_192_CBC;
            break;
        case TCipher::CAMELLIA_256_CBC:
            return POLARSSL_CIPHER_CAMELLIA_256_CBC;
            break;
        case TCipher::CAMELLIA_128_CFB128:
            return POLARSSL_CIPHER_CAMELLIA_128_CFB128;
            break;
        case TCipher::CAMELLIA_192_CFB128:
            return POLARSSL_CIPHER_CAMELLIA_192_CFB128;
            break;
        case TCipher::CAMELLIA_256_CFB128:
            return POLARSSL_CIPHER_CAMELLIA_256_CFB128;
            break;
        case TCipher::CAMELLIA_128_CTR:
            return POLARSSL_CIPHER_CAMELLIA_128_CTR;
            break;
        case TCipher::CAMELLIA_192_CTR:
            return POLARSSL_CIPHER_CAMELLIA_192_CTR;
            break;
        case TCipher::CAMELLIA_256_CTR:
            return POLARSSL_CIPHER_CAMELLIA_256_CTR;
            break;
        case TCipher::CAMELLIA_128_GCM:
            return POLARSSL_CIPHER_CAMELLIA_128_GCM;
            break;
        case TCipher::CAMELLIA_192_GCM:
            return POLARSSL_CIPHER_CAMELLIA_192_GCM;
            break;
        case TCipher::CAMELLIA_256_GCM:
            return POLARSSL_CIPHER_CAMELLIA_256_GCM;
            break;
        case TCipher::DES_ECB:
            return POLARSSL_CIPHER_DES_ECB;
            break;
        case TCipher::DES_CBC:
            return POLARSSL_CIPHER_DES_CBC;
            break;
        case TCipher::DES_EDE_ECB:
            return POLARSSL_CIPHER_DES_EDE_ECB;
            break;
        case TCipher::DES_EDE_CBC:
            return POLARSSL_CIPHER_DES_EDE_CBC;
            break;
        case TCipher::DES_EDE3_ECB:
            return POLARSSL_CIPHER_DES_EDE3_ECB;
            break;
        case TCipher::DES_EDE3_CBC:
            return POLARSSL_CIPHER_DES_EDE3_CBC;
            break;
        case TCipher::BLOWFISH_ECB:
            return POLARSSL_CIPHER_BLOWFISH_ECB;
            break;
        case TCipher::BLOWFISH_CBC:
            return POLARSSL_CIPHER_BLOWFISH_CBC;
            break;
        case TCipher::BLOWFISH_CFB64:
            return POLARSSL_CIPHER_BLOWFISH_CFB64;
            break;
        case TCipher::BLOWFISH_CTR:
            return POLARSSL_CIPHER_BLOWFISH_CTR;
            break;
        case TCipher::ARC4_128:
            return POLARSSL_CIPHER_ARC4_128;
            break;
        case TCipher::AES_128_CCM:
            return POLARSSL_CIPHER_AES_128_CCM;
            break;
        case TCipher::AES_192_CCM:
            return POLARSSL_CIPHER_AES_192_CCM;
            break;
        case TCipher::AES_256_CCM:
            return POLARSSL_CIPHER_AES_256_CCM;
            break;
        case TCipher::CAMELLIA_128_CCM:
            return POLARSSL_CIPHER_CAMELLIA_128_CCM;
            break;
        case TCipher::CAMELLIA_192_CCM:
            return POLARSSL_CIPHER_CAMELLIA_192_CCM;
            break;
        case TCipher::CAMELLIA_256_CCM:
            return POLARSSL_CIPHER_CAMELLIA_256_CCM;
            break;

        default:
            break;
        }

        return POLARSSL_CIPHER_NONE;
    }

    static auto     fromPolar(cipher_type_t t) -> TCipher {
        switch ( t ) {
        case POLARSSL_CIPHER_NONE:
        case POLARSSL_CIPHER_NULL:
            return TCipher::NONE;
            break;
        case POLARSSL_CIPHER_AES_128_ECB:
            return TCipher::AES_128_ECB;
            break;
        case POLARSSL_CIPHER_AES_192_ECB:
            return TCipher::AES_192_ECB;
            break;
        case POLARSSL_CIPHER_AES_256_ECB:
            return TCipher::AES_256_ECB;
            break;
        case POLARSSL_CIPHER_AES_128_CBC:
            return TCipher::AES_128_CBC;
            break;
        case POLARSSL_CIPHER_AES_192_CBC:
            return TCipher::AES_192_CBC;
            break;
        case POLARSSL_CIPHER_AES_256_CBC:
            return TCipher::AES_256_CBC;
            break;
        case POLARSSL_CIPHER_AES_128_CFB128:
            return TCipher::AES_128_CFB128;
            break;
        case POLARSSL_CIPHER_AES_192_CFB128:
            return TCipher::AES_192_CFB128;
            break;
        case POLARSSL_CIPHER_AES_256_CFB128:
            return TCipher::AES_256_CFB128;
            break;
        case POLARSSL_CIPHER_AES_128_CTR:
            return TCipher::AES_128_CTR;
            break;
        case POLARSSL_CIPHER_AES_192_CTR:
            return TCipher::AES_192_CTR;
            break;
        case POLARSSL_CIPHER_AES_256_CTR:
            return TCipher::AES_256_CTR;
            break;
        case POLARSSL_CIPHER_AES_128_GCM:
            return TCipher::AES_128_GCM;
            break;
        case POLARSSL_CIPHER_AES_192_GCM:
            return TCipher::AES_192_GCM;
            break;
        case POLARSSL_CIPHER_AES_256_GCM:
            return TCipher::AES_256_GCM;
            break;
        case POLARSSL_CIPHER_CAMELLIA_128_ECB:
            return TCipher::CAMELLIA_128_ECB;
            break;
        case POLARSSL_CIPHER_CAMELLIA_192_ECB:
            return TCipher::CAMELLIA_192_ECB;
            break;
        case POLARSSL_CIPHER_CAMELLIA_256_ECB:
            return TCipher::CAMELLIA_256_ECB;
            break;
        case POLARSSL_CIPHER_CAMELLIA_128_CBC:
            return TCipher::CAMELLIA_128_CBC;
            break;
        case POLARSSL_CIPHER_CAMELLIA_192_CBC:
            return TCipher::CAMELLIA_192_CBC;
            break;
        case POLARSSL_CIPHER_CAMELLIA_256_CBC:
            return TCipher::CAMELLIA_256_CBC;
            break;
        case POLARSSL_CIPHER_CAMELLIA_128_CFB128:
            return TCipher::CAMELLIA_128_CFB128;
            break;
        case POLARSSL_CIPHER_CAMELLIA_192_CFB128:
            return TCipher::CAMELLIA_192_CFB128;
            break;
        case POLARSSL_CIPHER_CAMELLIA_256_CFB128:
            return TCipher::CAMELLIA_256_CFB128;
            break;
        case POLARSSL_CIPHER_CAMELLIA_128_CTR:
            return TCipher::CAMELLIA_128_CTR;
            break;
        case POLARSSL_CIPHER_CAMELLIA_192_CTR:
            return TCipher::CAMELLIA_192_CTR;
            break;
        case POLARSSL_CIPHER_CAMELLIA_256_CTR:
            return TCipher::CAMELLIA_256_CTR;
            break;
        case POLARSSL_CIPHER_CAMELLIA_128_GCM:
            return TCipher::CAMELLIA_128_GCM;
            break;
        case POLARSSL_CIPHER_CAMELLIA_192_GCM:
            return TCipher::CAMELLIA_192_GCM;
            break;
        case POLARSSL_CIPHER_CAMELLIA_256_GCM:
            return TCipher::CAMELLIA_256_GCM;
            break;
        case POLARSSL_CIPHER_DES_ECB:
            return TCipher::DES_ECB;
            break;
        case POLARSSL_CIPHER_DES_CBC:
            return TCipher::DES_CBC;
            break;
        case POLARSSL_CIPHER_DES_EDE_ECB:
            return TCipher::DES_EDE_ECB;
            break;
        case POLARSSL_CIPHER_DES_EDE_CBC:
            return TCipher::DES_EDE_CBC;
            break;
        case POLARSSL_CIPHER_DES_EDE3_ECB:
            return TCipher::DES_EDE3_ECB;
            break;
        case POLARSSL_CIPHER_DES_EDE3_CBC:
            return TCipher::DES_EDE3_CBC;
            break;
        case POLARSSL_CIPHER_BLOWFISH_ECB:
            return TCipher::BLOWFISH_ECB;
            break;
        case POLARSSL_CIPHER_BLOWFISH_CBC:
            return TCipher::BLOWFISH_CBC;
            break;
        case POLARSSL_CIPHER_BLOWFISH_CFB64:
            return TCipher::BLOWFISH_CFB64;
            break;
        case POLARSSL_CIPHER_BLOWFISH_CTR:
            return TCipher::BLOWFISH_CTR;
            break;
        case POLARSSL_CIPHER_ARC4_128:
            return TCipher::ARC4_128;
            break;
        case POLARSSL_CIPHER_AES_128_CCM:
            return TCipher::AES_128_CCM;
            break;
        case POLARSSL_CIPHER_AES_192_CCM:
            return TCipher::AES_192_CCM;
            break;
        case POLARSSL_CIPHER_AES_256_CCM:
            return TCipher::AES_256_CCM;
            break;
        case POLARSSL_CIPHER_CAMELLIA_128_CCM:
            return TCipher::CAMELLIA_128_CCM;
            break;
        case POLARSSL_CIPHER_CAMELLIA_192_CCM:
            return TCipher::CAMELLIA_192_CCM;
            break;
        case POLARSSL_CIPHER_CAMELLIA_256_CCM:
            return TCipher::CAMELLIA_256_CCM;
            break;

        default:
            break;
        }

        return TCipher::NONE;
    }

    static auto     toPolar(TPadding p) -> cipher_padding_t {
        switch ( p ) {
        case TPadding::PKCS7:
            return POLARSSL_PADDING_PKCS7;
            break;

        case TPadding::ONE_AND_ZEROS:
            return POLARSSL_PADDING_ONE_AND_ZEROS;
            break;

        case TPadding::ZEROS_AND_LEN:
            return POLARSSL_PADDING_ZEROS_AND_LEN;
            break;

        case TPadding::ZEROS:
            return POLARSSL_PADDING_ZEROS;
            break;

        case TPadding::NONE:
            return POLARSSL_PADDING_NONE;
            break;
        }

        return POLARSSL_PADDING_NONE;
    }

    static auto     fromPolar(cipher_padding_t c) -> TPadding {
        switch ( c ) {
        case POLARSSL_PADDING_PKCS7:
            return TPadding::PKCS7;
            break;
        case POLARSSL_PADDING_ONE_AND_ZEROS:
            return TPadding::ONE_AND_ZEROS;
            break;
        case POLARSSL_PADDING_ZEROS_AND_LEN:
            return TPadding::ZEROS_AND_LEN;
            break;
        case POLARSSL_PADDING_ZEROS:
            return TPadding::ZEROS;
            break;
        case POLARSSL_PADDING_NONE:
            return TPadding::NONE;
            break;
        }

        return TPadding::NONE;
    }
};

///////////////////////////////////////////////////////////////////////////////
} // namespace qpolarssl
///////////////////////////////////////////////////////////////////////////////
#endif // define QPOLARSSL_TYPES_HPP
