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
#include <mbedtls/md.h>
#include <mbedtls/cipher.h>
#include <mbedtls/pk.h>
///////////////////////////////////////////////////////////////////////////////
namespace qpolarssl {
///////////////////////////////////////////////////////////////////////////////
class Conversion
{
public:
    static auto     toPolar(THash h) -> mbedtls_md_type_t {
        switch ( h ) {
        case THash::NONE:
            return MBEDTLS_MD_NONE;
            break;
        case THash::MD2:
            return MBEDTLS_MD_MD2;
            break;
        case THash::MD4:
            return MBEDTLS_MD_MD4;
            break;
        case THash::MD5:
            return MBEDTLS_MD_MD5;
            break;
        case THash::SHA1:
            return MBEDTLS_MD_SHA1;
            break;
        case THash::SHA224:
            return MBEDTLS_MD_SHA224;
            break;
        case THash::SHA256:
            return MBEDTLS_MD_SHA256;
            break;
        case THash::SHA384:
            return MBEDTLS_MD_SHA384;
            break;
        case THash::SHA512:
            return MBEDTLS_MD_SHA512;
            break;
        case THash::RIPEMD160:
            return MBEDTLS_MD_RIPEMD160;
            break;
        default:
            break;
        }

        return MBEDTLS_MD_NONE;
    }

    static auto     fromPolar(mbedtls_md_type_t t) -> THash {
        switch ( t ) {
        case MBEDTLS_MD_NONE:
            return THash::NONE;
            break;
        case MBEDTLS_MD_MD2:
            return THash::MD2;
            break;
        case MBEDTLS_MD_MD4:
            return THash::MD4;
            break;
        case MBEDTLS_MD_MD5:
            return THash::MD5;
            break;
        case MBEDTLS_MD_SHA1:
            return THash::SHA1;
            break;
        case MBEDTLS_MD_SHA224:
            return THash::SHA224;
            break;
        case MBEDTLS_MD_SHA256:
            return THash::SHA256;
            break;
        case MBEDTLS_MD_SHA384:
            return THash::SHA384;
            break;
        case MBEDTLS_MD_SHA512:
            return THash::SHA512;
            break;
        case MBEDTLS_MD_RIPEMD160:
            return THash::RIPEMD160;
            break;
        }

        return THash::NONE;
    }

    static auto     toPolar(TCipher c) -> mbedtls_cipher_type_t {
        switch ( c ) {
        case TCipher::NONE:
            return MBEDTLS_CIPHER_NONE;
            break;
        case TCipher::AES_128_ECB:
            return MBEDTLS_CIPHER_AES_128_ECB;
            break;
        case TCipher::AES_192_ECB:
            return MBEDTLS_CIPHER_AES_192_ECB;
            break;
        case TCipher::AES_256_ECB:
            return MBEDTLS_CIPHER_AES_256_ECB;
            break;
        case TCipher::AES_128_CBC:
            return MBEDTLS_CIPHER_AES_128_CBC;
            break;
        case TCipher::AES_192_CBC:
            return MBEDTLS_CIPHER_AES_192_CBC;
            break;
        case TCipher::AES_256_CBC:
            return MBEDTLS_CIPHER_AES_256_CBC;
            break;
        case TCipher::AES_128_CFB128:
            return MBEDTLS_CIPHER_AES_128_CFB128;
            break;
        case TCipher::AES_192_CFB128:
            return MBEDTLS_CIPHER_AES_192_CFB128;
            break;
        case TCipher::AES_256_CFB128:
            return MBEDTLS_CIPHER_AES_256_CFB128;
            break;
        case TCipher::AES_128_CTR:
            return MBEDTLS_CIPHER_AES_128_CTR;
            break;
        case TCipher::AES_192_CTR:
            return MBEDTLS_CIPHER_AES_192_CTR;
            break;
        case TCipher::AES_256_CTR:
            return MBEDTLS_CIPHER_AES_256_CTR;
            break;
        case TCipher::AES_128_GCM:
            return MBEDTLS_CIPHER_AES_128_GCM;
            break;
        case TCipher::AES_192_GCM:
            return MBEDTLS_CIPHER_AES_192_GCM;
            break;
        case TCipher::AES_256_GCM:
            return MBEDTLS_CIPHER_AES_256_GCM;
            break;
        case TCipher::CAMELLIA_128_ECB:
            return MBEDTLS_CIPHER_CAMELLIA_128_ECB;
            break;
        case TCipher::CAMELLIA_192_ECB:
            return MBEDTLS_CIPHER_CAMELLIA_192_ECB;
            break;
        case TCipher::CAMELLIA_256_ECB:
            return MBEDTLS_CIPHER_CAMELLIA_256_ECB;
            break;
        case TCipher::CAMELLIA_128_CBC:
            return MBEDTLS_CIPHER_CAMELLIA_128_CBC;
            break;
        case TCipher::CAMELLIA_192_CBC:
            return MBEDTLS_CIPHER_CAMELLIA_192_CBC;
            break;
        case TCipher::CAMELLIA_256_CBC:
            return MBEDTLS_CIPHER_CAMELLIA_256_CBC;
            break;
        case TCipher::CAMELLIA_128_CFB128:
            return MBEDTLS_CIPHER_CAMELLIA_128_CFB128;
            break;
        case TCipher::CAMELLIA_192_CFB128:
            return MBEDTLS_CIPHER_CAMELLIA_192_CFB128;
            break;
        case TCipher::CAMELLIA_256_CFB128:
            return MBEDTLS_CIPHER_CAMELLIA_256_CFB128;
            break;
        case TCipher::CAMELLIA_128_CTR:
            return MBEDTLS_CIPHER_CAMELLIA_128_CTR;
            break;
        case TCipher::CAMELLIA_192_CTR:
            return MBEDTLS_CIPHER_CAMELLIA_192_CTR;
            break;
        case TCipher::CAMELLIA_256_CTR:
            return MBEDTLS_CIPHER_CAMELLIA_256_CTR;
            break;
        case TCipher::CAMELLIA_128_GCM:
            return MBEDTLS_CIPHER_CAMELLIA_128_GCM;
            break;
        case TCipher::CAMELLIA_192_GCM:
            return MBEDTLS_CIPHER_CAMELLIA_192_GCM;
            break;
        case TCipher::CAMELLIA_256_GCM:
            return MBEDTLS_CIPHER_CAMELLIA_256_GCM;
            break;
        case TCipher::DES_ECB:
            return MBEDTLS_CIPHER_DES_ECB;
            break;
        case TCipher::DES_CBC:
            return MBEDTLS_CIPHER_DES_CBC;
            break;
        case TCipher::DES_EDE_ECB:
            return MBEDTLS_CIPHER_DES_EDE_ECB;
            break;
        case TCipher::DES_EDE_CBC:
            return MBEDTLS_CIPHER_DES_EDE_CBC;
            break;
        case TCipher::DES_EDE3_ECB:
            return MBEDTLS_CIPHER_DES_EDE3_ECB;
            break;
        case TCipher::DES_EDE3_CBC:
            return MBEDTLS_CIPHER_DES_EDE3_CBC;
            break;
        case TCipher::BLOWFISH_ECB:
            return MBEDTLS_CIPHER_BLOWFISH_ECB;
            break;
        case TCipher::BLOWFISH_CBC:
            return MBEDTLS_CIPHER_BLOWFISH_CBC;
            break;
        case TCipher::BLOWFISH_CFB64:
            return MBEDTLS_CIPHER_BLOWFISH_CFB64;
            break;
        case TCipher::BLOWFISH_CTR:
            return MBEDTLS_CIPHER_BLOWFISH_CTR;
            break;
        case TCipher::ARC4_128:
            return MBEDTLS_CIPHER_ARC4_128;
            break;
        case TCipher::AES_128_CCM:
            return MBEDTLS_CIPHER_AES_128_CCM;
            break;
        case TCipher::AES_192_CCM:
            return MBEDTLS_CIPHER_AES_192_CCM;
            break;
        case TCipher::AES_256_CCM:
            return MBEDTLS_CIPHER_AES_256_CCM;
            break;
        case TCipher::CAMELLIA_128_CCM:
            return MBEDTLS_CIPHER_CAMELLIA_128_CCM;
            break;
        case TCipher::CAMELLIA_192_CCM:
            return MBEDTLS_CIPHER_CAMELLIA_192_CCM;
            break;
        case TCipher::CAMELLIA_256_CCM:
            return MBEDTLS_CIPHER_CAMELLIA_256_CCM;
            break;

        default:
            break;
        }

        return MBEDTLS_CIPHER_NONE;
    }

    static auto     fromPolar(mbedtls_cipher_type_t t) -> TCipher {
        switch ( t ) {
        case MBEDTLS_CIPHER_NONE:
        case MBEDTLS_CIPHER_NULL:
            return TCipher::NONE;
            break;
        case MBEDTLS_CIPHER_AES_128_ECB:
            return TCipher::AES_128_ECB;
            break;
        case MBEDTLS_CIPHER_AES_192_ECB:
            return TCipher::AES_192_ECB;
            break;
        case MBEDTLS_CIPHER_AES_256_ECB:
            return TCipher::AES_256_ECB;
            break;
        case MBEDTLS_CIPHER_AES_128_CBC:
            return TCipher::AES_128_CBC;
            break;
        case MBEDTLS_CIPHER_AES_192_CBC:
            return TCipher::AES_192_CBC;
            break;
        case MBEDTLS_CIPHER_AES_256_CBC:
            return TCipher::AES_256_CBC;
            break;
        case MBEDTLS_CIPHER_AES_128_CFB128:
            return TCipher::AES_128_CFB128;
            break;
        case MBEDTLS_CIPHER_AES_192_CFB128:
            return TCipher::AES_192_CFB128;
            break;
        case MBEDTLS_CIPHER_AES_256_CFB128:
            return TCipher::AES_256_CFB128;
            break;
        case MBEDTLS_CIPHER_AES_128_CTR:
            return TCipher::AES_128_CTR;
            break;
        case MBEDTLS_CIPHER_AES_192_CTR:
            return TCipher::AES_192_CTR;
            break;
        case MBEDTLS_CIPHER_AES_256_CTR:
            return TCipher::AES_256_CTR;
            break;
        case MBEDTLS_CIPHER_AES_128_GCM:
            return TCipher::AES_128_GCM;
            break;
        case MBEDTLS_CIPHER_AES_192_GCM:
            return TCipher::AES_192_GCM;
            break;
        case MBEDTLS_CIPHER_AES_256_GCM:
            return TCipher::AES_256_GCM;
            break;
        case MBEDTLS_CIPHER_CAMELLIA_128_ECB:
            return TCipher::CAMELLIA_128_ECB;
            break;
        case MBEDTLS_CIPHER_CAMELLIA_192_ECB:
            return TCipher::CAMELLIA_192_ECB;
            break;
        case MBEDTLS_CIPHER_CAMELLIA_256_ECB:
            return TCipher::CAMELLIA_256_ECB;
            break;
        case MBEDTLS_CIPHER_CAMELLIA_128_CBC:
            return TCipher::CAMELLIA_128_CBC;
            break;
        case MBEDTLS_CIPHER_CAMELLIA_192_CBC:
            return TCipher::CAMELLIA_192_CBC;
            break;
        case MBEDTLS_CIPHER_CAMELLIA_256_CBC:
            return TCipher::CAMELLIA_256_CBC;
            break;
        case MBEDTLS_CIPHER_CAMELLIA_128_CFB128:
            return TCipher::CAMELLIA_128_CFB128;
            break;
        case MBEDTLS_CIPHER_CAMELLIA_192_CFB128:
            return TCipher::CAMELLIA_192_CFB128;
            break;
        case MBEDTLS_CIPHER_CAMELLIA_256_CFB128:
            return TCipher::CAMELLIA_256_CFB128;
            break;
        case MBEDTLS_CIPHER_CAMELLIA_128_CTR:
            return TCipher::CAMELLIA_128_CTR;
            break;
        case MBEDTLS_CIPHER_CAMELLIA_192_CTR:
            return TCipher::CAMELLIA_192_CTR;
            break;
        case MBEDTLS_CIPHER_CAMELLIA_256_CTR:
            return TCipher::CAMELLIA_256_CTR;
            break;
        case MBEDTLS_CIPHER_CAMELLIA_128_GCM:
            return TCipher::CAMELLIA_128_GCM;
            break;
        case MBEDTLS_CIPHER_CAMELLIA_192_GCM:
            return TCipher::CAMELLIA_192_GCM;
            break;
        case MBEDTLS_CIPHER_CAMELLIA_256_GCM:
            return TCipher::CAMELLIA_256_GCM;
            break;
        case MBEDTLS_CIPHER_DES_ECB:
            return TCipher::DES_ECB;
            break;
        case MBEDTLS_CIPHER_DES_CBC:
            return TCipher::DES_CBC;
            break;
        case MBEDTLS_CIPHER_DES_EDE_ECB:
            return TCipher::DES_EDE_ECB;
            break;
        case MBEDTLS_CIPHER_DES_EDE_CBC:
            return TCipher::DES_EDE_CBC;
            break;
        case MBEDTLS_CIPHER_DES_EDE3_ECB:
            return TCipher::DES_EDE3_ECB;
            break;
        case MBEDTLS_CIPHER_DES_EDE3_CBC:
            return TCipher::DES_EDE3_CBC;
            break;
        case MBEDTLS_CIPHER_BLOWFISH_ECB:
            return TCipher::BLOWFISH_ECB;
            break;
        case MBEDTLS_CIPHER_BLOWFISH_CBC:
            return TCipher::BLOWFISH_CBC;
            break;
        case MBEDTLS_CIPHER_BLOWFISH_CFB64:
            return TCipher::BLOWFISH_CFB64;
            break;
        case MBEDTLS_CIPHER_BLOWFISH_CTR:
            return TCipher::BLOWFISH_CTR;
            break;
        case MBEDTLS_CIPHER_ARC4_128:
            return TCipher::ARC4_128;
            break;
        case MBEDTLS_CIPHER_AES_128_CCM:
            return TCipher::AES_128_CCM;
            break;
        case MBEDTLS_CIPHER_AES_192_CCM:
            return TCipher::AES_192_CCM;
            break;
        case MBEDTLS_CIPHER_AES_256_CCM:
            return TCipher::AES_256_CCM;
            break;
        case MBEDTLS_CIPHER_CAMELLIA_128_CCM:
            return TCipher::CAMELLIA_128_CCM;
            break;
        case MBEDTLS_CIPHER_CAMELLIA_192_CCM:
            return TCipher::CAMELLIA_192_CCM;
            break;
        case MBEDTLS_CIPHER_CAMELLIA_256_CCM:
            return TCipher::CAMELLIA_256_CCM;
            break;

        default:
            break;
        }

        return TCipher::NONE;
    }

    static auto     toPolar(TPadding p) -> mbedtls_cipher_padding_t {
        switch ( p ) {
        case TPadding::PKCS7:
            return MBEDTLS_PADDING_PKCS7;
            break;

        case TPadding::ONE_AND_ZEROS:
            return MBEDTLS_PADDING_ONE_AND_ZEROS;
            break;

        case TPadding::ZEROS_AND_LEN:
            return MBEDTLS_PADDING_ZEROS_AND_LEN;
            break;

        case TPadding::ZEROS:
            return MBEDTLS_PADDING_ZEROS;
            break;

        case TPadding::NONE:
            return MBEDTLS_PADDING_NONE;
            break;
        }

        return MBEDTLS_PADDING_NONE;
    }

    static auto     fromPolar(mbedtls_cipher_padding_t c) -> TPadding {
        switch ( c ) {
        case MBEDTLS_PADDING_PKCS7:
            return TPadding::PKCS7;
            break;
        case MBEDTLS_PADDING_ONE_AND_ZEROS:
            return TPadding::ONE_AND_ZEROS;
            break;
        case MBEDTLS_PADDING_ZEROS_AND_LEN:
            return TPadding::ZEROS_AND_LEN;
            break;
        case MBEDTLS_PADDING_ZEROS:
            return TPadding::ZEROS;
            break;
        case MBEDTLS_PADDING_NONE:
            return TPadding::NONE;
            break;
        }

        return TPadding::NONE;
    }

    static auto     toPolar(TPki p) -> mbedtls_pk_type_t {
        switch ( p ) {
        case TPki::NONE:
            return MBEDTLS_PK_NONE;
            break;
        case TPki::RSA:
            return MBEDTLS_PK_RSA;
            break;
        case TPki::ECKEY:
            return MBEDTLS_PK_ECKEY;
            break;
        case TPki::ECKEY_DH:
            return MBEDTLS_PK_ECKEY_DH;
            break;
        case TPki::ECDSA:
            return MBEDTLS_PK_ECDSA;
            break;
        case TPki::RSA_ALT:
            return MBEDTLS_PK_RSA_ALT;
            break;
        case TPki::RSASSA_PSS:
            return MBEDTLS_PK_RSASSA_PSS;
            break;

        default:
            break;
        }

        return MBEDTLS_PK_NONE;
    }

    static auto     fromPolar(mbedtls_pk_type_t p) -> TPki {
        switch ( p ) {
        case MBEDTLS_PK_NONE:
            return TPki::NONE;
            break;
        case MBEDTLS_PK_RSA:
            return TPki::RSA;
            break;
        case MBEDTLS_PK_ECKEY:
            return TPki::ECKEY;
            break;
        case MBEDTLS_PK_ECKEY_DH:
            return TPki::ECKEY_DH;
            break;
        case MBEDTLS_PK_ECDSA:
            return TPki::ECDSA;
            break;
        case MBEDTLS_PK_RSA_ALT:
            return TPki::RSA_ALT;
            break;
        case MBEDTLS_PK_RSASSA_PSS:
            return TPki::RSASSA_PSS;
            break;

        default:
            break;
        }

        return TPki::NONE;
    }
};

///////////////////////////////////////////////////////////////////////////////
} // namespace qpolarssl
///////////////////////////////////////////////////////////////////////////////
#endif // define QPOLARSSL_TYPES_HPP
