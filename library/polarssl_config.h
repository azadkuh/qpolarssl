/** @file polarssl-config.h
  * polarssl configuration
  *
  * @copyright (C) 2015, azadkuh
  * @date 2015.02.08
  * @version 1.0.0
  * @author amir zamani <azadkuh@live.com>
  *
 */

#ifndef __POLARSSSL_CONGIH_H__
#define __POLARSSSL_CONGIH_H__
///////////////////////////////////////////////////////////////////////////////

// base
#define POLARSSL_BASE64_C

// hash
#define POLARSSL_MD4_C
#define POLARSSL_MD5_C
#define POLARSSL_SHA1_C
#define POLARSSL_SHA256_C
#define POLARSSL_SHA512_C
#define POLARSSL_MD_C

// cipher
#define POLARSSL_CIPHER_MODE_CBC
#define POLARSSL_CIPHER_MODE_WITH_PADDING
#define POLARSSL_CIPHER_PADDING_PKCS7
#define POLARSSL_CIPHER_PADDING_ONE_AND_ZEROS
#define POLARSSL_CIPHER_PADDING_ZEROS_AND_LEN
#define POLARSSL_CIPHER_PADDING_ZEROS

#define POLARSSL_HAVE_ASM
#define POLARSSL_CIPHER_C
#define POLARSSL_DES_C
#define POLARSSL_PADLOCK_C
#define POLARSSL_BLOWFISH_C
#define POLARSSL_AES_C
#define POLARSSL_AESNI_C

// random number generator and entropy
#define POLARSSL_CTR_DRBG_C
#define POLARSSL_ENTROPY_C

// PKI cryptography
#define POLARSSL_PK_C
#define POLARSSL_RSA_C
#define POLARSSL_BIGNUM_C
#define POLARSSL_OID_C
#define POLARSSL_PEM_PARSE_C
#define POLARSSL_PK_PARSE_C
#define POLARSSL_ASN1_PARSE_C
#define POLARSSL_PKCS1_V15
#define POLARSSL_PKCS1_V21


#include "polarssl/check_config.h"
///////////////////////////////////////////////////////////////////////////////
#endif // __POLARSSSL_CONGIH_H__
