/** @file qpolarsslcipher_priv.hpp
  * Qt wrapper class around polarssl functions
  *
  * @copyright (C) 2015, azadkuh
  * @date 2015.02.08
  * @version 1.0.0
  * @author amir zamani <azadkuh@live.com>
  *
 */

#ifndef QMBEDTLS_CIPHER_PRIV_HPP
#define QMBEDTLS_CIPHER_PRIV_HPP

#include "mbedtls/cipher.h"
#include <QByteArray>
///////////////////////////////////////////////////////////////////////////////
namespace qpolarssl {
namespace priv {
///////////////////////////////////////////////////////////////////////////////
class Cipher
{
public:
    explicit        Cipher(mbedtls_cipher_type_t t) {
        auto inf = mbedtls_cipher_info_from_type(t);

        if ( inf != nullptr ) {
            itype = t;
            mbedtls_cipher_setup(context(), inf);
        }
    }

    explicit        Cipher(const char* name) {
        auto inf = mbedtls_cipher_info_from_string(name);
        if ( inf != nullptr ) {
            itype = inf->type;
            mbedtls_cipher_setup(context(), inf);
        }
    }

    virtual        ~Cipher() {
        mbedtls_cipher_free(context());
    }

    bool            reset() {
        return mbedtls_cipher_reset(context()) == 0;
    }

    bool            isValid()const {
        return itype != MBEDTLS_CIPHER_NONE &&  itype != MBEDTLS_CIPHER_NULL;
    }

    auto            info()const -> const mbedtls_cipher_info_t*{
        return mbedtls_cipher_info_from_type(itype);
    }

    auto            context() -> mbedtls_cipher_context_t* {
        return &ictx;
    }

    auto            operator()(const QByteArray& message,
                               mbedtls_cipher_padding_t padding = MBEDTLS_PADDING_PKCS7) -> QByteArray {
        if ( !isValid() )
            return QByteArray();

        reset();

        int nRet = mbedtls_cipher_set_padding_mode(context(), padding);
        if ( nRet != 0 ) {
            qDebug("cipher padding had not been set. error: %d", nRet);
            return QByteArray();
        }

        const mbedtls_cipher_info_t* cinfo = info();

        QByteArray result;
        result.resize(message.length() + cinfo->block_size + 32);

        uint8_t* outBuffer = reinterpret_cast<uint8_t*>(result.data());
        size_t   outLength = 0;
        nRet = mbedtls_cipher_update(context(),
                                     reinterpret_cast<const uint8_t*>(message.constData()),
                                     message.length(),
                                     outBuffer,
                                     &outLength
                                     );
        if ( nRet != 0 ) {
            qDebug("cipher_update failed. error: %d", nRet);
            return QByteArray();
        }

        size_t totalLength = outLength;
        nRet = mbedtls_cipher_finish(context(),
                                     outBuffer + outLength,
                                     &outLength
                                     );
        if ( nRet != 0 ) {
            qDebug("cipher_finish failed. error: %d", nRet);
            return QByteArray();
        }

        totalLength += outLength;

        return result.left(totalLength);
    }

public:
    int             setKey(const QByteArray& key, mbedtls_operation_t operation = MBEDTLS_ENCRYPT) {
        return mbedtls_cipher_setkey(context(),
                                     reinterpret_cast<const uint8_t*>(key.constData()),
                                     key.length() << 3, // in bit
                                     operation
                                     );
    }

    int             setIv(const QByteArray& nonce) {
        return mbedtls_cipher_set_iv(context(),
                                     reinterpret_cast<const uint8_t*>(nonce.constData()),
                                     nonce.length()
                                     );
    }

protected:
    Q_DISABLE_COPY(Cipher)

    mbedtls_cipher_type_t       itype  = MBEDTLS_CIPHER_NONE;
    mbedtls_cipher_context_t    ictx;
};

///////////////////////////////////////////////////////////////////////////////
} // namespace priv
} // namespace polarssl
///////////////////////////////////////////////////////////////////////////////
#endif // QMBEDTLS_CIPHER_PRIV_HPP
