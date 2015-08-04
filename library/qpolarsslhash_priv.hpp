/** @file qpolarsslhash_priv.hpp
  * Qt wrapper class around polarssl functions
  *
  * @copyright (C) 2015, azadkuh
  * @date 2015.02.12
  * @version 1.0.0
  * @author amir zamani <azadkuh@live.com>
  *
 */

#ifndef QMBEDTLS_HASH_PRIV_HPP
#define QMBEDTLS_HASH_PRIV_HPP

#include "mbedtls_config.h"
#include "mbedtls/md.h"

#include <QByteArray>
#include <QFile>
///////////////////////////////////////////////////////////////////////////////
namespace qpolarssl {
namespace priv {
///////////////////////////////////////////////////////////////////////////////
class Hash
{
public:
    static auto     hash(const QByteArray& in,
                         mbedtls_md_type_t type = MBEDTLS_MD_SHA1) -> QByteArray {
        auto minfo = mbedtls_md_info_from_type(type);
        return makeHash(in, minfo);
    }

    static auto     hash(const QByteArray &in,
                         const char* name) -> QByteArray {
        auto minfo = mbedtls_md_info_from_string(name);
        return makeHash(in, minfo);
    }

    static auto     fileHash(const QString& filePath,
                             mbedtls_md_type_t type = MBEDTLS_MD_SHA1) -> QByteArray {
        auto minfo = mbedtls_md_info_from_type(type);
        return makeFileHash(filePath, minfo);
    }

    static auto     fileHash(const QString& filePath,
                             const char* name) -> QByteArray {
        auto minfo = mbedtls_md_info_from_string(name);
        return makeFileHash(filePath, minfo);
    }

    static auto     hmac(const QByteArray& key,
                         const QByteArray& message,
                         mbedtls_md_type_t type = MBEDTLS_MD_SHA1) -> QByteArray {
        auto minfo = mbedtls_md_info_from_type(type);
        return makeHmac(key, message, minfo);
    }

    static auto     hmac(const QByteArray& key,
                         const QByteArray& message,
                         const char* name) -> QByteArray {
        auto minfo = mbedtls_md_info_from_string(name);
        return makeHmac(key, message, minfo);
    }

public:
    explicit        Hash(mbedtls_md_type_t t) {
        auto minfo = mbedtls_md_info_from_type(t);
        if ( minfo != nullptr ) {
            itype   = t;
            mbedtls_md_init_ctx(context(), minfo);
        }
    }

    explicit        Hash(const char* name) {
        auto minfo = mbedtls_md_info_from_string(name);
        if ( minfo != nullptr ) {
            itype = mbedtls_md_get_type(minfo);
            mbedtls_md_init_ctx(context(), minfo);
        }
    }

    virtual        ~Hash() {
        mbedtls_md_free(context());
    }

    auto            context() -> mbedtls_md_context_t* {
        return &ictx;
    }

    bool            isValid()const {
        return itype != MBEDTLS_MD_NONE;
    }

    auto            info()const -> const mbedtls_md_info_t* {
        return mbedtls_md_info_from_type(itype);
    }

    int             start() {
        return mbedtls_md_starts(context());
    }

    int             update(const uint8_t* input, size_t length) {
        return mbedtls_md_update(context(), input, length);
    }

    int             update(const QByteArray& input) {
        return mbedtls_md_update(context(),
                                 reinterpret_cast<const uint8_t*>(input.constData()),
                                 input.length()
                                 );
    }

    auto            finish() -> QByteArray {
        QByteArray result;

        auto minfo = mbedtls_md_info_from_type(itype);
        Q_ASSERT( minfo != nullptr );

        if ( minfo != nullptr ) {
            result.resize( mbedtls_md_get_size(minfo) );
            int nRet = mbedtls_md_finish(context(),
                                         reinterpret_cast<uint8_t*>(result.data())
                                         );
            return (nRet == 0) ? result : QByteArray();
        }

        return result;
    }

    int             hmacStart(const QByteArray& key = QByteArray()) {
        mbedtls_md_hmac_reset(context());
        if ( key.length() > 0 ) {
            return mbedtls_md_hmac_starts(context(),
                                          reinterpret_cast<const uint8_t*>(key.constData()),
                                          key.length()
                                          );
        }

        return 0;
    }

    int             hmacUpdate(const uint8_t* input, size_t length) {
        return mbedtls_md_hmac_update(context(), input, length);
    }

    int             hmacUpdate(const QByteArray& input) {
        return mbedtls_md_hmac_update(context(),
                                      reinterpret_cast<const uint8_t*>(input.constData()),
                                      input.length()
                                      );
    }

    auto            hmacFinish() -> QByteArray {
        QByteArray result;

        auto minfo = mbedtls_md_info_from_type(itype);
        Q_ASSERT( minfo != nullptr );

        if ( minfo != nullptr ) {
            result.resize( mbedtls_md_get_size(minfo) );
            int nRet = mbedtls_md_hmac_finish(context(),
                                              reinterpret_cast<uint8_t*>(result.data())
                                              );
            return (nRet == 0) ? result : QByteArray();
        }

        return result;
    }

protected:
    static auto     makeHash(const QByteArray& in,
                             const mbedtls_md_info_t* minfo) -> QByteArray {
        QByteArray result;

        Q_ASSERT( minfo != nullptr );
        if ( minfo != nullptr ) {
            result.resize( mbedtls_md_get_size(minfo) );

            int nRet = mbedtls_md(minfo,
                                  reinterpret_cast<const uint8_t*>(in.constData()),
                                  in.length(),
                                  reinterpret_cast<uint8_t*>(result.data())
                                  );

            if ( nRet != 0 ) {
                qDebug("making hash function failed. type:%s, hash size:%d",
                       mbedtls_md_get_name(minfo),
                       mbedtls_md_get_size(minfo)
                       );
                return QByteArray();
            }
        }

        return result;
    }

    static auto     makeFileHash(const QString& filePath,
                                 const mbedtls_md_info_t* minfo) -> QByteArray {
        QFile f(filePath);
        if ( f.open(QFile::ReadOnly) ) {
            return makeHash(f.readAll(), minfo);
        }

        return QByteArray();
    }

    static auto     makeHmac(const QByteArray& key,
                             const QByteArray& message,
                             const mbedtls_md_info_t* minfo) -> QByteArray {
        QByteArray result;

        Q_ASSERT( minfo != nullptr );
        if ( minfo != nullptr ) {
           result.resize( mbedtls_md_get_size(minfo) );
           int nRet = mbedtls_md_hmac(minfo,
                                      reinterpret_cast<const uint8_t*>(key.constData()),
                                      key.length(),
                                      reinterpret_cast<const uint8_t*>(message.constData()),
                                      message.length(),
                                      reinterpret_cast<uint8_t*>(result.data())
                                      );

            if ( nRet != 0 ) {
                qDebug("making hmac function failed. type:%s, hash size:%d",
                       mbedtls_md_get_name(minfo),
                       mbedtls_md_get_size(minfo)
                       );
                return QByteArray();
            }
        }

        return result;
    }
protected:
    Q_DISABLE_COPY(Hash)

    mbedtls_md_type_t       itype  = MBEDTLS_MD_NONE;
    mbedtls_md_context_t    ictx;
};
///////////////////////////////////////////////////////////////////////////////
} // namespace priv
} // namespace qpolarssl
///////////////////////////////////////////////////////////////////////////////
#endif // QMBEDTLS_HASH_PRIV_HPP
