/** @file qpolarsslhash_priv.hpp
  * Qt wrapper class around polarssl functions
  *
  * @copyright (C) 2015, azadkuh
  * @date 2015.02.12
  * @version 1.0.0
  * @author amir zamani <azadkuh@live.com>
  *
 */

#ifndef QPOLARSSL_HASH_PRIV_HPP
#define QPOLARSSL_HASH_PRIV_HPP

#include "polarssl/md.h"
#include <QByteArray>
#include <QString>
///////////////////////////////////////////////////////////////////////////////
namespace qpolarssl {
namespace priv {
///////////////////////////////////////////////////////////////////////////////
class Hash
{
public:
    static auto     hash(const QByteArray& in,
                         md_type_t type = POLARSSL_MD_SHA1) -> QByteArray {
        auto minfo = md_info_from_type(type);
        return makeHash(in, minfo);
    }

    static auto     hash(const QByteArray &in,
                         const char* name) -> QByteArray {
        auto minfo = md_info_from_string(name);
        return makeHash(in, minfo);
    }

    static auto     fileHash(const QString& filePath,
                             md_type_t type = POLARSSL_MD_SHA1) -> QByteArray {
        auto minfo = md_info_from_type(type);
        return makeFileHash(filePath, minfo);
    }

    static auto     fileHash(const QString& filePath,
                             const char* name) -> QByteArray {
        auto minfo = md_info_from_string(name);
        return makeFileHash(filePath, minfo);
    }

    static auto     hmac(const QByteArray& key,
                         const QByteArray& message,
                         md_type_t type = POLARSSL_MD_SHA1) -> QByteArray {
        auto minfo = md_info_from_type(type);
        return makeHmac(key, message, minfo);
    }

    static auto     hmac(const QByteArray& key,
                         const QByteArray& message,
                         const char* name) -> QByteArray {
        auto minfo = md_info_from_string(name);
        return makeHmac(key, message, minfo);
    }

public:
    explicit        Hash(md_type_t t) {
        auto minfo = md_info_from_type(t);
        if ( minfo != nullptr ) {
            itype   = t;
            md_init_ctx(context(), minfo);
        }
    }

    explicit        Hash(const char* name) {
        auto minfo = md_info_from_string(name);
        if ( minfo != nullptr ) {
            itype = minfo->type;
            md_init_ctx(context(), minfo);
        }
    }

    virtual        ~Hash() {
        md_free_ctx(context());
    }

    auto            context() -> md_context_t* {
        return &ictx;
    }

    bool            isValid()const {
        return itype != POLARSSL_MD_NONE;
    }

    auto            info()const -> const md_info_t* {
        return md_info_from_type(itype);
    }

    int             start() {
        return md_starts(context());
    }

    int             update(const uint8_t* input, size_t length) {
        return md_update(context(), input, length);
    }

    int             update(const QByteArray& input) {
        return md_update(context(),
                         reinterpret_cast<const uint8_t*>(input.constData()),
                         input.length()
                         );
    }

    auto            finish() -> QByteArray {
        QByteArray result;

        auto minfo = md_info_from_type(itype);
        Q_ASSERT( minfo != nullptr );

        if ( minfo != nullptr ) {
            result.resize( minfo->size );
            int nRet = md_finish(context(),
                                 reinterpret_cast<uint8_t*>(result.data())
                                 );
            return (nRet == 0) ? result : QByteArray();
        }

        return result;
    }

    int             hmacStart(const QByteArray& key = QByteArray()) {
        md_hmac_reset(context());
        if ( key.length() > 0 ) {
            return md_hmac_starts(context(),
                                  reinterpret_cast<const uint8_t*>(key.constData()),
                                  key.length()
                                  );
        }

        return 0;
    }

    int             hmacUpdate(const uint8_t* input, size_t length) {
        return md_hmac_update(context(), input, length);
    }

    int             hmacUpdate(const QByteArray& input) {
        return md_hmac_update(context(),
                              reinterpret_cast<const uint8_t*>(input.constData()),
                              input.length()
                              );
    }

    auto            hmacFinish() -> QByteArray {
        QByteArray result;

        auto minfo = md_info_from_type(itype);
        Q_ASSERT( minfo != nullptr );

        if ( minfo != nullptr ) {
            result.resize( minfo->size );
            int nRet = md_hmac_finish(context(),
                                      reinterpret_cast<uint8_t*>(result.data())
                                      );
            return (nRet == 0) ? result : QByteArray();
        }

        return result;
    }

protected:
    static auto     makeHash(const QByteArray& in,
                             const md_info_t* minfo) -> QByteArray {
        QByteArray result;

        Q_ASSERT( minfo != nullptr );
        if ( minfo != nullptr ) {
            result.resize( minfo->size );

            int nRet = md(minfo,
                          reinterpret_cast<const uint8_t*>(in.constData()),
                          in.length(),
                          reinterpret_cast<uint8_t*>(result.data())
                          );

            if ( nRet != 0 ) {
                qDebug("making hash function failed. type:%s, hash size:%d",
                       minfo->name, minfo->size
                       );
                return QByteArray();
            }
        }

        return result;
    }

    static auto     makeFileHash(const QString& filePath,
                                 const md_info_t* minfo) -> QByteArray {
        QByteArray result;

        Q_ASSERT( minfo != nullptr );
        if ( minfo != nullptr ) {
            result.resize( minfo->size );

            int nRet = md_file(minfo,
                               filePath.toUtf8().constData(),
                               reinterpret_cast<uint8_t*>(result.data())
                          );

            if ( nRet != 0 ) {
                qDebug("making hash function failed. type:%s, hash size:%d",
                       minfo->name, minfo->size
                       );
                return QByteArray();
            }
        }

        return result;
    }

    static auto     makeHmac(const QByteArray& key,
                             const QByteArray& message,
                             const md_info_t* minfo) -> QByteArray {
        QByteArray result;

        Q_ASSERT( minfo != nullptr );
        if ( minfo != nullptr ) {
           result.resize( minfo->size );
           int nRet = md_hmac(minfo,
                              reinterpret_cast<const uint8_t*>(key.constData()),
                              key.length(),
                              reinterpret_cast<const uint8_t*>(message.constData()),
                              message.length(),
                              reinterpret_cast<uint8_t*>(result.data())
                              );

            if ( nRet != 0 ) {
                qDebug("making hmac function failed. type:%s, hash size:%d",
                       minfo->name, minfo->size
                       );
                return QByteArray();
            }
        }

        return result;
    }
protected:
    Q_DISABLE_COPY(Hash)

    md_type_t       itype  = POLARSSL_MD_NONE;
    md_context_t    ictx;
};
///////////////////////////////////////////////////////////////////////////////
} // namespace priv
} // namespace qpolarssl
///////////////////////////////////////////////////////////////////////////////
#endif // QPOLARSSL_HASH_PRIV_HPP
