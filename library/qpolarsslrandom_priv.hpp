/** @file qpolarsslrandom_priv.hpp
  * Qt wrapper class around polarssl functions
  *
  * @copyright (C) 2015, azadkuh
  * @date 2015.02.12
  * @version 1.0.0
  * @author amir zamani <azadkuh@live.com>
  *
 */

#ifndef QPOLARSSL_RANDOM_PRIV_HPP
#define QPOLARSSL_RANDOM_PRIV_HPP

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include <QByteArray>
///////////////////////////////////////////////////////////////////////////////
namespace qpolarssl {
namespace priv {
///////////////////////////////////////////////////////////////////////////////
class Random
{
public:
    explicit        Random(const uint8_t* custom = nullptr, size_t len=0) {
        mbedtls_entropy_init(&ientropy);
        mbedtls_ctr_drbg_init(context());
        mbedtls_ctr_drbg_seed(context(),
                      mbedtls_entropy_func, &ientropy,
                      custom, len
                      );
        mbedtls_ctr_drbg_set_prediction_resistance(context(),
                                                   MBEDTLS_CTR_DRBG_PR_OFF);
    }

    explicit        Random(const QByteArray& custom) :
        Random(reinterpret_cast<const uint8_t*>(custom.constData()), custom.length()) {
    }

    virtual        ~Random() {
        mbedtls_entropy_free(&ientropy);
        mbedtls_ctr_drbg_free(context());
    }

    auto            operator()(size_t length) -> QByteArray{
        QByteArray result;
        result.resize(length);
        int nRet = mbedtls_ctr_drbg_random(context(),
                                           reinterpret_cast<uint8_t*>(result.data()),
                                           length
                                           );

        return (nRet == 0 ) ? result : QByteArray();
    }

    int             random(uint8_t* output, size_t length) {
        return mbedtls_ctr_drbg_random(context(),
                                       output,
                                       length
                                       );
    }

    void            setPredictionResistance(bool resistance = false) {
        mbedtls_ctr_drbg_set_prediction_resistance(
                    context(),
                    (resistance) ? MBEDTLS_CTR_DRBG_PR_ON : MBEDTLS_CTR_DRBG_PR_OFF
                                   );
    }

    int             reseed(const uint8_t* additional, size_t len) {
        return mbedtls_ctr_drbg_reseed(context(), additional, len);
    }

    int             reseed(const QByteArray& additional) {
        return mbedtls_ctr_drbg_reseed(context(),
                                       reinterpret_cast<const uint8_t*>(additional.constData()),
                                       additional.length()
                                       );
    }

    void            update(const uint8_t* additional, size_t len) {
        mbedtls_ctr_drbg_update(context(), additional, len);
    }

    void            update(const QByteArray& additional) {
        mbedtls_ctr_drbg_update(context(),
                                reinterpret_cast<const uint8_t*>(additional.constData()),
                                additional.length()
                                );
    }

    auto            context() -> mbedtls_ctr_drbg_context* {
        return &ictx;
    }


protected:
    Q_DISABLE_COPY(Random)

    mbedtls_entropy_context     ientropy;
    mbedtls_ctr_drbg_context    ictx;
};

///////////////////////////////////////////////////////////////////////////////
} // namespace priv
} // namespace polarssl
///////////////////////////////////////////////////////////////////////////////
#endif // QPOLARSSL_RANDOM_PRIV_HPP
