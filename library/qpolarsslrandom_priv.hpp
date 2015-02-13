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

#include "polarssl/ctr_drbg.h"
#include "polarssl/entropy.h"
#include <QByteArray>
///////////////////////////////////////////////////////////////////////////////
namespace qpolarssl {
namespace priv {
///////////////////////////////////////////////////////////////////////////////
class Random
{
public:
    explicit        Random(const uint8_t* custom = nullptr, size_t len=0) {
        entropy_init(&ientropy);
        ctr_drbg_init(context(),
                      entropy_func, &ientropy,
                      custom, len
                      );
        ctr_drbg_set_prediction_resistance(context(),
                                           CTR_DRBG_PR_OFF);
    }

    explicit        Random(const QByteArray& custom) :
        Random(reinterpret_cast<const uint8_t*>(custom.constData()), custom.length()) {
    }

    virtual        ~Random() {
        entropy_free(&ientropy);
        ctr_drbg_free(context());
    }

    auto            operator()(size_t length) -> QByteArray{
        QByteArray result;
        result.resize(length);
        int nRet = ctr_drbg_random(context(),
                                   reinterpret_cast<uint8_t*>(result.data()),
                                   length
                                   );

        return (nRet == 0 ) ? result : QByteArray();
    }

    int             random(uint8_t* output, size_t length) {
        return ctr_drbg_random(context(),
                               output,
                               length
                               );
    }

    void            setPredictionResistance(bool resistance = false) {
        ctr_drbg_set_prediction_resistance(
                    context(),
                    (resistance) ? CTR_DRBG_PR_ON : CTR_DRBG_PR_OFF
                                   );
    }

    int             reseed(const uint8_t* additional, size_t len) {
        return ctr_drbg_reseed(context(), additional, len);
    }

    int             reseed(const QByteArray& additional) {
        return ctr_drbg_reseed(context(),
                               reinterpret_cast<const uint8_t*>(additional.constData()),
                               additional.length()
                               );
    }

    void            update(const uint8_t* additional, size_t len) {
        ctr_drbg_update(context(), additional, len);
    }

    void            update(const QByteArray& additional) {
        ctr_drbg_update(context(),
                        reinterpret_cast<const uint8_t*>(additional.constData()),
                        additional.length()
                        );
    }

    auto            context() -> ctr_drbg_context* {
        return &ictx;
    }


protected:
    Q_DISABLE_COPY(Random)

    entropy_context     ientropy;
    ctr_drbg_context    ictx;
};

///////////////////////////////////////////////////////////////////////////////
} // namespace priv
} // namespace polarssl
///////////////////////////////////////////////////////////////////////////////
#endif // QPOLARSSL_RANDOM_PRIV_HPP
