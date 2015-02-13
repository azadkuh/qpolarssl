#include <catch.hpp>

#include <QCryptographicHash>
#include "qpolarsslhash.hpp"
#include "text-generator.hpp"
///////////////////////////////////////////////////////////////////////////////
TEST_CASE("qpolarssh::Hash compilation", "[hash]") {
    REQUIRE( qpolarssl::Hash::supports(qpolarssl::THash::SHA1) );
    REQUIRE( qpolarssl::Hash::supports("MD5") );
    REQUIRE( qpolarssl::Hash::supports("SHA512") );

    CHECK( qpolarssl::Hash::supports(qpolarssl::THash::SHA256) );
}

TEST_CASE("qpolarssl::hash", "[hash]") {
    const auto source     = test::createSourceData();

    SECTION("md5 singleshot") {
        auto qtMd5      = QCryptographicHash::hash(source,
                                                   QCryptographicHash::Md5);
        auto polarMd5   = qpolarssl::Hash::hash(source, "MD5");

        INFO("md5 hashes");
        REQUIRE( (polarMd5 == qtMd5) );
    }

    SECTION("md4 singleshot") {
        auto qtMd4      = QCryptographicHash::hash(source,
                                                   QCryptographicHash::Md4);
        auto polarMd4   = qpolarssl::Hash::hash(source,
                                                qpolarssl::THash::MD4);

        INFO("md4 hashes");
        REQUIRE( (polarMd4 == qtMd4) );
    }

    SECTION("SHA1 singleshot") {
        auto qtSha1     = QCryptographicHash::hash(source,
                                                   QCryptographicHash::Sha1);
        auto polarSha1  = qpolarssl::Hash::hash(source, "SHA1");

        INFO("sha1 hashes");
        REQUIRE( (polarSha1 == qtSha1) );
    }

    SECTION("md5 iterative") {
        qpolarssl::Hash phash("MD5");
        QCryptographicHash qhash(QCryptographicHash::Md5);

        auto pStart = reinterpret_cast<const uint8_t*>(source.constData());
        auto pEnd   = pStart + source.length();

        auto pRead  = pStart;
        phash.start();
        qhash.reset();

        while ( pRead != pEnd ) {
            int chunkLength  = ((pEnd - pRead) > 64 ) ?
                                      64 : (pEnd - pRead);
            phash.update(pRead, chunkLength );
            qhash.addData((const char*) pRead, chunkLength);

            pRead += chunkLength;
        }

        auto polarMd5   = phash.finish();
        auto qtMd5      = qhash.result();

        INFO("iterative Md5\n\tpolar: 0x" <<
             polarMd5.toHex().constData() <<
             "\n\tQt: 0x" << qtMd5.toHex().constData() );
        REQUIRE( (polarMd5 == qtMd5) );
    }

    SECTION("sha1 multiuse") {
        auto qtSHA1     = QCryptographicHash::hash(source,
                                                   QCryptographicHash::Sha1);
        auto polarSHA1  = qpolarssl::Hash::hash(source, "SHA1");

        qpolarssl::Hash phash("SHA1");

        auto pStart = reinterpret_cast<const uint8_t*>(source.constData());
        auto pEnd   = pStart + source.length();


        auto pRead  = pStart;
        phash.start();
        while ( pRead != pEnd ) {
            int chunkLength  = ((pEnd - pRead) > 64 ) ?
                                      64 : (pEnd - pRead);
            phash.update(pRead, chunkLength );

            pRead += chunkLength;
        }
        auto polar1SHA1   = phash.finish();

        pRead = pStart;
        phash.start();
        while ( pRead != pEnd ) {
            int chunkLength  = ((pEnd - pRead) > 64 ) ?
                                      64 : (pEnd - pRead);
            phash.update(pRead, chunkLength );

            pRead += chunkLength;
        }
        auto polar2SHA1   = phash.finish();

        INFO("iterative test");
        REQUIRE((
                    (polar1SHA1 == polar2SHA1) &&
                    (polarSHA1  == polar2SHA1) &&
                    (polarSHA1  == qtSHA1)
                    ));
    }
}

TEST_CASE("qpolarssl::hmac", "[hmac][hash]") {
    SECTION("empty key, message") {
        QByteArray      key;
        QByteArray      message;

        auto hmacMd5     = qpolarssl::Hash::hmac(key, message, "MD5");
        auto hmacSha1    = qpolarssl::Hash::hmac(key, message, "SHA1");
        auto hmacSha256  = qpolarssl::Hash::hmac(key, message,
                                                qpolarssl::THash::SHA256);

        REQUIRE( (hmacMd5 ==
                   QByteArray::fromHex("74e6f7298a9c2d168935f58c001bad88")) );
        REQUIRE( (hmacSha1 ==
                  QByteArray::fromHex("fbdb1d1b18aa6c08324b7d64b71fb76370690e1d")) );
        REQUIRE( (hmacSha256 ==
                  QByteArray::fromHex("b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad")) );
    }

    SECTION("wikipedia sample key and message") {
        QByteArray  key("key");
        QByteArray  message("The quick brown fox jumps over the lazy dog");

        auto hmacMd5     = qpolarssl::Hash::hmac(key, message, "MD5");
        auto hmacSha1    = qpolarssl::Hash::hmac(key, message, "SHA1");
        auto hmacSha256  = qpolarssl::Hash::hmac(key, message,
                                                qpolarssl::THash::SHA256);

        REQUIRE( (hmacMd5 ==
                  QByteArray::fromHex("80070713463e7749b90c2dc24911e275")) );
        REQUIRE( (hmacSha1 ==
                  QByteArray::fromHex("de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9")) );
        REQUIRE( (hmacSha256 ==
                  QByteArray::fromHex("f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8")) );
    }

    SECTION("iterative test") {
        QByteArray  key("key");
        QByteArray  message("The quick brown fox jumps over the lazy dog");

        auto hmacMd5  = qpolarssl::Hash::hmac(key, message, "MD5");

        qpolarssl::Hash hash("MD5");
        auto pStart  = reinterpret_cast<const uint8_t*>(message.constData());
        auto pEnd    = pStart + message.length();

        auto pRead   = pStart;
        hash.hmacStart(key);
        while ( pRead != pEnd ) {
            int chunkSize = ((pEnd - pRead) > 4) ? 4 : (pEnd - pRead);
            hash.hmacUpdate(pRead, chunkSize);
            pRead += chunkSize;
        }
        auto hmac1Md5 = hash.hmacFinish();

        pRead   = pStart;
        hash.hmacStart();
        while ( pRead != pEnd) {
            int chunkSize = ((pEnd - pRead) > 4) ? 4 : (pEnd - pRead);
            hash.hmacUpdate(pRead, chunkSize);
            pRead += chunkSize;
        }
        auto hmac2Md5 = hash.hmacFinish();

        INFO("hmac-md5 tests.");
        REQUIRE((
                    (hmac1Md5 == hmac2Md5) &&
                    (hmac1Md5 == hmacMd5)
                    ));
    }
}

///////////////////////////////////////////////////////////////////////////////
