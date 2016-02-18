#include <catch.hpp>

#include <chrono>

#include <QCoreApplication>
#include <QFile>
#include <QFileInfo>
#include <QDir>
#include <QTextStream>
#include <QCryptographicHash>
#include <QDateTime>

#include "qpolarsslhash.hpp"
#include "qpolarsslcipher.hpp"
#include "text-generator.hpp"

///////////////////////////////////////////////////////////////////////////////
TEST_CASE("polarssl::Cipher compilation", "[cipher]") {
    REQUIRE( qpolarssl::Cipher::supports(qpolarssl::TCipher::AES_128_CBC) );
    REQUIRE( qpolarssl::Cipher::supports("DES-CBC") );
    REQUIRE( qpolarssl::Cipher::supports("AES-256-ECB") );
    if ( qpolarssl::Cipher::supportsAesNi() )
        qDebug("this hardware supports AESNI instruction set.");
}

TEST_CASE("polarssl::AES and fix hashes", "[cipher][aes]") {
    SECTION("AES-128-CBC") {
        qpolarssl::Cipher aes("AES-128-CBC");
        aes.setEncryptionKey(QByteArray
                             ::fromHex("2b7e151628aed2a6abf7158809cf4f3c"));

        INFO(R"xx(aes("AES-128-cbc") validity check)xx");
        REQUIRE( aes.isValid() );

        SECTION("sample 1 - 128bit") {
            aes.setIv(QByteArray
                      ::fromHex("7649ABAC8119B246CEE98E9B12E9197D"));
            auto testVector = QByteArray
                              ::fromHex("ae2d8a571e03ac9c9eb76fac45af8e51");
            auto cipher     = QByteArray
                              ::fromHex("5086cb9b507219ee95db113a917678b2");
            auto result     = aes(testVector, qpolarssl::TPadding::NONE);

            CHECK( (cipher == result ) );
        }

        SECTION("sample 2 - 128bit") {
            aes.setIv(QByteArray
                      ::fromHex("73BED6B8E3C1743B7116E69E22229516"));
            auto testVector = QByteArray
                              ::fromHex("f69f2445df4f9b17ad2b417be66c3710");
            auto cipher     = QByteArray
                              ::fromHex("3ff1caa1681fac09120eca307586e1a7");
            auto result     = aes(testVector, qpolarssl::TPadding::NONE);

            CHECK( (cipher == result ) );
        }
    }

    SECTION("AES-256-CBC") {
        qpolarssl::Cipher aes("AES-256-CBC");
        aes.setEncryptionKey(QByteArray::
                             fromHex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"));

        REQUIRE( aes.isValid() );

        SECTION("sample 1 - 256bit") {
            aes.setIv(QByteArray
                      ::fromHex("F58C4C04D6E5F1BA779EABFB5F7BFBD6"));
            auto testVector = QByteArray
                              ::fromHex("ae2d8a571e03ac9c9eb76fac45af8e51");
            auto cipher     = QByteArray
                              ::fromHex("9cfc4e967edb808d679f777bc6702c7d");
            auto result     = aes(testVector, qpolarssl::TPadding::NONE);

            CHECK( (cipher == result ) );
        }

        SECTION("sample 2 - 256bit") {
            aes.setIv(QByteArray
                      ::fromHex("39F23369A9D9BACFA530E26304231461"));
            auto testVector = QByteArray
                              ::fromHex("f69f2445df4f9b17ad2b417be66c3710");
            auto cipher     = QByteArray
                              ::fromHex("b2eb05e2c39be9fcda6c19078c6a9d1b");
            auto result     = aes(testVector, qpolarssl::TPadding::NONE);

            CHECK( (cipher == result ) );
        }
    }
}

TEST_CASE("polarssl::AES incremental", "[cipher][aes]") {
    const auto aes_mode  = qpolarssl::TCipher::AES_256_CBC;
    const auto hash_mode = qpolarssl::THash::SHA1;
    const QByteArray key(32, 'a');
    const QByteArray iv(16,  'z');

    const QByteArray sourceData = test::createSourceData(10000);

    // encrypt in one shot
    auto oneShot = [&]() {
        auto encryptedData = qpolarssl::Cipher::encrypt(
                aes_mode, iv, key, sourceData
                );
        REQUIRE( encryptedData.length() > 0 );

        return std::make_tuple(
                qpolarssl::Hash::hash(sourceData,    hash_mode),
                qpolarssl::Hash::hash(encryptedData, hash_mode),
                encryptedData
                );
    }();

    qpolarssl::Hash sha1(hash_mode);
    constexpr int ChunkSize = 4096;
    qpolarssl::Cipher polar(aes_mode);

    // encrypt incrementally
    polar.setIv(iv);
    polar.setEncryptionKey(key);

    auto iterativeSha1 = [&]() -> QByteArray {
        sha1.start();
        polar.start();
        const int sourceLength = sourceData.length();

        for ( int offset = 0;  offset < sourceLength;  offset += ChunkSize ) {
            int length = std::min(ChunkSize, sourceLength - offset);
            auto enc   = polar.update(QByteArray::fromRawData(
                        sourceData.data() + offset, length
                        ));

            REQUIRE( enc.length() > 0 );
            sha1.update(enc);
        }
        // finish cipher context, add paddings, ...
        sha1.update(polar.finish());
        return sha1.finish();
    }();
    REQUIRE( (iterativeSha1 == std::get<1>(oneShot)) );

    // decrypt incrementally
    polar.reset();
    polar.setIv(iv);
    polar.setDecryptionKey(key);
    iterativeSha1 = [&](const QByteArray& data) {
        sha1.start();
        polar.start();
        const int dataLength = data.length();

        for ( int offset = 0;  offset < dataLength;  offset += ChunkSize ) {
            int length = std::min(ChunkSize, dataLength - offset);
            auto plain = polar.update(QByteArray::fromRawData(
                        data.data() + offset, length
                        ));

            REQUIRE( plain.length() > 0 );
            sha1.update(plain);
        }
        // finalize cipher context, ...
        sha1.update(polar.finish());
        return sha1.finish();
    }(std::get<2>(oneShot));

    REQUIRE( (iterativeSha1 == std::get<0>(oneShot)) );
}

TEST_CASE("polarssl::AES to file", "[cipher][aes]") {
    QByteArray sourceData = test::createSourceData();
    test::createSourceFile(sourceData);

    QByteArray key(16, 'a'); {
        QFile fkey(QFileInfo(QCoreApplication::instance()->applicationDirPath(),
                             "aes128.key").absoluteFilePath()
                   );
        if ( fkey.open(QFile::WriteOnly) ) {
            fkey.write(key);
        }
    }
    QByteArray nonce(16, 'n'); {
        QFile fnonce(QFileInfo(QCoreApplication::instance()->applicationDirPath(),
                               "aes128.nonce").absoluteFilePath()
                     );
        if ( fnonce.open(QFile::WriteOnly) ) {
            fnonce.write(nonce);
        }
    }

    qpolarssl::Cipher polar(qpolarssl::TCipher::AES_128_CBC);
    polar.setEncryptionKey(key);
    polar.setIv(nonce);
    QByteArray encData = polar(sourceData);

    REQUIRE_FALSE( encData.isEmpty() );

    qDebug("md5 hash of encrypted data: %s",
           qpolarssl::Hash::hash(encData, "MD5").toHex().constData()
           );

    polar.reset();
    polar.setDecryptionKey(key);
    polar.setIv(nonce);
    QByteArray plainData = polar(encData);

    auto hash1 = qpolarssl::Hash::hash(sourceData, "MD5");
    auto hash2 = qpolarssl::Hash::hash(plainData, "MD5");
    REQUIRE( (hash1 == hash2) );
}

TEST_CASE("polarssl::AES speed test", "[cipher][benchmark]") {
    qDebug("\nTest looping of AES,\n  wait ...");

    qpolarssl::Cipher cipherEnc("AES-128-CBC");
    qpolarssl::Cipher cipherDec("AES-128-CBC");

    INFO("cipher: AES-128-CBC validity check.");
    REQUIRE( (cipherEnc.isValid()   &&   cipherDec.isValid()) );

    QByteArray key(16, 'a');
    cipherEnc.setEncryptionKey(key);
    cipherDec.setDecryptionKey(key);

    QByteArray iv(16, 'z');
    cipherEnc.setIv(iv);
    cipherDec.setIv(iv);

    const auto sourceData = test::createSourceData(6000);
    qDebug("    # %.3f [KB] of sample source has been created.",
           sourceData.length() / 1024.0
           );
    auto sourceHash = qpolarssl::Hash::hash(sourceData, "SHA1");

    const int   KIteration   = 1000;
    uint64_t    encDuration  = 0;
    uint64_t    decDuration  = 0;
    uint64_t    hashDuration = 0;

    qDebug("    # iterating %d times ...", KIteration);
    for ( int i = 0;    i < KIteration;    i++ ) {
        auto start      = std::chrono::high_resolution_clock::now();
        auto cipherData = cipherEnc(sourceData);
        auto end        = std::chrono::high_resolution_clock::now();
        encDuration += std::chrono::duration_cast<std::chrono::nanoseconds>(
                           end - start).count();

        start             = std::chrono::high_resolution_clock::now();
        auto expectedData = cipherDec(cipherData);
        end               = std::chrono::high_resolution_clock::now();
        decDuration += std::chrono::duration_cast<std::chrono::nanoseconds>(
                           end - start).count();

        start             = std::chrono::high_resolution_clock::now();
        auto expectedHash = qpolarssl::Hash::hash(expectedData, "SHA1");
        end               = std::chrono::high_resolution_clock::now();
        hashDuration += std::chrono::duration_cast<std::chrono::nanoseconds>(
                           end - start).count();

        REQUIRE( (expectedHash == sourceHash) );
    }

    qDebug("tickings (milliSec): hash = %.1f , enc = %.1f , dec = %.1f",
           hashDuration/1e6,
           encDuration/1e6,
           decDuration/1e6
           );
    double  sizeMB = sourceData.length() * KIteration;
    sizeMB /= (1024.0 * 1024.0);
    sizeMB *= 1e9;
    qDebug("AES speed:\n    Encryption: %.1f [MB/s]\n    Decryption: %.1f [MB/s]",
           sizeMB / encDuration,
           sizeMB / decDuration
           );
}

///////////////////////////////////////////////////////////////////////////////
