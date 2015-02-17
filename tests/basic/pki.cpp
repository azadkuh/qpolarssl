#include <catch.hpp>

#include <QString>
#include <QStringList>
#include <QTextStream>
#include <QProcess>

#include "qpolarsslpki.hpp"
#include "qpolarsslhash.hpp"

#include "text-generator.hpp"
///////////////////////////////////////////////////////////////////////////////
TEST_CASE("polarssl::Pki test", "[pki][sign]") {

    qDebug("making source file ...");
    const auto sourceData = test::createSourceData();

    const auto priPath = QStringLiteral(":/prikey");
    const auto pubPath = QStringLiteral(":/pubkey");

    SECTION("sign & verify w/ polarssl") {
        qpolarssl::Pki pki;
        REQUIRE( (pki.parseKeyFrom(priPath)== 0) );
        REQUIRE( pki.isValid() );

        const auto polarsslSignature = pki.sign(sourceData, qpolarssl::THash::SHA1);
        INFO("polarssl signature size");
        REQUIRE( (polarsslSignature.length() > 64) );
        test::writeToFile("polarssl.sig",   polarsslSignature);

        int nRet = pki.verify(sourceData, polarsslSignature, qpolarssl::THash::SHA1);
        INFO("verify polarssl: " << nRet);
        REQUIRE( (nRet == 0) );

        qpolarssl::Pki pkipub;
        REQUIRE( (pkipub.parsePublicKeyFrom(pubPath) == 0) );
        nRet = pkipub.verify(sourceData, polarsslSignature, qpolarssl::THash::SHA1);
        if ( nRet != 0 )
            qDebug("public verification failed: -0x%X", -nRet);
        INFO("verify public polarssl: " << nRet);
        CHECK( (nRet == 0) );
    }

#if defined(Q_OS_LINUX)  ||  defined(Q_OS_OSX)
    SECTION("sign w/ openssl, verify w/ polarssl") {
        test::createSourceFile(sourceData);
        auto priKeyData  = test::readFromFile(priPath);
        auto pubKeyData  = test::readFromFile(pubPath);
        test::writeToFile("key-private.pem", priKeyData);
        test::writeToFile("key-public.pem",  pubKeyData);

        QString command;
        QTextStream stream(&command);
        stream << "#!/bin/bash\n"
               << "openssl dgst -sha1 -sign "
               << "key-private.pem"
               << " -out openssl.sig "
               << test::filePath();
        stream.flush();
        test::writeToFile("sample.sh", command.toUtf8());
        QProcess::execute("/bin/bash", QStringList() << "sample.sh");
        auto opensslSignature = test::readFromFile("openssl.sig");

        INFO("signature file from openssl");
        REQUIRE( (opensslSignature.length() > 64 ) );
        qpolarssl::Pki pki;
        REQUIRE( (pki.parseKeyFrom(priPath) == 0) );
        int nRet = pki.verify(sourceData, opensslSignature, qpolarssl::THash::SHA1);
        INFO("verify openssl: " << nRet);
        REQUIRE( (nRet == 0) );
    }
#endif

    SECTION("encrypt & decrypt w/ polarssl") {
        const auto hash = qpolarssl::Hash::hash(sourceData, "SHA1");

        qpolarssl::Pki pkienc;
        REQUIRE( (pkienc.parsePublicKeyFrom(pubPath) == 0) );
        const auto encData = pkienc.encrypt(hash);
        REQUIRE( (encData.length() > 0 ) );

        qpolarssl::Pki pkidec;
        REQUIRE( (pkidec.parseKeyFrom(priPath) == 0) );
        const auto decData = pkidec.decrypt(encData);
        REQUIRE( (decData.length() > 0) );

        INFO("results must match");
        REQUIRE( (decData == hash) );
    }
}
///////////////////////////////////////////////////////////////////////////////
