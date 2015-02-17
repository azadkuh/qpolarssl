#include <catch.hpp>
#include <chrono>

#include "qpolarsslrandom.hpp"

///////////////////////////////////////////////////////////////////////////////
TEST_CASE("polarssl::random", "[rnd]") {
    qpolarssl::Random rnd1;
    qpolarssl::Random rnd2(QByteArray("some custom randomizer!"));

    auto data1  = rnd1(20);
    auto data2  = rnd2(64);

    INFO("should return meaningfull values.");
    REQUIRE( (data1.length() == 20    &&    data2.length() == 64));

    auto data3  = rnd1(20);
    auto data4  = rnd2(64);

    INFO("random data must be different.");
    REQUIRE( (data1 != data3    &&    data2 != data4) );
}

TEST_CASE("polarssl::random benchmark", "[rnd][benchmark]") {
    auto start = std::chrono::high_resolution_clock::now();
    qpolarssl::Random rnd;
    auto end   = std::chrono::high_resolution_clock::now();
    auto duration = double(std::chrono::duration_cast<std::chrono::nanoseconds>(end-start).count())
                    / 1000.0;
    qDebug("\n\nrandom number generator initialized in %.3f [uSec].\n  wait ...",
           duration
           );

    const size_t KBufferSize = 512;
    const size_t KIteration  = 128 * 1024;
    uint8_t data1[KBufferSize] = {0};
    uint8_t data2[KBufferSize] = {0};

    start = std::chrono::high_resolution_clock::now();
    for ( size_t i = 0;    i < KIteration;    i++ ) {
        rnd.random(data1, KBufferSize);
        rnd.random(data2, KBufferSize);
        int nResult = memcmp(data1, data2, KBufferSize);

        REQUIRE( (nResult != 0) );
    }
    end = std::chrono::high_resolution_clock::now();
    duration = double(std::chrono::duration_cast<std::chrono::nanoseconds>(end-start).count())
               / 1000.0;
    double totalMB = KBufferSize * KIteration * 2 / 1024.0;
    qDebug("%.1f MB of random data has been created in %.3f [uSec]\n" \
           "    performance: %.3f [MB/sec]",
           totalMB,
           duration,
           totalMB / duration * 1e6
           );
}

///////////////////////////////////////////////////////////////////////////////
