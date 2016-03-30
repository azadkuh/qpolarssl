# QPolarSSL

## Table of contents
- [About](#about)
- [Features](#features)
- [Usage](#usage)
    - [Hash](#hash)
    - [Cipher](#cipher)
    - [Random](#random)
    - [Pki / RSA](#pki)
- [Setup](#setup)
- [Tests](#tests)
- [License](#license)


## About
`QPolarSSL` is a thin wrapper (`Qt5` / `c++11`) around [mbedtls](https://github.com/ARMmbed/mbedtls) (formerly known as PolarSSL) library who implements a wide range of cryptographic algorithms including hashing (message digest), deterministic random bits generator (drbg), ciphers (symmetric) and public-key (asymmetric) infrastructure.

Thanks to efficiency of `mbedtls`, the `QPolarSSL` is less than `270KB` when compiled as a dynamic library (including mbedtls under OS X 10.11). `mbedtls` is highly configurable, so adding/removing features and algorithms into/from `QPolarSSL` is quite easy, simply tweak  [mbedtls_config.h](./library/mbedtls_config.h) and [mbedtls.pri](./library/mbedtls.pri).

> for a pure `c++11/14` cryptography (without `Qt`) library, see sister project: [mbedcrypto](https://github.com/azadkuh/mbedcrypto)

Tested platforms:

 * Ubuntu 14.04 (64bit, gcc 4.8+, 5.2+), Ubuntu 14.10 (32bit gcc 4.8+)
 * OS X (10.9 / 10.10 / 10.11, clang 3.5+)
 * Windows 7/8.1 (64bit - Visual Studio 2013/2015)

[TOC](#table-of-contents)

## Features
following features are included in `QPolarSSL` by *default build*:

* **Hash algorithms:**
    - `MD4`
    - `MD5`
    - `SHA1`
    - `SHA256`, `SHA224`
    - `SHA512` , `SHA384`
    - `HAMC`
* **Ciphers:**
    - `AES` and `AES-NI` (128, 192 and 256)
    - `DES` and `3DES`
    - `BLOWFISH`
    - `ECB` (Electronic Code Book) and `CBC` (Cipher Block Chaining) modes
    - `PKCS7` and other `mbedtls` paddings.
* **Random** generators by `ctr-drbg` / `entrpoy` from mbedtls
* **PKI**
    - `RSA`

## Usage

### Hash & HMAC
creating message-digest and HMAC:
```cpp
const QByteArray source  = fetchSourceDataFromSomewhere();
//  check algorithm availability
bool check    = qpolarssl::Hash::supports("SHA512");
//  select a hash method by name
auto hashSha1 = qpolarssl::Hash::hash(source, "SHA1");
//  select a hash method by type
auto hashMd5  = qpolarssl::Hash::hash(source, qpolarssl::THash::MD5);

// or
qpolarssl::Hash hash("SHA256");
hash.start();
while ( condition ) {
    // ...
    hash.update( chunk );
    // ...
}
auto hashSha256 = hash.finish();

// to start again:
hash.start();
// ... and compute another hash value as above.


// to make hmac message authentication code:
QByteArray key;     // secret key value in any length.
QByteArray message; // message to be hmac'ed in any length

auto hmacSha1 = qpolarssl::Hash::hmac(key, message, "SHA1");

```
see also: [qpolarsslhash.hpp](./include/qpolarssl/qpolarsslhash.hpp)


[TOC](#table-of-contents)

### Cipher
symmetric encryption/decryption:
```cpp
// first assign the key and the iv (initial vector)
QByteArray key = ...;
QByteArray iv  = ...;
// key / iv length depends on cipher algorithm

// do the encryption in one function call
QByteArray source  = ...; // source/plain data
QByteArray encData = qpolarssl::Cipher::encrypt(
    qpolarssl::TCipher::AES_256_CBC, iv, key, source
    );

// decryption
qpolarssl::Cipher cipher("AES-256-CBC"); // by name
cipher.setDecryptionKey(key);
cipher.setIv(iv);
auto plainData = cipher(encData);

REQUIRE( plainData == source );

// other cipher algorithms:
qpolarssl::Cipher blowfish(qpolarssl::TCipher::BLOWFISH_CBC);
qpolarssl::Cipher triDes("DES-EDE3-CBC");
// ...

// checks for hardware accelerated AES support (hardware acceleration):
if ( qpolarssl::Cipher::supportsAesNi() )
    qDebug("this hardware supports AESNI instruction set.");
```
see also: [qpolarsslcipher.hpp](./include/qpolarssl/qpolarsslcipher.hpp)

[TOC](#table-of-contents)


### Random
`Random` is a class based on `mbedtls`'s [ctr-drbg / entrpoy](https://tls.mbed.org/module-level-design-rng), can be used to generate random numbers and buffers:
```cpp
qpolarssl::Random rnd(QByteArray("my custom, optional intializer!");

auto randomData = rnd(20); // 20 bytes of random data

// in combination with qpolarssl::Cipher
qpolarssl::Cipher cipher("AES-128-CBC");
cipher.setEncryptionKey(key); // your key
cipher.setIv(rnd(16));
auto cipheredData = cipher(plainData);

```
see also: [qpolarsslrandom.hpp](./include/qpolarssl/qpolarsslrandom.hpp)

[TOC](#table-of-contents)


### Pki
The asymmetric encryption algorithms are accessible via the generic public key layer:
```cpp
// sign and verify data
qpolarssl::Pki pki;
pki.parseKeyFrom(priKeyFilePath);
const auto signature = pki.sign(sourceData, qpolarssl::THash::SHA1);

qpolarssl::Pki pkipub;
pkipub.parsePublicKeyFrom(pubKeyFilePath);
int nRet = pkipub.verify(sourceData, signature, qpolarssl::THash::SHA1);
REQUIRE( nRet == 0 );


// encrypt and decrypt data
const auto hash = qpolarssl::Hash::hash(sourceData, "SHA1");

qpolarssl::Pki pkienc;
pkienc.parsePublicKeyFrom(pubPath);
const auto encData = pkienc.encrypt(hash);

qpolarssl::Pki pkidec;
pkidec.parseKeyFrom(priPath);
const auto decData = pkidec.decrypt(encData);

REQUIRE( (decData == hash) );

```
see also: [qpolarsslrandom.hpp](./include/qpolarssl/qpolarsslrandom.hpp)

[TOC](#table-of-contents)


## Setup
instructions:
```bash
# prepare or update dependencies:
$> ./update-dependencies.sh

# now build the library (*.so) and the test units
$> qmake qpolarssl.pro
$> make -j 8
```

to make `QPolarSSL` as a static library add:
```
CONFIG += staticlib
```
to [library.pro](./library/library.pro).

dependecies:

* [Qt 5](http://www.qt.io/download)
* [mbedtls](https://tls.mbed.org/)
* [Catch](https://github.com/philsquared/Catch) only for unit testings.

[TOC](#table-of-contents)


## Tests
a [Catch](https://github.com/philsquared/Catch) based unit test application is also included.
```bash
$> ./xbin/test-basic -t

All available tags:
   2  [aes]
   2  [benchmark]
   4  [cipher]
   3  [hash]
   1  [hmac]
   1  [pki]
   2  [rnd]
   1  [sign]
8 tags
```

[TOC](#table-of-contents)


## License
Distributed under the MIT license. Copyright (c) 2015, Amir Zamani.

