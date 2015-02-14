# QPolarSSL

## Table of contents
- [About](#about)
- [Features](#features)
    - [Hash](#hash)
    - [Cipher](#cipher)
    - [Random](#random)
    - [Pki / RSA](#pki)
- [Setup](#setup)
- [Tests](#tests)
- [License](#license)
    

## About
`QPolarSSL` is a thin wrapper (`Qt5` / `c++11`) around [polarssl](https://github.com/polarssl/polarssl) library who implements a wide range of cryptographic algorithms including hashing (message digest), deterministic random bits generator (drbg), ciphers (symmetric) and public-key (asymmetric) infrastructure.

thanks to efficiency of `polarssl`, the `QPolarSSL` is less than `200KB` when compiled as a dynamic library. `polarssl` is highly configurable, so adding/removing features and algorithms into/from `QPolarSSL` is quite easy, simply tweak  [polarssl_config.h](./library/polarssl_config.h) and [polarssl.pri](./library/polarssl).

tested platforms:

 * Ubuntu 14.04 (64bit), Ubuntu 14.10 (32bit)
 * OSX (10.9 / 10.10)

[TOC](#table-of-contents)

## Features
at the moment current features from `polarssl` are included in *default build* of `QPolarSSL`:

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

list of supported hash algorithms (in default build):

* `MD4`
* `MD5`
* `SHA1`
* `SHA256`, `SHA224`
* `SHA512` , `SHA384`
* `HAMC`

[TOC](#table-of-contents)

### Cihper
symmetric encryption/decryption:
```cpp
QByteArray key      = getFromSomewhere();
QByteArray nonce    = getFromSomewhereElse();

qpolarssl::Cipher cipher("AES-128-CBC");
cipher.setEncryptionKey(key);
cipher.setIv(nonce);
// do encryption
QByteArray encData = cipher("abcdefghijklmnopqrs");

cipher.reset();
cipher.setDecryptionKey(key);
cipher.setIv(nonce);
// do decryption
QByteArray plainData = cipher(encData);

qpolarssl::Cipher blowfish(qpolarssl::TCipher::BLOWFISH_CBC);
qpolarssl::Cipher triDes("DES-EDE3-CBC");
```
see also: [qpolarsslcipher.hpp](./include/qpolarssl/qpolarsslcipher.hpp)

a combination of following modes are included in default build:

* `AES` and `AES-NI` (128, 192 and 256)
* `DES` and `3DES`
* `BLOWFISH`
* `ECB` (Electronic Code Book) and `CBC` (Cipher Block Chaining) modes
* `PKCS7` and other `polarssl` paddings.

[TOC](#table-of-contents)


### Random 
`Random` is a class based on `polarssl`'s [ctr-drbg / entrpoy](https://polarssl.org/module-level-design-rng), can be used to generate random numbers and buffers:
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
The asymmetric encryptrion algorithms are accessible via the generic public key layer:
```cpp
// sign and verify data
qpolarssl::Pki pki;
pki.parseKeyFrom(priPath);

const auto polarsslSignature = pki.sign(sourceData, qpolarssl::THash::SHA1);

qpolarssl::Pki pkipub;
pkipub.parsePublicKeyFrom(pubPath);

int nRet = pkipub.verify(sourceData, polarsslSignature, qpolarssl::THash::SHA1);
if ( nRet != 0 )
    qDebug("verification failed: -0x%X", -nRet);


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

at the moment `RSA` is included in `QPolarSSL` by default.

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
* [polarssl](https://github.com/azadkuh/qpolarssl) aka `mbed TSL`.
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

