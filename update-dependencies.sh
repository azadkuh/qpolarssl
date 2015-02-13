#!/bin/sh

echo "preparing the latest version of 3rd-party dependencies ...\n"

mkdir -p 3rdparty
cd 3rdparty

echo "\n--> polarssl/polarssl"
if [ -e polarssl ]; then
    cd polarssl
    git pull origin master
    cd ..
else
    git clone --depth 1 https://github.com/polarssl/polarssl.git -b master
fi

echo "\n--> philsquared/Catch"
if [ -e Catch ]; then
    cd Catch
    git pull origin master
    cd ..
else
    git clone --depth 1 https://github.com/philsquared/Catch.git -b master
fi

cd ..
echo "\ndone."
