#!/bin/sh
git clone https://github.com/relic-toolkit/relic
cd relic
mkdir target
cd target
cmake -DFP_PRIME=381 ../
make
make install
cd ../..
rm -rf relic
