#!/bin/bash

export CUR_DIR=$(pwd)

# build
cd ${CUR_DIR}
mkdir -p build && cd build
cmake ..
make

# check symbols
echo "check utest symbols: "
echo "    `objdump -T utest |grep utest_add`"
echo "    `objdump -T utest |grep utest_sub`"
echo "check utest_class symbols: "
echo "    `objdump -T utest_class |grep utest_add`"
echo "    `objdump -T utest_class |grep utest_sub`"
# dump utest symbols
./usymbol utest > symbols.txt
cat symbols.txt
./usymbol utest_class > symbols2.txt
cat symbols2.txt
