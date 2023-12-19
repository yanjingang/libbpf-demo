#!/bin/bash

export CUR_DIR=$(pwd)
BIN_NAME=utest_class
if [ $# -ge 1 ]; then
    BIN_NAME=$1
fi
echo "BIN_NAME: ${BIN_NAME}"

# 1. build
cd ${CUR_DIR}
rm -rf build/${BIN_NAME}
mkdir -p build && cd build
cmake ..
make


# 2. dump symbols
# check symbols
echo "check ${BIN_NAME} symbols: "
echo "    `objdump -T ${BIN_NAME} |grep utest_add`"
echo "    `objdump -T ${BIN_NAME} |grep utest_sub`"

# dump symbols
./usymbol ${BIN_NAME} > symbols-${BIN_NAME}.txt
cat symbols-${BIN_NAME}.txt | grep utest_

# strip symbols
strip --strip-all ${BIN_NAME}


# 3. ebpf test
# run user space test
pkill ${BIN_NAME}
RUN_CMD="./${BIN_NAME}"
nohup ${RUN_CMD} &

# run ebpf
ps -ef | grep ${RUN_CMD} | grep -v grep 
pid=$(ps -ef | grep ${RUN_CMD} | grep -v grep | awk '{print $2}')
echo "PID: ${pid}#"
sudo ./uprobe_symbol ${pid}

# sudo cat /sys/kernel/debug/tracing/trace_pipe

