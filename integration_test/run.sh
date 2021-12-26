#!/bin/sh

RAND_DIR=$(head -c 4 </dev/urandom | xxd -p)
TESTDIR=/tmp/"rust_miniscript_test_$RAND_DIR"

rm -rf ${TESTDIR}
mkdir -p ${TESTDIR}/1

# To kill any remaining open bitcoind.
killall -9 bitcoind

echo $PATH

BLOCKFILTERARG=""
if bitcoind -version | grep -q "v0\.\(19\|2\)"; then
    BLOCKFILTERARG="-blockfilterindex=1"
fi

FALLBACKFEEARG=""
if bitcoind -version | grep -q -e "v0\.2" -e "v2[2-9]"; then
    FALLBACKFEEARG="-fallbackfee=0.00001000"
fi

bitcoind -regtest $FALLBACKFEEARG \
    -datadir=${TESTDIR}/1 \
    -rpcport=12348 \
    -server=1 \
    -printtoconsole=0 &
PID1=$!

# Make sure it's listening.
sleep 3

RPC_URL=http://localhost:12348 \
    RPC_COOKIE=${TESTDIR}/1/regtest/.cookie \
    cargo run

RESULT=$?

kill -9 $PID1
rm -rf ${TESTDIR}
exit $RESULT
