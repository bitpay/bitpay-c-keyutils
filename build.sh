rm -fr ./key_utils_tests
gcc key_utils.c tests.c -o key_utils_tests -I./lib/libbtc/src/logdb/include -I./lib/libbtc/src/logdb/include/logdb -I./lib/libbtc/include/btc -I./lib/libbtc/src/secp256k1/include ./lib/libbtc/.libs/libbtc.a ./lib/libbtc/src/logdb/.libs/liblogdb.a ./lib/libbtc/src/secp256k1/.libs/libsecp256k1.a 
./key_utils_tests
