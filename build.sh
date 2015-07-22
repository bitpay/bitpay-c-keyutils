#gcc -o key_tests -lcrypto tests.c key_utils.c -I/usr/local/Cellar/libressl/2.1.6/include/
gcc key_utils.c tests.c -o key_tests -lcrypto -lssl -Wall -O0 -g
./key_tests
