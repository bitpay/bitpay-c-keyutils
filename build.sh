# gcc -o key_tests -lcrypto tests.c key_utils.c -I/usr/local/Cellar/openssl/1.0.2/include/
#gcc -o key_tests -lcrypto tests.c key_utils.c -I/usr/local/Cellar/openssl/1.0.1i/include/
gcc -o key_tests -lcrypto tests.c key_utils.c
./key_tests 
