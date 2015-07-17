#gcc -o key_tests -lcrypto tests.c key_utils.c -I/usr/local/Cellar/openssl/1.0.2/include/
gcc key_utils.c tests.c -o key_tests -lcrypto -lssl -Wall -O0 -g
for (( c=1; c<=50; c++ ))
  do
	./key_tests
done
