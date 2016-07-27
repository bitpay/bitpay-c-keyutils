#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <btc.h>
#include <ecc_key.h>
#include <hash.h>
#include <base58.h>
#include <ecc.h>
#include <utils.h>

#define	NOERROR	0
#define	ERROR 	-1
#define SHA256_LENGTH 32
#define SIN_STRING_LENGTH 36
#define MAX_SIGNATURE_BYTES_LENGTH 74
#define MAX_SIGNATURE_STRING_LENGTH 149

int generatePrivateKey(char **privateKeyHexString);
int generatePublicKeyFromPrivateKey(char *privateKeyHexString, char **publicKeyHexString);
int generateSinFromPrivateKey(char *privateKeyHexString, char **sin);
int signMessageWithPrivateKey(char *message, char *privateKeyHexString, char **signature, btc_bool compact);