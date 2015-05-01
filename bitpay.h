/*
 * File:   bitpay.h
 * Author: paul
 *
 * Created on April 27, 2015, 3:44 PM
 */


#include <stdio.h>
#include <stdlib.h>
#include "openssl/ec.h"
#include "openssl/bn.h"
#include "openssl/sha.h"
#include "openssl/ripemd.h"
#include "openssl/ecdsa.h"
#include "openssl/pem.h"

#define	NOERROR	0
#define	ERROR 	-1

int generatePem(char **pem);
int createNewKey(EC_GROUP *group, EC_KEY *eckey);
int generateSinFromPem(char *pem, char *sin);
int getPublicKeyFromPem(char *pemstring, char *pubkey);
int hexOfsha256(uint8_t *data, int inLength, char *output);
int digestofHex(uint8_t *message, char **output, char *type);
int createDataWithHexString(char *inputString, uint8_t **result);
int base58encode(char *input, char *base58encode);
