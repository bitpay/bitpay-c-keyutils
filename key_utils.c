#include "bitpay.h"

static int genPubKeyFromPrivKeyRaw(char *privateKeyHexString, btc_pubkey *pubkey);

int generatePrivateKey(char **privateKeyHexString) {
    int returnCode = NOERROR;
    btc_key key;

    btc_privkey_init(&key);
    btc_privkey_gen(&key);

    if(btc_privkey_is_valid(&key)) {
        char *privKeyHexString = utils_uint8_to_hex(key.privkey, BTC_ECKEY_PKEY_LENGTH);
        memcpy(*privateKeyHexString, privKeyHexString, BTC_ECKEY_PKEY_LENGTH * 2);
    } else {
        returnCode = ERROR;
    }

    btc_privkey_cleanse(&key);

    return returnCode;
}

int generatePublicKeyFromPrivateKey(char *privateKeyHexString, char **publicKeyHexString) {
    int returnCode = NOERROR;
    btc_pubkey pubkey;
    btc_pubkey_init(&pubkey);

    if(genPubKeyFromPrivKeyRaw(privateKeyHexString, &pubkey) == NOERROR) {
        size_t size = 66;
        btc_pubkey_get_hex(&pubkey, *publicKeyHexString, &size);
    } else {
        returnCode = ERROR;
    }

    btc_pubkey_cleanse(&pubkey);
    
    return returnCode;
}

static int genPubKeyFromPrivKeyRaw(char *privateKeyHexString, btc_pubkey *pubkey) {
    int returnCode = NOERROR;
    btc_key key;

    uint8_t *privateKey = utils_hex_to_uint8(privateKeyHexString);

    btc_privkey_init(&key);
    memcpy(key.privkey, privateKey, BTC_ECKEY_PKEY_LENGTH);

    if(btc_privkey_is_valid(&key)) {
        btc_pubkey_init(pubkey);
        // libbtc generates compressed public keys by default.
        btc_pubkey_from_key(&key, pubkey);

        if(!btc_privkey_verify_pubkey(&key, pubkey)) {
            returnCode = ERROR;
        }
    } else {
        returnCode = ERROR;
    }

    btc_privkey_cleanse(&key);
    
    return returnCode;
}

int generateSinFromPrivateKey(char *privateKeyHexString, char **sin) {
    btc_pubkey pubkey;
    btc_pubkey_init(&pubkey);

    if(genPubKeyFromPrivKeyRaw(privateKeyHexString, &pubkey) == ERROR) {
        btc_pubkey_cleanse(&pubkey);
        return ERROR;
    }

    uint8_t *hash256And160 = calloc(20, sizeof(uint8_t));
    uint8_t *concatenation  = calloc(22, sizeof(uint8_t));
    uint8_t *doubleHash256  = calloc(SHA256_LENGTH, sizeof(uint8_t));
    uint8_t *concatenationCheckSum  = calloc(26, sizeof(uint8_t));
    char *sinBase58  = calloc(SIN_STRING_LENGTH, sizeof(uint8_t));

    // Compute ripemd160(sha256(pubkey)).
    btc_pubkey_get_hash160(&pubkey, hash256And160);

    // Include additional bytes at the beginning.
    memcpy(concatenation, "\x0F\x02", 2);
    memcpy(concatenation + 2, hash256And160, 20);

    // Double hash256 to get the checksum.
    size_t length = 22;
    btc_hash(concatenation, length, doubleHash256);

    // Extract checksum and concatenate.
    memcpy(concatenationCheckSum, concatenation, 22);
    memcpy(concatenationCheckSum + 22, doubleHash256, 4);

    // Encode.
    length = 26;
    size_t lengthb58;
    btc_base58_encode(sinBase58, &lengthb58, concatenationCheckSum, length);
    memcpy(*sin, sinBase58, lengthb58);

    free(hash256And160);
    free(concatenation);
    free(doubleHash256);
    free(concatenationCheckSum);
    free(sinBase58);
    btc_pubkey_cleanse(&pubkey);

    return NOERROR;
}

int signMessageWithPrivateKey(char *message, char *privateKeyHexString, char **signature, btc_bool compact) {
    uint8_t *hash256  = calloc(SHA256_LENGTH, sizeof(uint8_t));
    unsigned char *sig = calloc(MAX_SIGNATURE_BYTES_LENGTH, sizeof(unsigned char));
    size_t outlen = MAX_SIGNATURE_BYTES_LENGTH;
    int returnCode = NOERROR;
    btc_key key;

    uint8_t *privateKey = utils_hex_to_uint8(privateKeyHexString);

    btc_privkey_init(&key);
    memcpy(key.privkey, privateKey, BTC_ECKEY_PKEY_LENGTH);

    btc_hash_sngl_sha256((unsigned char *)message, strlen(message), hash256);

    if(compact) {
        if(!btc_key_sign_hash_compact(&key, hash256, sig, &outlen)) {
            returnCode = ERROR;
        }
    } else {
        if(btc_key_sign_hash(&key, hash256, sig, &outlen)) {
            btc_pubkey pubkey;
            btc_pubkey_init(&pubkey);
            btc_pubkey_from_key(&key, &pubkey);

            if(!btc_pubkey_verify_sig(&pubkey, hash256, sig, outlen)) {
                returnCode = ERROR;
            }

            btc_pubkey_cleanse(&pubkey);
        } else {
            returnCode = ERROR;
        }
    }
    
    char *sigHexString = utils_uint8_to_hex(sig, outlen);
    memcpy(*signature, sigHexString, outlen * 2);

    btc_privkey_cleanse(&key);
    free(hash256);
    free(sig);

    return returnCode;
}