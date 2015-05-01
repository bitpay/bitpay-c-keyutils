#include <string.h>
#include "bitpay.h"

int generatePem(char **pem) {

    EC_KEY *eckey = NULL;

    BIO *out = BIO_new(BIO_s_mem());
    BUF_MEM *buf = NULL;
    EC_GROUP *group = NULL;
    
    group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    buf = BUF_MEM_new();
    eckey = EC_KEY_new();

    createNewKey(group, eckey);
    
    EC_GROUP_free(group);

    PEM_write_bio_ECPrivateKey(out, eckey, NULL, NULL, 0, NULL, NULL);

    BIO_get_mem_ptr(out, &buf);

     //TODO: refactor?
    if ( buf->data[219] == '\n') {
        memcpy(*pem, buf->data, 219);
    } else if ( buf->data[221] == '\n') {
        memcpy(*pem, buf->data, 221);
    } else {
        memcpy(*pem, buf->data, 223);
    }

    EC_KEY_free(eckey);
    BIO_free_all(out);

    return NOERROR;
};

int createNewKey(EC_GROUP *group, EC_KEY *eckey) {

    int asn1Flag = OPENSSL_EC_NAMED_CURVE;
    int form = POINT_CONVERSION_UNCOMPRESSED;

    EC_GROUP_set_asn1_flag(group, asn1Flag);
    EC_GROUP_set_point_conversion_form(group, form);
    EC_KEY_set_group(eckey, group);

    int resultFromKeyGen = EC_KEY_generate_key(eckey);

    if (resultFromKeyGen != 1){
        return ERROR;
    }

    return NOERROR;
}

int generateSinFromPem(char *pem, char *sin) {

    char *pub =     calloc(66, sizeof(char));

    u_int8_t *outBytesPub = calloc(33, sizeof(u_int8_t));
    u_int8_t *outBytesOfStep1 = calloc(33, sizeof(u_int8_t));
    u_int8_t *outBytesOfStep3 = calloc(23, sizeof(u_int8_t));
    u_int8_t *outBytesOfStep4a = calloc(33, sizeof(u_int8_t));

    char *step1 =   calloc(65, sizeof(char));
    char *step2 =   calloc(41, sizeof(char));
    char *step3 =   calloc(45, sizeof(char));
    char *step4a =  calloc(65, sizeof(char));
    char *step4b =  calloc(65, sizeof(char));
    char *step5 =   calloc(9, sizeof(char));
    char *step6 =   calloc(53, sizeof(char));

    getPublicKeyFromPem(pem, pub);
    //strcpy(pub, "020AFABD2AC85F5166FC134E44A737D04D1822216E012E6920CFC54B04E30A5045");

    unsigned int inLength = strlen(pub);
    
    createDataWithHexString(pub, &outBytesPub);
    digestofHex(outBytesPub, &step1, "sha256");
    step1[64] = '\0';

    createDataWithHexString(step1, &outBytesOfStep1);
    digestofHex(outBytesOfStep1, &step2, "ripemd160");
    step2[40] = '\0';
   
    memcpy(step3, "0F02", 4);
    memcpy(step3+4, step2, 40);
    // sprintf(step3, "0F02%s", step2);
    step3[44] = '\0';

    createDataWithHexString(step3, &outBytesOfStep3);
    digestofHex(outBytesOfStep3, &step4a, "sha256");
    step4a[64] = '\0';

    createDataWithHexString(step4a, &outBytesOfStep4a);
    digestofHex(outBytesOfStep4a, &step4b, "sha256");
    step4b[64] = '\0';


    memcpy(step5, step4b, 8);
    
    sprintf(step6, "%s%s", step3, step5);

    BIGNUM *bnfromhex = BN_new();
    BN_hex2bn(&bnfromhex, step6);
    char *codeString = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";


    char buildString[35];
    int lengthofstring = 0;
    int startat = 34;

    while(BN_is_zero(bnfromhex) != 1){
      int rem = BN_mod_word(bnfromhex, 58);
      buildString[startat] = codeString[rem];
      BN_div_word(bnfromhex, 58);
      lengthofstring++;
      startat--;
    }
    startat ++;
    char *base58encode = calloc(lengthofstring, sizeof(char));
    int j = 0;
    int i;
    for (i = startat; i < lengthofstring; i++) {
      base58encode[j] = buildString[i];
      j++;
    }


    printf("Compressed Pub: %s\n\n", pub);
    printf("step 1: %s\n", step1);
    printf("Step 2: %s\n", step2);
    printf("step 3: %s\n", step3);
    printf("step 4a: %s\n", step4a);
    printf("step 4b: %s\n", step4b);
    printf("Step 5: %s\n", step5);
    printf("Step 6: %s\n", step6);
    printf("Base58: %s\n", base58encode);
    
    free(pub);  
    free(step1);
    free(step2);
    free(step3);
    free(step4a);
    free(step4b);
    free(step6);
    free(step5);
    free(base58encode);

    free(outBytesPub);
    free(outBytesOfStep1);
    free(outBytesOfStep3);
    free(outBytesOfStep4a);
    
    return NOERROR;
}

int getPublicKeyFromPem(char *pemstring, char *pubkey) {

    EC_KEY *eckey = NULL;
    EC_KEY *key = NULL;
    EC_POINT *pub_key = NULL;
    BIO *in = NULL;
    const EC_GROUP *group = NULL;
    char *hexPoint = NULL;
    char xval[65] = "";
    char yval[65] = "";
    char *oddNumbers = "13579BDF";

    BIGNUM start;
    const BIGNUM *res;
    BN_CTX *ctx;

    BN_init(&start);
    ctx = BN_CTX_new();

    res = &start;

    const char *cPem = pemstring;
    in = BIO_new(BIO_s_mem());
    BIO_puts(in, cPem);
    key = PEM_read_bio_ECPrivateKey(in, NULL, NULL, NULL);
    res = EC_KEY_get0_private_key(key);

    eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
    group = EC_KEY_get0_group(eckey);
    pub_key = EC_POINT_new(group);

    EC_KEY_set_private_key(eckey, res);

    if (!EC_POINT_mul(group, pub_key, res, NULL, NULL, ctx)) {
        return ERROR;
    }

    EC_KEY_set_public_key(eckey, pub_key);

    hexPoint = EC_POINT_point2hex(group, pub_key, 4, ctx);

    char *hexPointxInit = hexPoint + 2;
    memcpy(xval, hexPointxInit, 64);

    char *hexPointyInit = hexPoint + 66;
    memcpy(yval, hexPointyInit, 64);

    char *lastY = hexPoint + 129;

    if (strstr(oddNumbers, lastY) != NULL) {
        sprintf(pubkey, "03%s", xval);
    } else {
        sprintf(pubkey, "02%s", xval);
    }

    BN_CTX_free(ctx);
    EC_KEY_free(eckey);
    EC_KEY_free(key);
    EC_POINT_free(pub_key);
    BIO_free(in);

    return NOERROR;
};

int createDataWithHexString(char *inputString, uint8_t **result) {

    int i, o = 0;
    uint8_t outByte = 0;

    int inLength = strlen(inputString);

    uint8_t *outBytes = malloc(sizeof(uint8_t) * ((inLength / 2) + 1));

    for (i = 0; i < inLength; i++) {
        uint8_t c = inputString[i];
        int8_t value = -1;

        if      (c >= '0' && c <= '9') value =      (c - '0');
        else if (c >= 'A' && c <= 'F') value = 10 + (c - 'A');
        else if (c >= 'a' && c <= 'f') value = 10 + (c - 'a');

        if (value >= 0) {
            if (i % 2 == 1) {
                outBytes[o++] = (outByte << 4) | value;
                outByte = 0;
            } else {
                outByte = value;
            }

        } else {
            if (o != 0) break;
        }
    }

    memcpy(*result, outBytes, inLength/2);

    free(outBytes);

    return NOERROR;
}


int digestofHex(uint8_t *message, char **output, char *type) {
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len, i;

    OpenSSL_add_all_digests();

    md = EVP_get_digestbyname(type);
    mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, message, strlen(message));
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    EVP_MD_CTX_destroy(mdctx);

    char *digest = calloc(md_len*2, sizeof(char));
    for(i = 0; i < md_len; i++)
      sprintf(&digest[strlen(digest)], "%02x", md_value[i]);

    memcpy(*output, digest, strlen(digest));
    free(digest);
    /* Call this once before exit. */
    EVP_cleanup();
    return 0;
}
