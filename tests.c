#include "bitpay.h"

static void runPrivateKeyTest();
static void runPublicKeyTest();
static void runSinGenerationTest();
static void runSignatureTest();

int main() {
    btc_ecc_start();

    runPrivateKeyTest();
    runPublicKeyTest();
    runSinGenerationTest();
    runSignatureTest();

    btc_ecc_stop();

    return 0;
}

static void runPrivateKeyTest() {
    char *privateKeyHexString = calloc(BTC_ECKEY_PKEY_LENGTH * 2, sizeof(char));
    
    printf("(1/4) Running Private Key Test...\n\t");

    if (generatePrivateKey(&privateKeyHexString) == ERROR) {
        printf("\n\tError in generatePrivateKey! Invalid Key.\n\t");
    } else {
        printf("\n\tOK!");
    }

    free(privateKeyHexString);
}

static void runPublicKeyTest() {
    char *privateKeyHexString = "97811b691dd7ebaeb67977d158e1da2c4d3eaa4ee4e2555150628acade6b344c";
    char *publicKeyHexString = calloc(66, sizeof(char));
    char publicKeyExpected[] = "02326209e52f6f17e987ec27c56a1321acf3d68088b8fb634f232f12ccbc9a4575";

    printf("\n\n(2/4) Running Public Key Test...\n\t");

    if(generatePublicKeyFromPrivateKey(privateKeyHexString, &publicKeyHexString) == ERROR) {
        printf("\n\tError in generatePublicKeyFromPrivateKey!\n\t");
    } else {
        if(strcmp(publicKeyHexString, publicKeyExpected) != 0) {
            printf("\n\tPublic Keys are not equal!\n\t");
        } else {
            printf("\n\tOK!");
        }
    }

    free(publicKeyHexString);
}

static void runSinGenerationTest() {
    char *privateKeyHexString = "97811b691dd7ebaeb67977d158e1da2c4d3eaa4ee4e2555150628acade6b344c";                         
    char *sin = calloc(SIN_STRING_LENGTH, sizeof(char));
    char sinExpected[] = "Tf3yr5tYvccKNVrE26BrPs6LWZRh8woHwjR";

    printf("\n\n(3/4) Running SIN Generation Test...\n\t");

    if(generateSinFromPrivateKey(privateKeyHexString, &sin) == ERROR) {
        printf("\n\tError in generateSinFromPrivateKey!\n\t");
    } else {
        if(strcmp(sin, sinExpected) != 0) {
            printf("\n\tSINs are not equal!\n\t");
        } else {
            printf("\n\tOK!");
        }
    }

    free(sin);
}

static void runSignatureTest() {
    char *privateKeyHexString = "000000000000000000000000000000000000000000056916d0f9b31dc9b637f3";
    char *message = "The question of whether computers can think is like the question of whether submarines can swim.";
    char *signature = calloc(MAX_SIGNATURE_STRING_LENGTH, sizeof(char));
    char sigDERExpected[] = "3045022100cde1302d83f8dd835d89aef803c74a119f561fbaef3eb9129e45f30de86abbf9022006ce643f5049ee1f27890467b77a6a8e11ec4661cc38cd8badf90115fbd03cef";
    char sigCompactExpected[] = "cde1302d83f8dd835d89aef803c74a119f561fbaef3eb9129e45f30de86abbf906ce643f5049ee1f27890467b77a6a8e11ec4661cc38cd8badf90115fbd03cef";

    printf("\n\n(4/4) Running DER and Compact Signature Test...\n\t");

    if(signMessageWithPrivateKey(message, privateKeyHexString, &signature, false) == ERROR) {
        printf("\n\tError in signMessageWithPrivateKey!\n\t");
    } else {
        if(strcmp(signature, sigDERExpected) != 0) {
            printf("\n\tDER Signatures are not equal!\n\n");
        } else {
            printf("\n\tOK!\n");
        }
    }

    memset(signature, 0, strlen(signature));

    if(signMessageWithPrivateKey(message, privateKeyHexString, &signature, true) == ERROR) {
        printf("\n\tError in signMessageWithPrivateKey!\n\t");
    } else {
        if(strcmp(signature, sigCompactExpected) != 0) {
            printf("\n\tCompact Signatures are not equal!\n\n");
        } else {
            printf("\n\tOK!\n\n");
        }
    }

    free(signature);
}