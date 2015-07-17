#include "bitpay.h"

static void runPemTest();
static void runPublicKeyTest();
static void runSinTest();
static void runSignatureTest();

int main() {
    runPemTest();
    //runPublicKeyTest();
    //runSinTest();
    //runSignatureTest();
    return 0;
}

static void runSignatureTest() {
    int signa;
    char *message = "https://test.bitpay.com/invoices{\"currency\":\"USD\",\"price\":100,\"token\":\"GVTANyBKSJRdSzy88P72H2LB7gky7o4J8bebVbVaF6pA\"}";
    char *pem = malloc(240);
    char *signature = calloc(145, sizeof(char));
    char *actual_start = calloc(4, sizeof(char));
    char *expected_start = calloc(5, sizeof(char));

    pem[239]='\0';
    generatePem(&pem);
    signa = signMessageWithPem(message, pem, &signature);
    if (signa == ERROR) {
        printf("Signature Error.\n");
    };
    actual_start[3] = '\0';
    memcpy(actual_start, signature, 4);
    if (strlen(signature) == 138) {
        memcpy(expected_start, "3043", 4);
        expected_start[4] = '\0';
    } else if (strlen(signature) == 140) {
        memcpy(expected_start, "3044", 4);
        expected_start[4] = '\0';
    } else if (strlen(signature) == 142) {
        memcpy(expected_start, "3045", 4);
        expected_start[4] = '\0';
    } else if (strlen(signature) == 144) {
        memcpy(expected_start, "3046", 4);
        expected_start[4] = '\0';
    } else {
        printf("%lu is not a valid signature length\n", (unsigned long)strlen(signature));
    }

    if (strcmp(actual_start, expected_start) == 0)
        printf(".");
    else
        printf("Signature test - Expected: %s, Actual: %s for %s\n", expected_start, actual_start, signature);
    printf("\n");

    free(expected_start);
    free(pem);
    free(signature);
    free(actual_start);
}

static void runSinTest() {
    char *fixed_pem = "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEIOg1/L9j0a63o5mRtzmG6N3Cn76MDpbUd2ZYAy4kYmq1oAcGBSuBBAAK\noUQDQgAE2IauvNs634tRrspRnEMbv9dQ84xoqBFilQQkmhHZJde+/8VwpMQ4wIQP\nYB429LjWsy3VyOF8vUpUmIvx17g/7g==\n-----END EC PRIVATE KEY-----\n";
    int singood;
    char *expected_sin = "Tf41EHiUGugMMeAR35DXfUrfkjzwmvqRQkz";
    char *sin = calloc(35, sizeof(char));

    singood = generateSinFromPem(fixed_pem, &sin);
    if (singood == ERROR)
        printf("Sin Error\n");
    if (strcmp(expected_sin, sin) == 0)
        printf(".");
    else
        printf("Sin test - Expected: %s, Actual: %s\n", expected_sin, sin);

    free(sin);
}

static void runPublicKeyTest(){
    char *pub = malloc(67);
    char *fixed_pem = "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEIOg1/L9j0a63o5mRtzmG6N3Cn76MDpbUd2ZYAy4kYmq1oAcGBSuBBAAK\noUQDQgAE2IauvNs634tRrspRnEMbv9dQ84xoqBFilQQkmhHZJde+/8VwpMQ4wIQP\nYB429LjWsy3VyOF8vUpUmIvx17g/7g==\n-----END EC PRIVATE KEY-----\n";
    char *expected_pub = "02D886AEBCDB3ADF8B51AECA519C431BBFD750F38C68A811629504249A11D925D7";
    int pubgood = getPublicKeyFromPem(fixed_pem, &pub);
    if (pubgood == ERROR)
        printf("Error retrieving public key\n");
    if (strcmp(expected_pub, pub) == 0)
        printf(".");
    else
        printf("Public key test - Expected: %s, Actual: %s\n", expected_pub, pub);

    free(pub);
}

static void runPemTest() {
    char *expected_pem_S = "MHQCAQ";
    char *expected_pem_N = "SuBBAAK\n";
    char *actual_pem_S = calloc(7, sizeof(char));
    char *actual_pem_N = calloc(9, sizeof(char));
    char *pem = calloc(240, sizeof(char));

    pem[239]='\0';

    if (generatePem(&pem) == ERROR) {
        printf("Error in generatePem");
    }

    actual_pem_S[6] = '\0';
    actual_pem_N[8] = '\0';
    memcpy(actual_pem_S, pem+31, 6);
    memcpy(actual_pem_N, pem+88, 8);

    if (strcmp(expected_pem_S, actual_pem_S) == 0)
        printf(".");
    else
        printf("Pem test - Expected: %s, Actual: %s\n", expected_pem_S, actual_pem_S);
    if (strcmp(expected_pem_N, actual_pem_N) == 0)
        printf(".");
    else
        printf("Pem test - Expected: %s, Actual: %s\n", expected_pem_N, actual_pem_N);

    free(pem);
    free(actual_pem_S);
    free(actual_pem_N);
}
