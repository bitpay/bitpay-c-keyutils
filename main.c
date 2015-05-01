//
// Created by paul on 4/27/15.
//

#include "bitpay.h"

int main() {

    char *pem = malloc(240);
    char *sin = malloc(35);

    memset(pem, '\0', 240);
    // generatePem(&pem);

    strcpy(pem, "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEIOg1/L9j0a63o5mRtzmG6N3Cn76MDpbUd2ZYAy4kYmq1oAcGBSuBBAAK\noUQDQgAE2IauvNs634tRrspRnEMbv9dQ84xoqBFilQQkmhHZJde+/8VwpMQ4wIQP\nYB429LjWsy3VyOF8vUpUmIvx17g/7g==\n-----END EC PRIVATE KEY-----\n");

    printf("%s\n", pem);

    generateSinFromPem(pem, sin);

	signMessageWithPem("Hello", pem);

    free(pem);
    free(sin);

    return 1;
}

