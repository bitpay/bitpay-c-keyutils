//
// Created by paul on 4/27/15.
//

#include "bitpay.h"

int main() {

    char *pem = malloc(240);
    char *sin = malloc(35);

    generatePem(&pem);

    printf("%s\n", pem);

    generateSinFromPem(pem, sin);


    free(pem);
    free(sin);

    return 1;
}

