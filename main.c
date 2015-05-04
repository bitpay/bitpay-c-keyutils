//
// Created by paul on 4/27/15.
//

#include "bitpay.h"

int main() {

    char *pem = malloc(240);
    char *sin = malloc(35);
    char *pub = malloc(67);
    memset(pem, '\0', 240);
    generatePem(&pem);

    printf("%s\n", pem);

    int pubgood = getPublicKeyFromPem(pem, &pub);
    printf("public key: %s\n", pub);
    int singood = generateSinFromPem(pem, &sin);
    if(singood == NOERROR)
        printf("Sin: %s\n", sin);
    else
        printf("Sin Error\n");

    char *message = "https://test.bitpay.com/invoices{\"currency\":\"USD\",\"price\":100,\"token\":\"GVTANyBKSJRdSzy88P72H2LB7gky7o4J8bebVbVaF6pA\"}";
    int signa;
    char *signature = calloc(145, sizeof(char));
	signa = signMessageWithPem(message, pem, &signature);
    if(signa == NOERROR){
        printf("Signature: %s\n", signature);
    }
    else {
        printf("Signature Error.\n");
    };
    free(pem);
    free(pub);
    free(sin);
    free(signature);

    return 1;
}

