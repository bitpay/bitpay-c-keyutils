# Using the BitPay Key Utilities Library

This library provides utilities for use with the BitPay API. It enables creating keys, retrieving public keys, creating the SIN that is used in retrieving tokens from BitPay, and signing payloads for the `X-Signature` header in a BitPay API request.

## Quick Start
### Installation

Clone the github repository and include the bitpay.h header in your project. This should give you access to the functions:

```c
int generatePrivateKey(char **privateKeyHexString) // Creates a btc_key and returns a string with the hexadecimal representation of it.
int generatePublicKeyFromPrivateKey(char *privateKeyHexString, char **publicKeyHexString) // Takes a private key hex string and returns the corresponding compressed public key as an hex string.
int generateSinFromPrivateKey(char *privateKeyHexString, char **sin) // Gets the base58 unique identifier associated with the private key.
int signMessageWithPrivateKey(char *message, char *privateKeyHexString, char **signature, btc_bool compact) // Sets signature to the signature of the sha256 of the message; signature can be either in DER or compact format.
```

## API Documentation

API Documentation is available on the [BitPay site](https://bitpay.com/api).

## Running the Tests

```bash
$ sh build.sh
```