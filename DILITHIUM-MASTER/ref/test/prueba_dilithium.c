#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h> 
#include "../randombytes.h"
#include "../sign.h"

#define MLEN 59
int main(void)
{
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];

    printf("Generating keys...\n");
    crypto_sign_keypair(pk, sk);

    printf("Creating file...\n");
    FILE* kyber_keys_file;
    kyber_keys_file = fopen("../txt/dilithium_keys.txt", "wt");
  
    fputs("Public key:", kyber_keys_file);

    for(long unsigned int i = 0; i < sizeof(pk) / sizeof(pk[0]); i++) {
  	    fprintf(kyber_keys_file, "%d.", pk[i]);
    }

    fputs("\nPrivate key:", kyber_keys_file);

    for(long unsigned int i = 0; i < sizeof(sk) / sizeof(sk[0]); i++) {
  	    fprintf(kyber_keys_file, "%d.", sk[i]);
    }

    fclose(kyber_keys_file);

    uint8_t pk1[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk1[CRYPTO_SECRETKEYBYTES];
    char string1[10000];
    char string2[10000];
    char temp[] = "000";

    int j = 0;
    int ret;
    size_t mlen, smlen;
    uint8_t b;
    uint8_t m[MLEN + CRYPTO_BYTES];
    uint8_t m2[MLEN + CRYPTO_BYTES];
    uint8_t sm[MLEN + CRYPTO_BYTES];

    printf("Reading file...");
    kyber_keys_file = fopen("../txt/dilithium_keys.txt", "r");

    char x = fgetc(kyber_keys_file);
    while(x != '\n') {
        if(x == '.' || isdigit(x) == 0) {
            x = fgetc(kyber_keys_file);
            continue;
        }

        for(int i = 2; i >= 0; i--) {
            if(x == '.') {
                x = fgetc(kyber_keys_file);
                break;
            }

            if(i == 2) {
                temp[i] = x;
                temp[i - 1] = '0';
                temp[i - 2] = '0';
            }

            if(i == 1) {
                temp[i] = temp[i + 1];
                temp[i + 1] = x;
            }

            if(i == 0) {
                temp[i] = temp[i + 1];
                temp[i + 1] = temp[i + 2];
                temp[i + 2] = x;
            }

            x = fgetc(kyber_keys_file);
        }

        pk1[j] = (uint8_t) atoi(temp);
        printf("%d.", pk1[j]);

        j++;
    }

    x = fgetc(kyber_keys_file);
    j = 0;

    while(feof(kyber_keys_file) == 0) {
        if(x == '.' || isdigit(x) == 0) {
            x = fgetc(kyber_keys_file);
            continue;
        }

        for(int i = 2; i >= 0; i--) {
            if(x == '.') {
                x = fgetc(kyber_keys_file);
                break;
            }

            if(i == 2) {
                temp[i] = x;
                temp[i - 1] = '0';
                temp[i - 2] = '0';
            }

            if(i == 1) {
                temp[i] = temp[i + 1];
                temp[i + 1] = x;
            }

            if(i == 0) {
                temp[i] = temp[i + 1];
                temp[i + 1] = temp[i + 2];
                temp[i + 2] = x;
            }

            x = fgetc(kyber_keys_file);
        }

        sk1[j] = (uint8_t) atoi(temp);

        j++;
    }

    fclose(kyber_keys_file);

    printf("Public key\n");
    for(long unsigned int i = 0; i < sizeof(pk1) / sizeof(pk1[0]); i++) {   
        printf("%d.", pk1[i]);
    }

    printf("\nPrivate key\n");
    for(long unsigned int i = 0; i < sizeof(sk1) / sizeof(sk1[0]); i++) {
        printf("%d", sk1[i]);
    }

    randombytes(m, MLEN);

    crypto_sign(sm, &smlen, m, MLEN, sk1);
    ret = crypto_sign_open(m2, &mlen, sm, smlen, pk1);

    if(ret) {
        fprintf(stderr, "Verification failed\n");
        return -1;
    }

    if(smlen != MLEN + CRYPTO_BYTES) {
        fprintf(stderr, "Signed message lengths wrong\n");
        return -1;
    }

    if(mlen != MLEN) {
        fprintf(stderr, "Message lengths wrong\n");
        return -1;
    }

    for(int i = 0; i < MLEN; ++i) {
        if(m2[i] != m[i]) {
            fprintf(stderr, "Messages don't match\n");
            return -1;
        }
    }

    if(!ret) {
        fprintf(stderr, "Verification\n");
        return 1;
    }

    return 0;
}
