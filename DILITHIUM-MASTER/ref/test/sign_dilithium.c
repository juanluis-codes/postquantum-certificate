#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h> 
#include "../randombytes.h"
#include "../sign.h"

#define MLEN 59

int sign(char *filename, uint8_t *sk1, size_t lensk1, uint8_t *pk1, size_t lenpk1) {
    FILE* kyber_keys_file;

    //uint8_t pk1[1184 + CRYPTO_BYTES];
    //uint8_t sk1[CRYPTO_SECRETKEYBYTES];
    //char temp[] = "000";

    int j = 0;
    size_t smlen;
    uint8_t sm[1184 + CRYPTO_BYTES];

    printf("Reading file...");
/*     kyber_keys_file = fopen("KEYS/issuing_keys.txt", "r");

    char x = fgetc(kyber_keys_file);

    while(x != '\n') {
        x = fgetc(kyber_keys_file);
    }

    x = fgetc(kyber_keys_file);

    while(x != '\n') {
        x = fgetc(kyber_keys_file);
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

    kyber_keys_file = fopen("KEYS/encryption_kyber_keys.txt", "r");

    x = fgetc(kyber_keys_file);
    j = 0;

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

        j++;
    }

    fclose(kyber_keys_file); */

    //randombytes(m, MLEN);

    crypto_sign(sm, &smlen, pk1, 1184, sk1);

    kyber_keys_file = fopen(filename, "a");

    for(long unsigned int i = 0; i < sizeof(sm) / sizeof(sm[0]); i++) {
        if(i == (sizeof(sm) / sizeof(sm[0])) - 1) {
            fprintf(kyber_keys_file, "%d", sm[i]);
        } else {
            fprintf(kyber_keys_file, "%d.", sm[i]);
        }
    }

    fprintf(kyber_keys_file, "\nLongitud de la firma: %zu", smlen);

    fclose(kyber_keys_file);

    return 0;
}

//int main(void) {

//    return 0;
//}