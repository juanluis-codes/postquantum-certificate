#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h> 
#include "../randombytes.h"
#include "../sign.h"

int sign(char *filename, uint8_t *sk1, uint8_t *pk1);

int sign(char *filename, uint8_t *sk1, uint8_t *pk1) {
    FILE* kyber_keys_file;

    size_t smlen;
    uint8_t sm[1184 + CRYPTO_BYTES];

    crypto_sign(sm, &smlen, pk1, 1184, sk1);

    kyber_keys_file = fopen(filename, "a");

    fputs("[", kyber_keys_file);

    for(long unsigned int i = 0; i < sizeof(sm) / sizeof(sm[0]); i++) {
        if(i == (sizeof(sm) / sizeof(sm[0])) - 1) {
            fprintf(kyber_keys_file, "%d]", sm[i]);
        } else {
            fprintf(kyber_keys_file, "%d,", sm[i]);
        }
    }

    fprintf(kyber_keys_file, "\nLongitud de la firma: %zu", smlen);

    fclose(kyber_keys_file);

    return 0;
}

//int main(void) {

//    return 0;
//}