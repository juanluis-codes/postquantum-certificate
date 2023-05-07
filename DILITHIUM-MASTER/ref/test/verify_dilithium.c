#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <math.h>
#include "../randombytes.h"
#include "../sign.h"

#define MLEN 59

int verify(uint8_t *sm, size_t smlen, uint8_t *pk1, uint8_t *m) {
    FILE* kyber_keys_file;

    //uint8_t pk1[CRYPTO_PUBLICKEYBYTES];
    //uint8_t sk1[CRYPTO_SECRETKEYBYTES];
    //char temp[] = "000";

    int ret, j;
    uint8_t b;
    //size_t mlen, smlen;
    size_t mlen;
    //smlen = 0;
    //uint8_t m[1184 + CRYPTO_BYTES];
    uint8_t m2[1184 + CRYPTO_BYTES];
    //uint8_t sm[1184 + CRYPTO_BYTES];
    //int* smlenw = malloc(sizeof(char));

/*     kyber_keys_file = fopen("KEYS/issuing_keys.txt", "r");

    char x = fgetc(kyber_keys_file);

    while(x != '\n') {
        x = fgetc(kyber_keys_file);
    }

    x = fgetc(kyber_keys_file);
    
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

    fclose(kyber_keys_file);

    printf("Public key\n");
    for(long unsigned int i = 0; i < sizeof(pk1) / sizeof(pk1[0]); i++) {   
        printf("%d.", pk1[i]);
    }

    kyber_keys_file = fopen(filename, "r");

    x = fgetc(kyber_keys_file);
    while(x != 'C') {
        x = fgetc(kyber_keys_file);
    }

    x = fgetc(kyber_keys_file);
    while(x != 'C') {
        x = fgetc(kyber_keys_file);
    }
    j = 0;

    while(x != '\n') {
        if(x == ',' || isdigit(x) == 0) {
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

        m[j] = (uint8_t) atoi(temp);

        j++;
    }

    j = 0;

    while(x != 'F') {
        x = fgetc(kyber_keys_file);
    }

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

        sm[j] = (uint8_t) atoi(temp);

        j++;
    }

    while(x != 'L') {
        x = fgetc(kyber_keys_file);
    }

    j = 0;

    while(x != '\n') {
        if(isdigit(x) == 0) {
            x = fgetc(kyber_keys_file);
            continue;
        }

        smlenw[j] = x - '0';
        j++;
        x = fgetc(kyber_keys_file);
        if(isdigit(x) != 0) {
            smlenw = realloc(smlenw, sizeof(char) * j);
        }
    }

    smlen = 0;
    for(int i = 0; i < j; i++) {
        smlen = smlen + (smlenw[i] * (pow(10, j - i - 1)));
    }

    fclose(kyber_keys_file); */

    ret = crypto_sign_open(m2, &mlen, sm, smlen, pk1);

    if(ret) {
        fprintf(stderr, "Verification failed\n");
        return -1;
    }

    if(smlen != 1184 + CRYPTO_BYTES) {
        fprintf(stderr, "Signed message lengths wrong\n");
        return -1;
    }

    if(mlen != 1184) {
      fprintf(stderr, "Message lengths wrong\n");
      return -1;
    }

    for(int i = 0; i < 1184; ++i) {
        if(m2[i] != m[i]) {
            fprintf(stderr, "Messages don't match\n");
            return -1;
        }
    }

    //free(smlenw);
    return 0;
}

//int main(void) {

//    return 0;
//}