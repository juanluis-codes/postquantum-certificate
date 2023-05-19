#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <math.h>
#include "../randombytes.h"
#include "../sign.h"

int verify(uint8_t *sm, size_t smlen, uint8_t *pk1, uint8_t *m);

int verify(uint8_t *sm, size_t smlen, uint8_t *pk1, uint8_t *m) {
    int ret;
    size_t mlen;
    uint8_t m2[1184 + CRYPTO_BYTES];

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

    return 0;
}