#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h> 
#include "../randombytes.h"
#include "../sign.h"

int generateKeys();

int generateKeys() {
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
	uint8_t sk[CRYPTO_SECRETKEYBYTES];

    crypto_sign_keypair(pk, sk);

	FILE* public_key_file;
	FILE* private_key_file;
	public_key_file = fopen("KEYS/issuing_public_key_dilithium.pub", "wt");

    fputs("DILITHIUM\n[", public_key_file);

    for(long unsigned int i = 0; i < sizeof(pk) / sizeof(pk[0]); i++) {
    	if(i == ((sizeof(pk) / sizeof(pk[0])) - 1)) {
    		fprintf(public_key_file, "%d]", pk[i]);
    	} else {
    		fprintf(public_key_file, "%d,", pk[i]);
    	}
    }

	fclose(public_key_file);
	private_key_file = fopen("KEYS/issuing_private_key_dilithium", "wt");

    fputs("- - - - DILITHIUM PRIVATE KEY BEGINS - - - -\n[", private_key_file);

    for(long unsigned int i = 0; i < sizeof(sk) / sizeof(sk[0]); i++) {
    	if(i == ((sizeof(sk) / sizeof(sk[0])) - 1)) {
    		fprintf(private_key_file, "%d]", sk[i]);
    	} else {
    		fprintf(private_key_file, "%d,", sk[i]);
    	}
    }

	fputs("\n- - - - DILITHIUM PRIVATE KEY ENDS - - - -", private_key_file);

    fclose(private_key_file);

	return 0;
}
