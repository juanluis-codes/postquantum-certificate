# IMPORTS
import random
import sympy
# LOCAL IMPORTS
import GCD as gcd

# RSAKeyset
# This class defines a RSA keyset
# Attributes:
# e -> (int) RSA exponent. Public key
# n -> (int) RSA module. Public key
# d -> (int) RSA private key
class RSAKeyset:
    # Builder
    def __init__(self, e = 65537, n = 0, d = 0, generate = True):
        self.e = e

        if(not(generate)):
            self.n = n
            self.d = d
        else:
            p = RSAKeyset._randomPrimeGenerator(1024)
            q = RSAKeyset._randomPrimeGenerator(1024)
            self.n = p * q
            fi = (p - 1) * (q - 1)

            self._privateKeyGenerator(fi)

    # Public exponent getter
    # Return: (int) RSA exponent. Public key
    def getE(self):
        return self.e

    # Public module getter
    # Return: (int) RSA module. Public key
    def getN(self):
        return self.n

    # Private key getter
    # Return: (int) RSA private key
    def getD(self):
        return self.d
    
    # Object to string
    def __repr__(self):
        return "[Exponent: {}, Module: {}, Private key: {}]".format(self.e, self.n, self.d)

    # This method generates a random prime
    # Parameters:
    # length -> (int) Prime length
    # Return: (int) Random prime
    def _randomPrimeGenerator(length):
        prime = random.SystemRandom().randint(pow(2, length), pow(2, length + 1))

        if(prime % 2 == 0):
            prime = prime + 1

        while(not(sympy.isprime(prime))):
            prime = prime + 2
        
        return prime

    # This method generates a RSA private key
    # Parameters:
    # fi -> (int) It helps to calculate the RSA private key
    # Return: (void)
    def _privateKeyGenerator(self, fi):
        x = gcd.GCD(self.e, fi)
        self.d = x.getU() % fi

# RSACipher
# This class defines the methods for a RSA cipher
# Attributes:
# rsa_keyset -> (RSAKeyset) RSA keyset
class RSACipher:
    # Builder
    def __init__(self, rsa_keyset = RSAKeyset()):
        self.rsa_keyset = rsa_keyset

    # RSA keyset getter
    # Return: (int) RSA keyset
    def getRSAKeyset(self):
        return self.rsa_keyset
    
    # Public exponent getter
    # Return: (int) RSA exponent. Public key
    def getRSAKeysetE(self):
        return self.rsa_keyset.getE()

    # Public module getter
    # Return: (int) RSA module. Public key
    def getRSAKeysetN(self):
        return self.rsa_keyset.getN()
    
    # Private key getter
    # Return: (int) RSA private key
    def getRSAKeysetD(self):
        return self.rsa_keyset.getD()
    
    # Object to string
    def __repr__(self):
        return "{}".format(self.rsa_keyset)

    # This method encrypts a message using the RSA algorithm
    # Parameters:
    # to_encrypt -> (int) Message to encrypt
    # n -> (int) RSA module. Public key
    # e -> (int) RSA exponent. Public key
    # Return: (int) Encrypted message
    def encrypt(to_encrypt, n, e):
        encryption = pow(to_encrypt, e, n)
        return encryption

    # This method decrypts a message using the RSA algorithm
    # Parameters:
    # to_decrypt -> (int) Message to decrypt
    # d -> (int) RSA private key
    # n -> (int) RSA module. Public key
    # Return: (int) Decrypted message
    def decrypt(to_decrypt, private_key, n):
        decryption = pow(to_decrypt, private_key, n)
        return decryption

# RSASignature
# This class defines the methods for a RSA signature
# Attributes:
# rsa_keyset -> (RSAKeyset) RSA keyset
class RSASignature:
    # Builder
    def __init__(self, rsa_keyset = RSAKeyset()):
        self.rsa_keyset = rsa_keyset
        self.signature = None

    # RSA keyset getter
    # Return: (RSAKeyset) RSA keyset
    def getRSAKeyset(self):
        return self.rsa_keyset
    
    # Public exponent getter
    # Return: (int) RSA exponent. Public key
    def getRSAKeysetE(self):
        return self.rsa_keyset.getE()

    # Public module getter
    # Return: (int) RSA module. Public key
    def getRSAKeysetN(self):
        return self.rsa_keyset.getN()
    
    # Private key getter
    # Return: (int) RSA private key
    def getRSAKeysetD(self):
        return self.rsa_keyset.getD()
    
    def getSignature(self):
        return self.signature

    # Object to string
    def __repr__(self):
        return "{}".format(self.rsa_keyset)

    # This method signs a message using the RSA algorithm
    # Parameters:
    # to_sign -> (int) Message to sign
    # Return: (void)
    def sign(self, to_sign):
        self.signature = pow(to_sign, self.rsa_keyset.getD(), self.rsa_keyset.getN())

    # This method verifies a message using the RSA algorithm
    # Parameters:
    # to_verify -> (int) Signature to verify
    # n -> (int) RSA module. Public key
    # e -> (int) RSA exponent. Public key
    # Return: (int) Verified message
    def verify(signature, n, e):
        return pow(signature, e, n)
