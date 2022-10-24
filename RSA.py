import random
from random import SystemRandom
import sympy
import GCD as gcd

class RSA:
    def __init__(self, e = 65537, n = 0, d = 0, generate = True):
        self.e = e
        if(not(generate)):
            self.n = n
            self.d = d

        else:
            p = RSA.random_prime_generator(1024)
            q = RSA.random_prime_generator(1024)
            self.n = p * q
            fi = (p - 1) * (q - 1)
            self.private_key_generator(fi)

    def random_prime_generator(length):
        p = random.SystemRandom().randint(pow(2, length), pow(2, length + 1))

        if(p % 2 == 0):
            p = p + 1

        while(not(sympy.isprime(p))):
            p = p + 2
        
        return p

    def private_key_generator(self, fi):
        x = gcd.GCD(self.e, fi)
        self.d = x.u % fi

class RSASignature:
    def __init__(self, rsakeyset = RSA()):
        self.rsakeyset = rsakeyset

    def sign(self, to_sign):
        self.signature = pow(to_sign, self.rsakeyset.d, self.rsakeyset.n)
        return self.signature

    def verify(signature, issuing_keyset):
        return pow(signature, issuing_keyset.e, issuing_keyset.n)
