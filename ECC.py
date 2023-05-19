# IMPORTS
from random import randint
from sympy import *
# LOCAL IMPORTS
import GCD as gcd

# GLOBALS
# Coefs A and B. The bitcoin curve is y**2 = x**3 + 7
A = 0
B = 7
# PRIME
P = 2**256 - 2**32 - 977
# Number of points of the curve
N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

# FieldElement
# This class defines finite field element
# Attributes:
# num -> (int) Finite field element
# prime -> (int) Finite field prime
class FieldElement:
    # Builder
    def __init__(self, num, prime):
        if num >= prime or num < 0:
            error = "Num {} not in field range 0 to {}".format(num, prime - 1)
            raise ValueError(error)
        
        self.num = num
        self.prime = prime

    # Finite field element getter
    # Return: (int) Finite field element
    def getNum(self):
        return self.num

    # Finite field prime getter
    # Return: (int) Finite field prime
    def getPrime(self):
        return self.prime

    # Object to string
    def __repr__(self):
        return "FieldElement_{}({})".format(self.prime, self.num)

    # This method proves that two instances are equal
    # Parameters:
    # other -> (FieldElement) Instance to compare with self
    # Return: (BOOLEAN) True if equal, False if not equal
    def __eq__(self, other):
        if other is None:
            return False
        
        return self.num == other.num and self.prime == other.prime

    # This method proves that two instances are not equal
    # Parameters:
    # other -> (FieldElement) Instance to compare with self
    # Return: (BOOLEAN) True if not equal, False if equal
    def __ne__(self, other):
        return not (self == other)

    # This method adds two elements of the finite field
    # Parameters:
    # other -> (FieldElement) Instance to add
    # Return: (FieldElement) The addition between self and other
    def __add__(self, other):
        if self.prime != other.prime:
            raise TypeError('Cannot add two numbers in different Fields')
        
        num = (self.num + other.num) % self.prime
        
        return self.__class__(num, self.prime)

    # This method subtracts two elements of the finite field
    # Parameters:
    # other -> (FieldElement) Instance to substract
    # Return: (FieldElement) The substraction between self and other
    def __sub__(self, other):
        if self.prime != other.prime:
            raise TypeError('Cannot subtract two numbers in different Fields')

        num = (self.num - other.num) % self.prime

        return self.__class__(num, self.prime)

    # This method multiplies two elements of the finite field
    # Parameters:
    # other -> (FieldElement) Instance to multiply
    # Return: (FieldElement) The multiplication between self and other
    def __mul__(self, other):
        if self.prime != other.prime:
            raise TypeError('Cannot multiply two numbers in different Fields')

        num = (self.num * other.num) % self.prime

        return self.__class__(num, self.prime)

    # This method defines the pow of a finite field element
    # Parameters:
    # exponent -> (int) Exponent of the pow
    # Return: (FieldElement) The exponent power of a finite field element
    def __pow__(self, exponent):
        n = exponent % (self.prime - 1)
        num = pow(self.num, n, self.prime)
        return self.__class__(num, self.prime)

    # This method divides two elements of the finite field
    # Parameters:
    # other -> (FieldElement) Instance to be divided with
    # Return: (FieldElement) The division between self and other
    def __truediv__(self, other):
        if self.prime != other.prime:
            raise TypeError('Cannot divide two numbers in different Fields')
        
        num = (self.num * pow(other.num, self.prime - 2, self.prime)) % self.prime
        
        return self.__class__(num, self.prime)

    # This method multiplies by a number the finite field element
    # Parameters:
    # coefficient -> (int) Coefficient of the multiplication
    # Return: (FieldElement) The multiplication between self and coefficient
    def __rmul__(self, coefficient):
        num = (self.num * coefficient) % self.prime
        
        return self.__class__(num=num, prime=self.prime)

# Point
# This class defines a point in an elliptic curve
# Attributes:
# a -> (int), (FieldElement) Elliptic curve a coefficient
# b -> (int), (FieldElement) Elliptic curve b coefficient
# x -> (int), (FieldElement) Point x coordinate
# y -> (int), (FieldElement) Point y coordinate
class Point:
    # Builder
    def __init__(self, x, y, a, b):
        self.a = a
        self.b = b
        self.x = x
        self.y = y
        
        if self.x is None and self.y is None:
            return
        
        if self.y**2 != self.x**3 + a * x + b:
            raise ValueError('({}, {}) is not on the curve'.format(x, y))

    # Coefficient A getter
    # Return: (int), (FieldElement) Coefficient A
    def getA(self):
        return self.a

    # Coefficient B getter
    # Return: (int), (FieldElement) Coefficient B
    def getB(self):
        return self.b
    
    def getX(self):
        return self.x
    
    def getY(self):
        return self.y
        
    # Object to string
    def __repr__(self):
        if self.x is None:
            return 'Point(infinity)'
        elif isinstance(self.x, FieldElement):
            return 'Point({},{})_{}_{} FieldElement({})'.format(self.x.getNum(), self.y.getNum(), self.a.getNum(), self.b.getNum(), self.x.prime) 
        else:
            return 'Point({},{})_{}_{}'.format(self.x, self.y, self.a, self.b)

    # This method proves that two instances are equal
    # Parameters:
    # other -> (Point) Instance to compare with self
    # Return: (BOOLEAN) True if equal, False if not equal
    def __eq__(self, other):
        return self.x == other.x and self.y == other.y and self.a == other.a and self.b == other.b

    # This method proves that two instances are not equal
    # Parameters:
    # other -> (Point) Instance to compare with self
    # Return: (BOOLEAN) True if not equal, False if equal
    def __ne__(self, other):
        return not (self == other)

    # This method adds two points of the elliptic curve
    # Parameters:
    # other -> (Point) Instance to add
    # Return: (Point) The addition between self and other
    def __add__(self, other):
        if self.a != other.a or self.b != other.b:
            raise TypeError('Points {}, {} are not on the same curve'.format(self, other))

        if self.x is None:
            return other

        if other.x is None:
            return self

        if self.x == other.x and self.y != other.y:
            return self.__class__(None, None, self.a, self.b)

        if self.x != other.x:
            s = (other.y - self.y) / (other.x - self.x)
            x = s**2 - self.x - other.x
            y = s * (self.x - x) - self.y
            return self.__class__(x, y, self.a, self.b)

        if self == other and self.y == 0 * self.x:
            return self.__class__(None, None, self.a, self.b)

        if self == other:
            s = (3 * self.x**2 + self.a) / (2 * self.y)
            x = s**2 - 2 * self.x
            y = s * (self.x - x) - self.y
            return self.__class__(x, y, self.a, self.b)

    # This method multiplies by a number the point
    # Parameters:
    # coefficient -> (int) Coefficient of the multiplication
    # Return: (Point) The multiplication between self and coefficient
    def __rmul__(self, coefficient):
        coef = coefficient
        current = self
        result = self.__class__(None, None, self.a, self.b)
        
        while coef:
            if coef & 1:
                result += current
                
            current += current
            coef >>= 1
            
        return result

# FieldElement
# This class defines the finite field for the bitcoin elliptic curve
# Inheritance: FieldElement
class S256Field(FieldElement):
    # Builder
    def __init__(self, num, prime=None):
        super().__init__(num=num, prime=P)

    # Object to string
    def __repr__(self):
        return '{:x}'.format(self.num).zfill(64)
    
G = Point(S256Field(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798, P), S256Field(0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8, P), S256Field(A, P), S256Field(B, P))

# S256Point
# This class defines a point in the bitcoin elliptic curve
# Inheritance: S256Point
class S256Point(Point):
    # Builder
    def __init__(self, x, y, a=None, b=None):
        a, b = S256Field(A), S256Field(B)
        
        if type(x) == int:
            super().__init__(x=S256Field(x), y=S256Field(y), a=a, b=b)
        else:
            super().__init__(x=x, y=y, a=a, b=b)

    # Object to string
    def __repr__(self):
        if self.x is None:
            return 'S256Point(infinity)'
        else:
            return 'S256Point(0x{}, 0x{})'.format(self.x, self.y)

    # This method multiplies by a number the point
    # Parameters:
    # coefficient -> (int) Coefficient of the multiplication
    # Return: (S256Point) The multiplication between self and coefficient
    def __rmul__(self, coefficient):
        coef = coefficient % N
        return super().__rmul__(coef)
    
    # This method generates a random point of the bitcoin curve
    # Return: (S256Point) Random point of the bitcoin curve
    def generate_random_point():
        return randint(1, P - 1) * G

    # This method encrypts a point of the curve
    # Parameters:
    # to_encrypt -> (S256Point) Point to encrypt
    # public_key -> (S256Point) ECDSA public key
    # Return: (String) The kG, q encryption set
    def encrypt(to_encrypt, public_key):
        k = randint(2, N - 1)
        kG = k * G
        kP = k * public_key
        q = to_encrypt + kP
        encryption = ("{} {}").format(kG, q)
        return encryption

    # This method decrypts th kG, q encryption set
    # Parameters:
    # kG -> (S256Point) kG encryption
    # q -> (S256Point) q encryption
    # private_key -> (int) ECDSA private key
    # Return: (S256Point) The message decrypted
    def decrypt(kG, q, private_key):
        decryption = q + ((N - 1) * (private_key * kG))
        return decryption
    
# S256Keyset
# This class defines a ECDSA keyset
# Attributes:
# public_key -> (S256Point) ECDSA public key
# private_key -> (int) ECDSA private key
class S256Keyset:
    # Builder
    def __init__(self, public_key = None, private_key = 0, generate = True):
        if(not(generate)):
            self.public_key = public_key
            self.private_key = private_key
            
        else:
            self.private_key = randint(2, N - 1)
            self.public_key = self.private_key * G

    # Public key getter
    # Return: (S256Point) ECDSA public key
    def getPublicKey(self):
        return self.public_key

    # Private key getter
    # Return: (int) ECDSA private key
    def getPrivateKey(self):
        return self.private_key

    # Object to string
    def __repr__(self):
        return ("[Public key: {}, Private key: {}]").format(self.public_key, self.private_key)

# S256Signature
# This class defines the methods for a ECDSA signature
# Attributes:
# s256_keyset -> (S256Keyset) ECDSA keyset
class S256Signature:
    def __init__(self, s256_keyset = S256Keyset()):
        self.s256_keyset = s256_keyset
        self.R = None
        self.s = None

    # ECDSA keyset getter
    # Return: (S256Keyset) ECDSA keyset
    def getECDSAKeyset(self):
        return self.s256_keyset
    
    # Public key getter
    # Return: (S256Point) ECDSA public key
    def getPublicKey(self):
        return self.s256_keyset.getPublicKey()

    # Private key getter
    # Return: (int) ECDSA private key
    def getPrivateKey(self):
        return self.s256_keyset.getPrivateKey()
    
    # ECDSA signature R getter
    # Return: (S256Point) ECDSA signature R getter
    def getR(self):
        return self.R

    # ECDSA signature s getter
    # Return: (int) ECDSA signature s getter
    def getS(self):
        return self.s

    # This method signs a message using the ECDSA algorithm
    # Parameters:
    # to_sign -> (S256Point) Message to sign
    # Return: (int) Signed message
    def sign(self, to_sign):
        k = randint(2, N - 1)
        x = gcd.GCD(k, N)
        
        while(x.gcd != 1):
            k = randint(2, N - 1)
            x = gcd.GCD(k, N)
        
        R = k * G
        r = R.x.getNum() % N
        
        while(r == 0):
            k = gcd.GCD(randint(2, N - 1), N)
            R = k * G
            r = R.x % N

        s = ((to_sign - (r * self.s256_keyset.getPrivateKey())) * x.getU()) % N

        self.R = R
        self.s = s

    # This method verifies a message using the RSA algorithm
    # Parameters:
    ########
    # to_verify -> (int) Message to verify
    # public_key -> (S256Point) Public key
    # R -> (S256Point) Signature to verify
    # s -> (int) Signature to verify
    # Return: (boolean) True if verified false if not verified
    def verify(to_verify, public_key, R, s):
        mP = to_verify * G
        rQ = R.x.getNum() * public_key
        sR = s * R
        return (mP == (rQ + sR))

# GLOBALS
# Generator Point
G = S256Point(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)