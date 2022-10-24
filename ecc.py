from random import randint

import hashlib
import hmac

import GCD as gcd

# Finite Field Element
class FieldElement:
    # Field Element builder
    def __init__(self, num, prime):
        if num >= prime or num < 0:
            error = 'Num {} not in field range 0 to {}'.format(num, prime - 1)
            raise ValueError(error)
        
        self.num = num
        self.prime = prime

    # Represents the Field Element
    def __repr__(self):
        return 'FieldElement_{}({})'.format(self.prime, self.num)

    # Proves that two instances are equal
    def __eq__(self, other):
        if other is None:
            return False
        
        return self.num == other.num and self.prime == other.prime

    # Proves that two instances are not equal
    def __ne__(self, other):
        return not (self == other)

    # Adds two elements of the Finite Field
    def __add__(self, other):
        if self.prime != other.prime:
            raise TypeError('Cannot add two numbers in different Fields')
        
        num = (self.num + other.num) % self.prime
        
        return self.__class__(num, self.prime)

    # Subtracts two elements of the Finite Field
    def __sub__(self, other):
        if self.prime != other.prime:
            raise TypeError('Cannot subtract two numbers in different Fields')

        num = (self.num - other.num) % self.prime

        return self.__class__(num, self.prime)

    # Multiplies two elements of the Finite Field
    def __mul__(self, other):
        if self.prime != other.prime:
            raise TypeError('Cannot multiply two numbers in different Fields')

        num = (self.num * other.num) % self.prime

        return self.__class__(num, self.prime)

    # Pow of the Finite Field Element
    def __pow__(self, exponent):
        n = exponent % (self.prime - 1)
        num = pow(self.num, n, self.prime)
        return self.__class__(num, self.prime)

    # Divides two elements of the Finite Field
    def __truediv__(self, other):
        if self.prime != other.prime:
            raise TypeError('Cannot divide two numbers in different Fields')
        
        num = (self.num * pow(other.num, self.prime - 2, self.prime)) % self.prime
        
        return self.__class__(num, self.prime)

    # Multiplies by a number (coefficient) the Finite Field Element
    def __rmul__(self, coefficient):
        num = (self.num * coefficient) % self.prime
        
        return self.__class__(num=num, prime=self.prime)

# Point in an EC
class Point:
    # Point of the EC builder
    def __init__(self, x, y, a, b):
        self.a = a
        self.b = b
        self.x = x
        self.y = y
        
        if self.x is None and self.y is None:
            return
        
        if self.y**2 != self.x**3 + a * x + b:
            raise ValueError('({}, {}) is not on the curve'.format(x, y))

    # Proves that two instances are equal
    def __eq__(self, other):
        return self.x == other.x and self.y == other.y and self.a == other.a and self.b == other.b

    # Proves that two instances are not equal
    def __ne__(self, other):
        return not (self == other)

    # Represents the Point of the EC
    def __repr__(self):
        if self.x is None:
            return 'Point(infinity)'
        
        elif isinstance(self.x, FieldElement):
            return 'Point({},{})_{}_{} FieldElement({})'.format(self.x.num, self.y.num, self.a.num, self.b.num, self.x.prime)
        
        else:
            return 'Point({},{})_{}_{}'.format(self.x, self.y, self.a, self.b)

    # Adds two points of the EC
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

    # Multiplies by a number (coefficient) the EC Point
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

# Coefs A and B. The curve is y2 = x3 + 7
A = 0
B = 7
# PRIME
P = 2**256 - 2**32 - 977
# Number of Points of the curve
N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

# Defines the S256 Finite Field
class S256Field(FieldElement):
    # S256 Field Element builder
    def __init__(self, num, prime=None):
        super().__init__(num=num, prime=P)

    # Represents the S256 Field Element
    def __repr__(self):
        return '{:x}'.format(self.num).zfill(64)

# Defines the S256 EC. The curve is y2 = x3 + 7
class S256Point(Point):
    # S256 EC builder
    def __init__(self, x, y, a=None, b=None):
        a, b = S256Field(A), S256Field(B)
        
        if type(x) == int:
            super().__init__(x=S256Field(x), y=S256Field(y), a=a, b=b)
            
        else:
            super().__init__(x=x, y=y, a=a, b=b)

    # Represents the S256 EC
    def __repr__(self):
        if self.x is None:
            return 'S256Point(infinity)'
        
        else:
            return 'S256Point({}, {})'.format(self.x, self.y)

    # Multiplies by a number (coefficient) the EC Point
    def __rmul__(self, coefficient):
        coef = coefficient % N
        return super().__rmul__(coef)
    

class S256EC_keyset:
    # Keyset builder
    def __init__(self, publicKey = None, privateKey = 0, generate = True):
        if(not(generate)):
            self.publicKey = publicKey
            self.privateKey = privateKey
            
        else:
            self.privateKey = randint(2, N - 1)
            self.publicKey = self.privateKey * G

    # Represents the S256EC Keyset
    def __repr__(self):
        return ("Private key = {}\n\nPublic key = {}").format(self.privateKey, self.publicKey)
        
class S256EC_signature:
    def __init__(self, s256keyset):
        self.s256keyset = s256keyset
        
    def sign(self, to_sign):
        k = randint(2, N - 1)
        x = gcd.GCD(k, N)
        
        while(x.gcd != 1):
            k = randint(2, N - 1)
            x = gcd.GCD(k, N)
        
        R = k * G
        r = R.x.num % N
        
        while(r == 0):
            k = gcd.GCD(randint(2, N - 1), N)
            R = k * G
            r = R.x % N

        s = ((to_sign - (r * self.s256keyset.privateKey)) * x.u) % N

        self.R = R
        self.s = s

            
    
    def verify(text_to_verify, publicKey, R, s):
        mP = text_to_verify * G
        rQ = R.x.num * publicKey
        sR = s * R
        return (mP == (rQ + sR))
        
# Generator Point
G = S256Point(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)

# Initial coordinates
x1 = FieldElement(8, P)
y1 = FieldElement(91736135629086734185706894124002126994554994840140056297753929940646699135966, P)

# M Point encrypted
q = S256Point(x1,y1)
kG = S256Point(x1,y1)
