# GCD
# This class defines the GCD of 2 numbers
# Attributes:
# a -> (int) Number a
# b -> (int) Number b
# gcd -> (int) GCD of a and b
# u -> (int) Coefficient u
# v -> (int) Coefficient v
class GCD:
    # Builder
    def __init__(self, a, b):
        self.a = a
        self.b = b
        self._gcd()

    # Number a getter
    # Return: (int) Number a
    def getA(self):
        return self.a

    # Number b getter
    # Return: (int) Number b
    def getB(self):
        return self.b

    # Coefficient u getter
    # Return: (int) Coefficient u
    def getU(self):
        return self.u
    
    # Coefficient v getter
    # Return: (int) Coefficient v
    def getV(self):
        return self.v
    
    # GCD of a and b getter
    # Return: (int) Coefficient u
    def getGCD(self):
        return self.gcd

    # This method calculates the GCD of the two numbers a and b
    # Return: (void)
    def _gcd(self):
        if(self.b == 0):
            self.gcd = 0
            self.u = 1
            self.v = 0
            
        else:
            a = self.a
            b = self.b
            u0 = 1
            u1 = 0
            v0 = 0
            v1 = 1
 
            while(b != 0):
                q = a//b
                r = a - b * q
                u = u0 - q * u1
                v = v0 - q * v1
                # Update a, b
                a = b
                b = r
                # Update for next iteration
                u0 = u1
                u1 = u
                v0 = v1
                v1 = v

            self.gcd = a
            self.u = u0
            self.v = v0
        
