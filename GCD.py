
class GCD:
    def __init__(self, a, b):
        self.a = a
        self.b = b
        self._gcd()

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
        
