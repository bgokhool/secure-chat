"""
This module will be used ot generate large random primes with
the smallest primitive root
"""
from Crypto.Util import number
from Crypto.PublicKey import DSA
import rsa_encoder as r


class RandPrime():
    """
    Takes a number n to generate an n-bit long prime number
    with a corresponding generator

    NOTE: 512 <= n <= 1024
    """

    def __init__(self, n):
        self.n = n
        self.dsa = DSA.generate(self.n)

    def getPrime(self):
        return self.dsa.p

    def getGenerator(self):
        return self.dsa.g


if __name__ == "__main__":
    genprime = RandPrime(1024)
    p = genprime.getPrime()
    g = genprime.getGenerator()
    print(p)
    print(number.isPrime(p))
    print()
    print(g)
    print(r.fast_exp_w_mod(g,p-1,p))

mydict = {}
for n in range(512, 1088, 64):
    dsa = DSA.generate(n)
    p_g_tuple = (dsa.p, dsa.g)
    mydict[str(n)] = p_g_tuple

# print(mydict["512"])
# print(mydict["576"])
# print(mydict["640"])
# print(mydict["704"])
# print(mydict["768"])
# print(mydict["832"])
# print(mydict["896"])
# print(mydict["960"])
# print(mydict["1024"])
