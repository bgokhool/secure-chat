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

primes_dict = {}
for n in range(512, 1088, 64):
    dsa = DSA.generate(n)
    p_g_tuple = (dsa.p, dsa.g)
    primes_dict[str(n)] = p_g_tuple

# print(primes_dict["512"])
# print(primes_dict["576"])
# print(primes_dict["640"])
# print(primes_dict["704"])
# print(primes_dict["768"])
# print(primes_dict["832"])
# print(primes_dict["896"])
# print(primes_dict["960"])
# print(primes_dict["1024"])
