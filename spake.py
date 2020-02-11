"""
This script will be used for the SPAKE protocol
"""
import rsa_encoder as r
from random import randint, choice
from hashlib import sha3_512 as H

class SPAKE():

    G = [2, 4, 8, 5, 10, 9, 7, 3, 6, 1]
    g = 2
    p = 11
    pw = 2
    M = N = 5
    hkey = key = x = x_upper = x_star = y_star = None

    def __init__(self, pw):
        self.pw = pw
        self.compute_x()
        self.compute_x_upper()
        self.compute_x_star()

    def complete_exchange(self, ystar):
        self.set_y_star(ystar)
        self.compute_key()
        self.compute_hash_key()

    def compute_x(self):
        self.x = randint(1, self.p-1)

    def compute_x_upper(self):
        self.x_upper = r.fast_exp_w_mod(self.g, self.x, self.p)

    def compute_x_star(self):
        self.x_star = self.x_upper * r.fast_exp_w_mod(self.M, self.pw, self.p)

    def get_x_star(self):
        return self.x_star

    def set_y_star(self, num):
        self.y_star = num

    def compute_key(self):
        n_pw = r.fast_exp_w_mod(self.N, self.pw, self.p)
        tmp = self.y_star/n_pw
        the_key = r.fast_exp_w_mod(tmp, self.x, self.p)
        self.key = str(the_key)

    def compute_hash_key(self):
        bin_key = self.key.encode('utf-8')
        self.hkey = H(bin_key)

    def get_hex_key(self):
        return self.hkey.hexdigest()



if __name__ == "__main__":
    # data = 'Sending encrypted'
    # data = data.encode('utf-8')
    # sha3_512 = H(data)
    # sha3_512_digest = sha3_512.digest()
    # sha3_512_hex_digest = sha3_512.hexdigest()
    # print('Printing digest output')
    # print(sha3_512_digest)
    # print('Printing hexadecimal output')
    # print(sha3_512_hex_digest)
    a = SPAKE(4)
    b = SPAKE(4)
    a_xstar = a.get_x_star()
    b_ystar = b.get_x_star()
    str_astar = str(a_xstar)
    str_bstar = str(b_ystar)
    a.complete_exchange(int(str_bstar))
    b.complete_exchange(int(str_astar))
    print(a.get_hex_key())
    print(b.get_hex_key())
    print(a.get_hex_key() == b.get_hex_key())
