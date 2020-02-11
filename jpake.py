"""
This script will be used for the JPAKE protocol
"""
from hashlib import sha3_512 as H
from random import randint, choice

class JPAKE():

    G = [2, 4, 8, 5, 10, 9, 7, 3, 6, 1]
    g = 2
    q = 11
    pw = 2

    def __init__(self, pw):
        self.pw = pw
        self.x_1 = self.get_rand_val_mod_q()
        self.x_2 = self.get_rand_val_mod_q()
        self.compute_gx1()
        self.compute_gx2()

    def get_rand_val_mod_q(self):
         return randint(1, self.q-1)

    def compute_gx1(self):
        self.gx1 = r.fast_exp_w_mod(self.g, self.x_1, self.q)

    def compute_gx2(self):
        self.gx2 = r.fast_exp_w_mod(self.g, self.x_2, self.q)

    def get_gx1():
        return self.x1

    def get_gx2():
        return self.x2
