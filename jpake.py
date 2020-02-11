"""
This script will be used for the JPAKE protocol
"""
from hashlib import sha3_512 as H
from random import randint, choice
import rsa_encoder as r

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

    def get_gx1(self):
        return self.gx1

    def get_gx2(self):
        return self.gx2

    def send_first(self):
        return (self.gx1, self.gx2)

    def get_first(self, gx3gx4):
        self.gx3 = gx3gx4[0]
        self.gx4 = gx3gx4[1]

    def computeA(self):
        g_product = (((self.gx1 * self.gx3)%self.q)*self.gx4)%self.q
        self.x2_times_s = self.x_2 * self.pw
        self.A = r.fast_exp_w_mod(g_product, self.x2_times_s, self.q)

    def send_second(self):
        return self.A

    def get_second(self, B):
        self.B = B

    def compute_key(self):
        g_to_x2x4s = r.fast_exp_w_mod(self.gx4, self.x2_times_s, self.q)
        quotient = (self.B/g_to_x2x4s)%self.q
        self.key = r.fast_exp_w_mod(quotient, self.x_2, self.q)

    def session_key(self):
        str_key = str(self.key)
        bin_key = str_key.encode('utf-8')
        self.sess_key = H(bin_key)

    def get_hex_key(self):
        return self.sess_key.hexdigest()

    def zkp_for(self, x_val):
        v = self.get_rand_val_mod_q()
        gv = r.fast_exp_w_mod(self.g, v, self.q)
        gx = r.fast_exp_w_mod(self.g, x_val, self.q)
        h = H(self.g, gv, gx)
        r = v-(x_val*h)
        return (gv, r)

if __name__ == "__main__":
    alice = JPAKE(4)
    bob = JPAKE(4)
    alice_gx1gx2 = alice.send_first()
    bob_gx3gx4 = bob.send_first()
    alice.get_first(bob_gx3gx4)
    bob.get_first(alice_gx1gx2)

    alice.computeA()
    bob.computeA()
    alice_A = alice.send_second()
    bob_B = bob.send_second()
    alice.get_second(bob_B)
    bob.get_second(alice_A)

    alice.compute_key()
    bob.compute_key()
    alice.session_key()
    bob.session_key()

    print(alice.get_hex_key())
    print(bob.get_hex_key())
    print(alice.get_hex_key() == bob.get_hex_key())
