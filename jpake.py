"""
This script will be used for the JPAKE protocol
"""
from hashlib import sha3_512 as H
from random import randint, choice
import rsa_encoder as r
from Crypto.PublicKey import DSA

class JPAKE():

    pw = 21

    def __init__(self, pw, signerID, prime=71, generator=7):
        self.q = prime
        self.g = generator
        self.clientId = signerID
        self.setSignerID(signerID)
        self.pw = pw
        self.x_1 = self.get_rand_val_mod_q()
        self.x_2 = self.get_rand_val_mod_q()
        self.compute_gx1()
        self.compute_gx2()

    def setSignerID(self, someID):
        value = 0
        for char in someID:
            value = (value +ord(char))%self.q
        self.signerID = value
        print(str(self.clientId)+ "'s signer ID is:", self.signerID)

    def getSignerID(self):
        return self.signerID

    def storeOtherID(self, signerID):
        self.otherSignerID = signerID

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
        pfx1 = self.zkp_for(self.g, self.x_1)
        pfx2 = self.zkp_for(self.g, self.x_2)
        return (self.gx1, self.gx2, pfx1, pfx2)

    def my_hash(self, gv, gx_i, signerID):
        """ signerID is a string """
        g_product = (self.g*gv*gx_i)%self.q
        int_signerID = int(signerID)
        int_hash = r.fast_exp_w_mod(g_product, int_signerID, self.q)

        # Adding this to decrease the size of the number to be hashed
        # otherwise the to_bytes function does not work
        int_hash = int_hash%10000

        sha_hashing = H(int_hash.to_bytes(2, "big"))
        sha_hashing_int = int(sha_hashing.hexdigest(), 16)
        num = sha_hashing_int
        while num > 10:
            num = r.sum_digits(num)

        # print("The h value is", num)
        return num

    def verify_zkp(self, pf_val, some_gx, g):
        gv = pf_val[0]
        r_val = pf_val[1]
        h = self.my_hash(gv, some_gx, self.otherSignerID)

        if r_val >= 0:
            gr = r.fast_exp_w_mod(g, r_val, self.q)
        else:
            gr_inverse = r.fast_exp_w_mod(g, -r_val, self.q)
            gcd, x, y =r.egcd(gr_inverse, self.q)
            gr = x
        gxh = r.fast_exp_w_mod(some_gx, h, self.q)
        grxh = (gr*gxh)%self.q
        # print(gv == grxh)
        return gv == grxh

    def get_first(self, gx3gx4):
        self.gx3 = gx3gx4[0]
        self.gx4 = gx3gx4[1]
        self.verify_zkp(gx3gx4[2], self.gx3, self.g)
        self.verify_zkp(gx3gx4[3], self.gx4, self.g)
        self.computeA()

    def computeA(self):
        self.own_g_product = (((self.gx1 * self.gx3)%self.q)*self.gx4)%self.q
        self.x2_times_s = self.x_2 * self.pw
        self.A = r.fast_exp_w_mod(self.own_g_product, self.x2_times_s, self.q)

    def send_second(self):
        pfx2_time_s = self.zkp_for(self.own_g_product, self.x2_times_s)
        return self.A, pfx2_time_s

    def get_second(self, B_pfx4s):
        self.B = B_pfx4s[0]
        self.other_g_product = (((self.gx1 * self.gx3)%self.q)*self.gx2)%self.q
        self.verify_zkp(B_pfx4s[1], self.B, self.other_g_product)

    def compute_key(self):
        g_to_x2x4s = r.fast_exp_w_mod(self.gx4, self.x2_times_s, self.q)

        gcd, x, y = r.egcd(g_to_x2x4s, self.q)
        g_to_x2x4s_inverse = x

        quotient = (self.B*g_to_x2x4s_inverse)%self.q
        self.key = r.fast_exp_w_mod(quotient, self.x_2, self.q)

    def session_key(self):
        str_key = str(self.key)
        bin_key = str_key.encode('utf-8')
        self.sess_key = H(bin_key)

    def get_hex_key(self):
        return self.sess_key.hexdigest()

    def zkp_for(self, g, x_val):
        gx = r.fast_exp_w_mod(g, x_val, self.q)

        v = self.get_rand_val_mod_q()
        gv = r.fast_exp_w_mod(g, v, self.q)

        # I am having problems with this hashing
        # I don't know what type of hashing they are expecting in the paper
        h = self.my_hash(gv, gx, self.signerID)
        r_val = v-(x_val*h)
        # print(str(self.clientId) + "'s r value:", r_val)
        return (gv, r_val)

def convert_first_to_tuple(firstMsg):
    firstls = firstMsg.split(",")
    firstlst = [i.strip(" ()") for i in firstls]
    gx1 = int(firstlst[0])
    gx2 = int(firstlst[1])
    pfx1 = (int(firstlst[2]), int(firstlst[3]))
    pfx2 = (int(firstlst[4]), int(firstlst[5]))
    return (gx1, gx2, pfx1, pfx2)

def convert_second_to_tuple(secondMsg):
    secondls = secondMsg.split(",")
    secondlst = [i.strip(" ()") for i in secondls]
    B = int(secondlst[0])
    pfx4s = (int(secondlst[1]), int(secondlst[2]))
    return (B, pfx4s)

if __name__ == "__main__":
    count_pass= count_fail = 0
    for j in range(512, 1088, 64):
        for i in range(50):
            dsa = DSA.generate(j)
            alice = JPAKE(4, "Alice", dsa.p, dsa.g)
            bob = JPAKE(4, "Bob", dsa.p, dsa.g)

            alice.storeOtherID(bob.getSignerID())
            bob.storeOtherID(alice.getSignerID())

            alice_gx1gx2 = alice.send_first()
            bob_gx3gx4 = bob.send_first()
            alice.get_first(bob_gx3gx4)
            bob.get_first(alice_gx1gx2)
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
            if alice.get_hex_key() == bob.get_hex_key():
                count_pass += 1
            else:
                count_fail += 1
    print("Numer passed: ", count_pass)
    print("Numer failed: ", count_fail)
