from Crypto.Random import random
from random import randint

def gcd(a,b):
    # a > b
    if(b==0):
        return a
    else:
        return gcd(b,a%b)

# Extended Euclidean Algorithm
def egcd(a, b):
    # b > a
	if a == 0:
		return (b, 0, 1)
	else:
		gcd, x, y = egcd(b % a, a)
		return (gcd, y - (b//a) * x, x)

def sum_digits(n):
    s = 0
    while n:
        s += n % 10
        n //= 10
    return s

def key_gen(p = 7, q = 29):
    n = p*q
    phi_n = (p-1)*(q-1)
    kpub_ls = []
    for e in range(1, phi_n):
        if gcd(phi_n, e) == 1:
            kpub_ls.append(e)
    num_possible_e = len(kpub_ls)
    random_e_choice = randint(0,num_possible_e-1)
    e = d = kpub_ls[random_e_choice]
    for possible_d in kpub_ls:
        if (e*possible_d)%phi_n == 1:
            d = possible_d
    k_pub = e
    k_priv = d
    return (n, k_pub, k_priv)


def get_pub_key(key):
    return (key[0], key[1])


def get_priv_key(key):
    return (key[0], key[2])


def encode(plaintext):
    ciphertext = ""
    for i in plaintext:
        ciphertext += chr(ord(i)+3)
    return ciphertext


def decode(ciphertext):
    plaintext = ""
    for i in ciphertext:
        plaintext += chr(ord(i)-3)
    return plaintext


"""
we can get the binary value of a decimal number
in python using the bin() function
for e.g
>>>print(bin(18))
0b10010
>>>bin_a = bin(19)
>>>print(int(bin_a, 2))
19
"""
def fast_exponentiation(number, exponent):
    bin_e = bin(exponent)
    str_e = bin_e[2:]
    rstr_e = ''.join(reversed(str_e))
    num_ops = len(rstr_e)

    answer = 1
    for chr_e in rstr_e:
        if chr_e == "1":
            answer *= number
        number = number**2

    return answer

def fast_exp_w_mod(number, exponent, modulus):
    bin_e = bin(exponent)
    str_e = bin_e[2:]
    rstr_e = ''.join(reversed(str_e))
    num_ops = len(rstr_e)

    answer = 1
    for chr_e in rstr_e:
        if chr_e == "1":
            answer = (answer * number)% modulus
        number = (number**2)% modulus

    return answer


def rsa_enc(plain_num, pub_key):
    n = pub_key[0]
    e = pub_key[1]
    if plain_num not in range(0,n):
        print("Number not integers mod n")
        return
    else:
        cipher_num = (plain_num**e)%n        # this is bad as it is, I need ot change it to use fast exponentiation
    return cipher_num


def rsa_dec(cipher_num, priv_key):
    n = priv_key[0]
    d = priv_key[1]
    if cipher_num not in range(0,n):
        print("Number not integers mod n")
        return
    else:
        plain_num = (cipher_num**d)%n
    return plain_num


if __name__ == "__main__":
    # print("Testing shift by 3 cipher")
    # mytext = "hello"
    # cryptext = encode(mytext)
    # print("Plaintext is: {}".format(mytext))
    # print("Ciphertext is: {}".format(cryptext))
    # print("Deciphering we get: {}".format(decode(cryptext)))

    # y = rsa_enc(4,(91,5))
    # print(y)
    # x = rsa_dec(y, (91,29))
    # print(x)

    exp_e = fast_exponentiation(2,7)
    print(exp_e)
    gcd, x, y = egcd(3, 50)
    print(gcd, x, y)
