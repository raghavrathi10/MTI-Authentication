import random
import math
from PIL import Image
from Crypto.Cipher import AES
from datetime import datetime


# Encrytion algorithm start

filename = "tux.bmp"
filename_out_cbc = "tux_encrypted_cbc"
filename_out_ecb = "tux_encrypted_ecb"
format = "BMP"
key = "aaaabbbbccccdddd" #change this key to the key generated through MIT, later.


# Padding to make the data multiple of 16
def pad(data):
    return data + b"\x00" * (16 - len(data) % 16)


# Maps the RGB
def convert_to_RGB(data):
    r, g, b = tuple(map(lambda d: [data[i] for i in range(0, len(data)) if i % 3 == d], [0, 1, 2]))
    pixels = tuple(zip(r, g, b))
    return pixels


def process_image(filename):
    # Opens image and converts it to RGB format for PIL
    im = Image.open(filename)
    data = im.convert("RGB").tobytes()

    original = len(data)

    # Encrypts using AES CBC mode
    new = convert_to_RGB(aes_cbc_encrypt(key, pad(data))[:original])

    # Create a new PIL Image object and save the old image data into the new image.
    im2 = Image.new(im.mode, im.size)
    im2.putdata(new)

    # Save image
    im2.save(filename_out_cbc + "." + format, format)


    # Encrypts using AES ECB mode
    new1 = convert_to_RGB(aes_ecb_encrypt(key, pad(data))[:original])

    im3 = Image.new(im.mode, im.size)
    im3.putdata(new1)

    im3.save(filename_out_ecb + "." + format, format)
    print('Encryption completed')

# CBC
def aes_cbc_encrypt(key, data, mode=AES.MODE_CBC):
    IV = "A" * 16  # manually setting the initialization vector to simplify things
    aes = AES.new(key, mode, IV)
    new_data = aes.encrypt(data)
    return new_data


# ECB
def aes_ecb_encrypt(key, data, mode=AES.MODE_ECB):
    aes = AES.new(key, mode)
    new_data = aes.encrypt(data)
    return new_data


# Encryption algorithm ends


"""
Generate prime numbers with the Miller-Rabin Primality Test.

"""
def square_and_multiply(x, k, p=None):
    """
    Square and Multiply Algorithm
    Parameters: positive integer x and integer exponent k,
                optional modulus p
    Returns: x**k or x**k mod p when p is given
    """
    b = bin(k).lstrip('0b')
    r = 1
    for i in b:
        r = r**2
        if i == '1':
            r = r * x
        if p:
            r %= p
    return r

def miller_rabin_primality_test(p, s=5):
    if p == 2: # 2 is the only prime that is even
        return True
    if not (p & 1): # n is a even number and can't be prime
        return False

    p1 = p - 1
    u = 0
    r = p1  # p-1 = 2**u * r

    while r % 2 == 0:
        r >>= 1
        u += 1

    assert p-1 == 2**u * r

    def witness(a):
        """
        Returns: True, if there is a witness that p is not prime.
                False, when p might be prime
        """
        z = square_and_multiply(a, r, p)
        if z == 1:
            return False

        for i in range(u):
            z = square_and_multiply(a, 2**i * r, p)
            if z == p1:
                return False
        return True

    for j in range(s):
        a = random.randrange(2, p-2)
        if witness(a):
            return False

    return True

def generate_primes(n=512, k=1):
    # Generates prime numbers with bitlength n.

    assert k > 0
    assert n > 0 and n < 4096

    # follows from the prime number theorem
    necessary_steps = math.floor( math.log(2**n) / 2 )
    # get n random bits as our first number to test for primality
    x = random.getrandbits(n)

    primes = []

    while k>0:
        if miller_rabin_primality_test(x, s=7):
            primes.append(x)
            k = k-1
        x = x+1

    return primes

def prime():

    # n is the bit length of the prime
    n = 16
    primes = generate_primes(n=n)
    for p in primes:
        return p


# globally declaring prime and generator
prime_p = prime()
g = random.randint(2, prime_p-2)
print('The generator is: ', g)

# g = 3
# prime_p = 17

def egcd(a, b):

    if a == 0:
        return (b, 0, 1)

    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modInverse(a, m = prime_p):
    # to calculate the inverse in phi p mod system.
    m = m-1
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m


def MTI_A0(a,b,Z_a,Z_b,x,y):
    start = datetime.now()
    # print(a,b,Z_a, Z_b,x,y)

    # alices session public key
    m_ab = (g**x) % prime_p
    # print('m_ab',m_ab)

    # bobs session public key
    m_ba = g**y % prime_p
    # print('m_ba',m_ba)

    # alice computes
    K_A = (((m_ba**a) % prime_p) * ((Z_b**x) % prime_p))% prime_p

    # bob computes
    K_B = (((m_ab**b) % prime_p) * ((Z_a**y) % prime_p))% prime_p
    # print(K_A,K_B)
    if K_A == K_B:
        # global key
        # key = bytes(K_A)
        # print(len(key))
        stop = datetime.now()
        time = stop - start
        print('Time taken for computaion: ', time)
        return K_A
    else:
        return "value error"


def MTI_B0(a,b,Z_a,Z_b,x,y):

    start = datetime.now()

    m_ab = (Z_b**x) % prime_p
    a_inv = modInverse(a)

    m_ba = (Z_a**y) % prime_p    #g^ay
    b_inv = modInverse(b)

    K_A = (((m_ba**a_inv) % prime_p ) * ((g**x) % prime_p))%prime_p
    K_B = (((m_ab**b_inv) % prime_p ) *  ((g**y) % prime_p)) % prime_p

    stop = datetime.now()
    time = stop - start
    print('Time taken for computaion: ', time)

    # print(K_A, K_B)
    if K_A == K_B:
        return K_A
    else:
        return "value error"


def MTI_C0(a,b,Z_a,Z_b,x,y):

    start = datetime.now()


    m_ab = (Z_b**x) % prime_p
    a_inv = modInverse(a)

    m_ba = (Z_a**y) % prime_p
    b_inv = modInverse(b)

    K_A = ((m_ba ** (a_inv) % prime_p) ** x) % prime_p
    K_B = ((m_ab ** (b_inv) % prime_p) ** y) % prime_p

    stop = datetime.now()
    time = stop - start
    print('Time taken for computaion: ', time)

    # print(K_A, K_B)
    if K_A == K_B:
        return K_A
    else:
        return "value error"

def MTI_C1(a,b,Z_a,Z_b,x,y):

    start = datetime.now()

    m_ab = (((Z_b ** x) % prime_p) **a) % prime_p
    m_ba = (((Z_a ** y) % prime_p) **b) % prime_p

    K_A =  (m_ba**x) % prime_p
    K_B = (m_ab ** y) % prime_p
    # print(K_A,K_B)

    stop = datetime.now()
    time = stop - start
    print('Time taken for computaion: ', time)

    if K_A == K_B:
        return K_A
    else:
        return "value error"


if __name__ == '__main__':

    print('The prime is: ', prime_p, '\n')

    # user 1 long term private key 'a'
    private_1 = int(input(print("User 1 select your long term private key: \n")))
    # os.system('clear')
#     user 1 long term public key g^a
    Z_1 = (g ** private_1) % prime_p
    print("Your long term public key is: ", Z_1)

#     user 2 long term private key 'b'
    private_2 = int(input(print('User 2 select your long term private key:\n')))

#     User 2 long term public key 'g^y'
    Z_2 = (g ** private_2) % prime_p
    print('Your long term public key is: ', Z_2)


# user 1 selects a session secret key 'x'
    temp_private_1 = int(input(print("User 1 select your session private key: \n")))


# user 2 selects a session secret key 'y'
    temp_private_2 = int(input(print("User 2 select your session private key: \n")))

    print('----------------------------------------------------\n')

    i = 1
    while i > 0:
        print('----------------------------------------------------\n')

        print('''
           Please select your option for Key exchange:
           1. Key Exchange
           2. Encrypt
           0. Exit 
           ''')
        n = input('enter value: ')

        if n == '1':
            print('Your session key using MTI A0 is: ', MTI_A0(private_1,private_2,Z_1,Z_2,temp_private_1,temp_private_2), '\n')

            print('Your session key using MTI B0 is: ', MTI_B0(private_1,private_2,Z_1,Z_2,temp_private_1,temp_private_2), '\n')

            print('Your session key using MTI C0 is: ', MTI_C0(private_1,private_2,Z_1,Z_2,temp_private_1,temp_private_2), '\n')

            print('Your session key using MTI C1 is: ', MTI_C1(private_1,private_2,Z_1,Z_2,temp_private_1,temp_private_2), '\n')

        elif n == '2':
            process_image(filename)

        elif n == '0':
            i = 0
        else:
            print('wrong option selected')


