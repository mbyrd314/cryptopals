# Brute force check all possible seed values (only 16 bits)
# Can't use previous method because there are only 14 known plaintext characters
# For password reset token, count back in time to see if the token is a MT output
# of a time stamp
import random, os, time

def xor_bytes(byte1, byte2):
    """
    XORs two bytestrings and returns the result

    Args:
        byte1 (bytes): The first bytestring to be XORed
        byte2 (bytes): The second bytestring to be XORed

    Returns:
        bytes: The result of XORing the two inputs
    """
    return bytes(a^b for a,b in zip(byte1, byte2))

class MT19937:
    def __init__(self, seed_val):
        # These are the required constants for 32 bit MT19937
        self.w, self.n, self.m, self.r = 32, 624, 397, 31
        self.a = int.from_bytes(b'\x99\x08\xB0\xDF', byteorder='big')
        self.u, self.d = 11, int.from_bytes(b'\xFF\xFF\xFF\xFF', byteorder='big')
        self.s, self.b = 7, int.from_bytes(b'\x9D\x2C\x56\x80', byteorder='big')
        self.t, self.c = 15, int.from_bytes(b'\xEF\xC6\x00\x00', byteorder='big')
        self.l = 18
        self.f = 1812433253
        self.MT = [0]*self.n
        self.index = self.n+1
        self.lower_mask = (self.l << self.r) - 1
        self.upper_mask = not self.lower_mask # Lowest w bits of not lower_mask
        self.upper_mask = self.upper_mask & (2**self.w-1)
        self.seed_val = seed_val
        self.seed_mt(self.seed_val)

    def seed_mt(self, seed_val):
        self.index = self.n
        self.MT[0] = seed_val
        for i in range(1, self.n):
            num = (self.f * (self.MT[i-1] ^ (self.MT[i-1] >> (self.w-2))) + i)
            self.MT[i] = num & (2**self.w-1)

    def twist(self):
        for i in range(self.n):
            x = (self.MT[i] & self.upper_mask) + (self.MT[(i+1)%self.n] & self.lower_mask)
            xA = x >> 1
            if (x % 2) != 0:
                xA = xA ^ self.a
            self.MT[i] = self.MT[(i+self.m)%self.n] ^ xA
        self.index = 0

    def extract_number(self):
        if self.index >= self.n:
            if self.index > self.n:
                raise ValueError('Generator was never seeded')
            else:
                self.twist()

        y = self.MT[self.index]
        y = y ^ ((y >> self.u) & self.d)
        y = y ^ ((y << self.s) & self.b)
        y = y ^ ((y << self.t) & self.c)
        y = y ^ (y >> self.l)

        self.index += 1
        return y & (2**self.w-1) # Return lowest w bits of y

    def untemper(self, val):
        val = val ^ (val >> self.l)
        val = val ^ ((val << self.t) & self.c)
        mask = int.from_bytes(b'\x7f', byteorder='big')
        for i in range(4):
            tmp = (mask << 7*(i+1)) & self.b
            val = val ^ ((val << self.s) & tmp)
        for i in range(3): # self.d is all 1s, so it isn't needed here
            val = val ^ (val >> self.u)
        return val & (2**self.w-1)

    def cloneMT(self, other_MT):
        for i in range(self.n):
            self.MT[i] = self.untemper(other_MT.extract_number())
        self.index = self.n

    def stream_encrypt(self, plaintext):
        keysize = 4 # MT generates 4 byte outputs
        ciphertext = b''
        for i in range(len(plaintext)):
            idx = i % keysize
            if idx == 0:
                num = self.extract_number()
                keystream = int.to_bytes(num, keysize, byteorder='big')
                # print(f'num={num}, keystream={keystream}, type(keystream)={type(keystream)}, type(keystream[idx])={type(keystream[idx])}, type(plaintext[i])={type(plaintext[i])}')
            ciphertext += int.to_bytes(plaintext[i] ^ keystream[idx], 1, byteorder='big')
        return ciphertext

def create_password_reset_token(plaintext):
    cur_time = int(time.time())
    print(f'Seed time = {cur_time}')
    mt = MT19937(cur_time)
    token = mt.stream_encrypt(plaintext)
    return token

def is_valid_token(token):
    cur_time = int(time.time())
    print(f'Start time = {cur_time}')
    for t in range(cur_time, cur_time-1000, -1): # Checks the previous 1000 time values
        mt = MT19937(t)
        plaintext = mt.stream_encrypt(token)
        if plaintext[-14:] == b'A'*14:
            print(f'MT seeded at time {t}')
            return True
    print(f'MT was not seeded with a time value')
    return False

if __name__ == '__main__':
    seed_val = random.randint(0, 2**16-1) # Generating a random 16 bit seed
    plaintext = os.urandom(random.randint(5, 32)) # Generating a random number of random characters
    plaintext += b'A'*14
    mt0 = MT19937(seed_val)
    ciphertext = mt0.stream_encrypt(plaintext)
    cracked_seed = None
    print(f'seed_val={seed_val}')
    print(f'plaintext={plaintext}')
    print(f'ciphertext={ciphertext}')
    for seed1 in range(0, 2**16-1):
        mt1 = MT19937(seed1)
        plain1 = mt1.stream_encrypt(ciphertext)
        if plain1[-14:] == b'A'*14:
            cracked_seed = seed1
            print(f'Decrypted plaintext = {plain1}')
            break
    print(f'seed_val={seed_val}, cracked_seed={cracked_seed}')

    plaintext = os.urandom(random.randint(5, 32)) # Generating a random number of random characters
    plaintext += b'A'*14
    token = create_password_reset_token(plaintext)
    time.sleep(random.randint(10, 100))
    valid = is_valid_token(token)
    if valid:
        print(f'Token was seeded with time value')
    else:
        print('Token was not seeded with time value')
