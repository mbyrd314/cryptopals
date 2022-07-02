# Brute force check every time starting with the current time going backward until
# you match the output that was generated and thus the seed
import time, random

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

if __name__ == '__main__':
    delta = random.randint(40, 100)
    time.sleep(delta)
    t0 = int(time.time())
    seed_val = t0
    mt0 = MT19937(seed_val)
    print(f'Seeded first MT')
    delta = random.randint(40, 100)
    time.sleep(delta)
    out0 = mt0.extract_number()
    # out0 = mt0.MT[0]
    cur_time = int(time.time())
    cracked_seed = None
    print(f'Starting iteration')
    # Guess every seed value from the current time to 3000 seconds in the past
    for t in range(cur_time, cur_time-3000, -1):
        mt1 = MT19937(t)
        out1 = mt1.extract_number()
        # out1 = mt1.MT[0]
        if out1 == out0:
            cracked_seed = t
            break
    print(f't0 = {t0}, Cracked seed val = {cracked_seed}')
