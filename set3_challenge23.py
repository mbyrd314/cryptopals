# Extract 624 outputs from the MT, untemper all of them to get the corresponding
# internal state values, then use those to calculate all future outputs
import random


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

if __name__ == '__main__':
    iters = 100
    for it in range(iters):
        print(f'Iteration: {it}')
        seed0 = random.randint(1, 2**32-1)
        mt0 = MT19937(seed0)
        seed1 = random.randint(1, 2**32-1)
        mt1 = MT19937(seed1)
        print(f'seed0={seed0}, seed1={seed1}')
        mt1.cloneMT(mt0)
        # print(f'mt0.MT = {mt0.MT}')
        # print(f'mt1.MT = {mt1.MT}')
        for i in range(10): # Testing that they generate the same outputs even with different seeds
            out0 = mt0.extract_number()
            out1 = mt1.extract_number()
            print(f'i={i}, out0={out0}, out1={out1}')
        print()
