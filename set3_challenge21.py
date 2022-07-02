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

if __name__ == '__main__':
    # These are the required constants for 32 bit MT19937
    # w, n, m, r = 32, 624, 397, 31
    # a = int.from_bytes(b'\x99\x08\xB0\xDF', byteorder='big')
    # u, d = 11, int.from_bytes(b'\xFF\xFF\xFF\xFF', byteorder='big')
    # s, b = 7, int.from_bytes(b'\x9D\x2C\x56\x80', byteorder='big')
    # t, c = 15, int.from_bytes(b'\xEF\xC6\x00\x00', byteorder='big')
    # l = 18
    # f = 1812433253
    # MT = [0]*n
    # index = n+1
    # lower_mask = (l << r) - 1
    # upper_mask = not lower_mask # Lowest w bits of not lower_mask
    # upper_mask = upper_mask & (2**w-1)
    #
    # def seed_mt(seed):
    #     global index
    #     index = n
    #     MT[0] = seed
    #     for i in range(1, n):
    #         num = (f * (MT[i-1] ^ (MT[i-1] >> (w-2))) + i)
    #         MT[i] = num & (2**w-1)
    #
    # def twist():
    #     global index
    #     for i in range(n):
    #         x = (MT[i] & upper_mask) + (MT[(i+1)%n] & lower_mask)
    #         xA = x >> 1
    #         if (x % 2) != 0:
    #             xA = xA ^ a
    #         MT[i] = MT[(i+m)%n] ^ xA
    #     index = 0
    #
    # def extract_number():
    #     global index
    #     if index >= n:
    #         if index > n:
    #             raise ValueError('Generator was never seeded')
    #         else:
    #             twist()
    #
    #     y = MT[index]
    #     y = y ^ ((y >> u) & d)
    #     y = y ^ ((y << s) & b)
    #     y = y ^ ((y << t) & c)
    #     y = y ^ (y >> l)
    #
    #     index += 1
    #     return y & (2**w-1) # Return lowest w bits of y

    # Testing to make sure that it reliably produces the same sequence with random seed values
    outer_iters = 10
    for it in range(outer_iters):
        iters = 100
        seed_val = random.randint(21, 2**32)
        nums = []
        print(f'Starting iteration {it}, seed = {seed_val}')
        for i in range(iters):
            mt = MT19937(seed_val)
            mt.extract_number()
            nums.append([x for x in mt.MT])
            print(f'i={i}, MT={mt.MT[:10]}')
            # seed_mt(seed_val)
            # extract_number()
            # nums.append([x for x in MT])
            # print(f'i={i}, MT={MT[:10]}')
        trueCount = 0
        falseCount = 0
        for i in range(iters):
            for j in range(iters):
                for k in range(len(nums[0])):
                    if nums[i][k] != nums[j][k]:
                        falseCount += 1
                        print(f'Sequence {i} and Sequence {j} were not equal at position {k}')
                    else:
                        trueCount += 1
        print(f'Iteration: {it}, True count = {trueCount}')
        print(f'Iteration: {it}, False count = {falseCount}') # This should be 0
