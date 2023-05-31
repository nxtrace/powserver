import random
import time


def get_r_and_d(n):
    r = 0
    d = n

    while d % 2 == 0:
        r += 1
        d //= 2

    return r, d


class PrimeGenerator:
    def __init__(self, bits, k=40):
        self.bits = bits
        self.k = k

    def generate_large_number(self):
        start = time.time()

        p = self.generate_prime()
        q = self.generate_prime()
        if p > q:
            p, q = p, q
        num = p * q

        end = time.time()
        elapsed = end - start

        return p, q, num, elapsed

    def generate_prime(self):
        while True:
            p = random.getrandbits(self.bits)
            if self.is_prime(p):
                return p

    def is_prime(self, num):
        if num < 2:
            return False
        if num < 4:
            return True
        if num % 2 == 0 or num % 3 == 0:
            return False

        r, d = get_r_and_d(num - 1)

        for _ in range(self.k):
            a = random.randint(2, num - 2)
            x = pow(a, d, num)

            if x == 1 or x == num - 1:
                continue

            for _ in range(r - 1):
                x = pow(x, 2, num)

                if x == num - 1:
                    break
            else:
                return False

        return True


if __name__ == '__main__':
    _bits = 36

    prime_generator = PrimeGenerator(_bits)
    _p, _q, _num, _elapsed = prime_generator.generate_large_number()

    print(f"p: {_p}")
    print(f"q: {_q}")
    print(f"Product: {_num}")
    print(f"Elapsed time: {_elapsed} seconds")
