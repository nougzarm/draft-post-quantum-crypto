from constants import ZETA, Q

def BitRev(i: int, L=7) -> int:
    reversed_i = 0

    for k in range(L):
        bit = (i >> k) & 1
        reversed_i |= (bit << (L - 1 - k))

    return reversed_i

if __name__ == '__main__':
    print([(ZETA**BitRev(i)) % Q for i in range(128)])