from constants import Q, N, ZETA, ZETAS

def BitRev(i: int, L=7) -> int:
    reversed_i = 0

    for k in range(L):
        bit = (i >> k) & 1
        reversed_i |= (bit << (L - 1 - k))

    return reversed_i

""" 
Correspond à l'algorithme 11 de la spec
Il s'agit du coeur de la multiplication entre deux éléments de l'anneau T_Q
"""
def MultiplyNTTs(f_ntt: list, g_ntt: list):
    if len(f_ntt) != N or len(g_ntt) != N:
        raise ValueError(f"Longueurs incompatibles")

    h_ntt = [0] * N
    for i in range(128):
        gamma = ((ZETAS[i]**2) * ZETA) % Q
        C = BaseCaseMultiply(f_ntt[2*i], f_ntt[2*i + 1], g_ntt[2*i], g_ntt[2*i + 1], gamma)
        h_ntt[2*i] = C[0]
        h_ntt[2*i + 1] = C[1]
        
    return h_ntt

""" 
Correspond à l'algorithme 12 de la spec 
"""
def BaseCaseMultiply(a0, a1, b0, b1, gamma):
    c0 = (a0*b0 + a1*b1*gamma) % Q
    c1 = (a0*b1 + a1*b0) % Q
    return [c0, c1]

if __name__ == '__main__':
    print([(ZETA**BitRev(i)) % Q for i in range(128)])