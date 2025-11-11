from constants import Q, N, ZETA, ZETAS

def BitRev(i: int, L=7) -> int:
    reversed_i = 0

    for k in range(L):
        bit = (i >> k) & 1
        reversed_i |= (bit << (L - 1 - k))

    return reversed_i

""" 
Algorithm 11 : MultiplyNTTs(f_ntt, g_ntt)
Computes the product (in the ring T_Q) of two NTT representations.

Input : Two arrays f_ntt and g_ntt in Z_Q^N
Output : An array h_ntt in Z_Q^N
"""
def MultiplyNTTs(f_ntt: list, g_ntt: list):
    if len(f_ntt) != N or len(g_ntt) != N:
        raise ValueError(f"The lengths of the lists do not match")

    h_ntt = [0] * N
    for i in range(128):
        gamma = ((ZETAS[i]**2) * ZETA) % Q
        C = BaseCaseMultiply(f_ntt[2*i], f_ntt[2*i + 1], g_ntt[2*i], g_ntt[2*i + 1], gamma)
        h_ntt[2*i] = C[0]
        h_ntt[2*i + 1] = C[1]
        
    return h_ntt

""" 
Algorithm 12 : BaseCaseMultiply(a0, a1, b0, b1, gamma)
Computes the product of two degree-one polynomials with respect to a quadratic modulus.

Input : a0, a1, b0, b1 in Z_Q
Input : gamma in Z_Q
Output : c0, c1 in Z_Q
"""
def BaseCaseMultiply(a0: int, a1: int, b0: int, b1: int, gamma: int):
    c0 = (a0*b0 + a1*b1*gamma) % Q
    c1 = (a0*b1 + a1*b0) % Q
    return [c0, c1]