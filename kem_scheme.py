from pke_scheme import *
from xof import H, G, J

""" 
Algorithm 16 : ML-KEM.KeyGen_internal(d, z)
Uses randomness to generate an encapsulation key and a corresponding decapsulation key.

Input : randomness d in B^32
Input : randomness z in B^32
Output : encapsulation key ek in B^(384*k + 32)
output : decapsulation key dk in B^(768*k + 96)
"""
def KEM_KeyGen_internal(d: bytes, z: bytes, k: int, eta_1: int):
    if len(z) != 32:
        raise ValueError(f"Mauvaise longueur de la seed z")
    
    ek_pke, dk_pke = PKE_KeyGen(d, k, eta_1)
    dk = dk_pke + ek_pke + H(ek_pke) + z

    return ek_pke, dk

""" 
Algorithm 17 : ML-KEM.Encaps_internal(ek, m)
Uses the encapsulation key and randomness to generate a key and an associated ciphertext.

Input : encapsulation key ek in B^(384*k + 32)
Input : randomness m in B^32
Output : shared secret key K in B^32
Output : ciphertext c in B^(32 * (d_u*k + d_v))
"""
def KEM_Encaps_internal(ek: bytes, m: bytes, k: int, eta_1: int, eta_2: int, d_u: int, d_v: int):
    K, r = G(m + H(ek))
    c = PKE_Encrypt(ek, m, r, k, eta_1, eta_2, d_u, d_v)
    return K, c

""" 
Algorithm 18 : ML-KEM.Decaps_internal(dk, c)
Uses the decapsulation key to produce a shared secret key from a ciphertext.

Input : decapsulation key dk in B^(768*k + 96)
Input : ciphertext c in B^(32 * (d_u*k + d_v))
Output : shared secret key K in B^32
"""
def KEM_Decaps_internal(dk: bytes, c: bytes, k: int, eta_1: int, eta_2: int, d_u: int, d_v: int):
    dk_pke = dk[:384 * k]
    ek_pke = dk[384 * k:768 * k + 32]
    h = dk[768 * k + 32:768 * k + 64]
    z = dk[768 * k + 64:]
    m_prime = PKE_Decrypt(dk_pke, c, k, d_u, d_v)
    K_prime, r_prime = G(m_prime + h)
    K_bar = J(z + c)
    c_prime = PKE_Encrypt(ek_pke, m_prime, r_prime, k, eta_1, eta_2, d_u, d_v)

    if c != c_prime:
        K_prime = K_bar
    
    return K_prime