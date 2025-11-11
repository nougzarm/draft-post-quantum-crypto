from constants import CONST_d, N
from xof import G, PRF
from polynomial import *
from conversion import *

""" 
Valeurs des paramètres approuvées :
1ere configuration : k = 2, eta_1 = 3, eta_2 = 2, d_u = 10, d_v = 4
2eme configuration : k = 3, eta_1 = 2, eta_2 = 2, d_u = 10, d_v = 4
3eme configuration : k = 4, eta_1 = 2, eta_2 = 2, d_u = 11, d_v = 5
"""

""" 
Algorithm 13 : K-PKE.KeyGen(d)

Input : randomness d in B^32
Output : (ek, dk) pair of encryption-decryption keys
with : ek in B^(384*k + 32), and dk in B^(384*k)
"""
def PKE_KeyGen(d: bytes, k: int, eta_1: int):
    if k not in (2, 3, 4):
        raise ValueError(f"Mauvaise valeur de paramètre k.")
    if eta_1 not in (2, 3):
        raise ValueError(f"Mauvaise valeur de paramètre eta_1.")
    if len(d) != 32:
        raise ValueError(f"Mauvaise longueur de la seed d")

    rho, gamma = G(d + bytes([k]))
    N_var = 0

    A_ntt = []
    for i in range(k):
        temp_line = []
        for j in range(k):
            temp_line.append(SampleNTT(rho + bytes([j]) + bytes([i])))
        A_ntt.append(temp_line)

    s = []
    for i in range(k):
        s.append(SamplePolyCBD(PRF(eta_1, gamma, bytes([N_var])), eta_1))
        N_var += 1
    
    e = []
    for i in range(k):
        e.append(SamplePolyCBD(PRF(eta_1, gamma, bytes([N_var])), eta_1))
        N_var += 1
    
    s_ntt = [NTT(poly) for poly in s]
    e_ntt = [NTT(poly) for poly in e]

    t_ntt = []
    for i in range(k):
        pol_temp = PolynomialNTT()
        for j in range(k):
            pol_temp = pol_temp + A_ntt[i][j] * s_ntt[j]
        t_ntt.append(pol_temp + e_ntt[i])
    
    ek = b"".join([ByteEncode(poly.coeffs, CONST_d) for poly in t_ntt]) + rho
    dk = b"".join([ByteEncode(poly.coeffs, CONST_d) for poly in s_ntt])
    
    return ek, dk

""" 
Algorithm 14 : K-PKE.Encrypt(ek, m, r)

Input : encryption key ek in B^(384*k + 32)
Input : message m in B^32
Input : randomness r in B^32
Output : ciphertext c in B^(32 * (d_u * k + d_v))
"""
def PKE_Encrypt(ek: bytes, m: bytes, r: bytes, k: int, eta_1: int, eta_2: int, d_u: int, d_v: int):
    if k not in (2, 3, 4): raise ValueError(f"Mauvaise valeur de k.")
    if eta_1 not in (2, 3) or eta_2 not in (2, 3): raise ValueError(f"Mauvaise valeur eta_1 ou eta_2.")
    if d_u not in range(12) or d_v not in range(12):
        raise ValueError(f"Mauvaise valeur de paramètre d_u ou d_v.")
    
    if len(ek) != 384*k + 32 or len(m) != 32 or len(r) != 32:
        raise ValueError(f"Mauvaise longueur d'une des entrées ek, m ou r")
    
    N_var = 0
    t_ntt = [PolynomialNTT(ByteDecode(ek[384*i : 384*(i+1)], CONST_d)) for i in range(k)]
    rho = ek[384*k:]

    A_ntt = []
    for i in range(k):
        temp_line = []
        for j in range(k):
            temp_line.append(SampleNTT(rho + bytes([j]) + bytes([i])))
        A_ntt.append(temp_line)

    y = []
    for i in range(k):
        y.append(SamplePolyCBD(PRF(eta_1, r, bytes([N_var])), eta_1))
        N_var += 1

    e_1 = []
    for i in range(k):
        e_1.append(SamplePolyCBD(PRF(eta_2, r, bytes([N_var])), eta_2))
        N_var += 1

    e_2 = SamplePolyCBD(PRF(eta_2, r, bytes([N_var])), eta_2)
    y_ntt = [NTT(poly) for poly in y]

    u = []
    for i in range(k):
        pol_temp = PolynomialNTT()
        for j in range(k):
            pol_temp = pol_temp + A_ntt[j][i] * y_ntt[j]
        u.append(inverse_NTT(pol_temp) + e_1[i])
    
    mu = Polynomial([Decompress(b, 1) for b in ByteDecode(m, 1)])

    v_ntt_temp = PolynomialNTT()
    for i in range(k):
        v_ntt_temp += t_ntt[i] * y_ntt[i]
    v = inverse_NTT(v_ntt_temp) + e_2 + mu

    c_1 = b"".join([ByteEncode([Compress(coeff, d_u) for coeff in poly.coeffs], d_u) for poly in u])
    c_2 = ByteEncode([Compress(coeff, d_v) for coeff in v.coeffs], d_v)

    return c_1 + c_2

""" 
Algorithm 15 : K-PKE.Decrypt(dk, c)

Input : decryption key dk in B^(384*k)
Input : ciphertext c in B^(32 * (d_u*k + d_v))
Output : message m in B^32
"""
def PKE_Decrypt(dk: bytes, c: bytes, k: int, d_u: int, d_v: int) -> bytes:
    if k not in (2, 3, 4):
        raise ValueError(f"Mauvaise valeur de paramètre k.")
    if d_u not in range(12) or d_v not in range(12):
        raise ValueError(f"Mauvaise valeur de paramètre d_u ou d_v.")
    
    if len(dk) != 384*k or len(c) != 32*(d_u*k + d_v):
        raise ValueError(f"Mauvaise longueur d'une des entrées ek, m ou r")

    c_1 = c[:32 * d_u * k]
    c_2 = c[32 * d_u * k:]

    u_prime = []
    for i in range(k):
        decode = ByteDecode(c_1[32*d_u*i:32*d_u*(i+1)], d_u)
        u_prime.append(Polynomial([Decompress(coeff, d_u) for coeff in decode]))

    v_prime = Polynomial([Decompress(coeff, d_v) for coeff in ByteDecode(c_2, d_v)])

    s_ntt = [PolynomialNTT(ByteDecode(dk[384*i:384*(i+1)], CONST_d)) for i in range(k)]
    pdt_temp = PolynomialNTT()
    for i in range(k):
        pdt_temp += s_ntt[i] * NTT(u_prime[i])
    w = v_prime - inverse_NTT(pdt_temp)
    m = ByteEncode([Compress(coeff, 1) for coeff in w.coeffs], 1)
    return m

# --- Exemple d'utilisation et tests ---
if __name__ == '__main__':
    k, eta_1, eta_2, d_u, d_v = 3, 2, 2, 10, 4
    seed = b"Salut de la part de moi meme lee"

    ek, dk = PKE_KeyGen(seed, k, eta_1)

    message = b"Ce message est tres confidentiel"
    ciphertext = PKE_Encrypt(ek, message, seed, k, eta_1, eta_2, d_u, d_v)

    mess_decrypt = PKE_Decrypt(dk, ciphertext, k, d_u, d_v)
    print(mess_decrypt)