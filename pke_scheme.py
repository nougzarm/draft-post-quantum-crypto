from constants import CONST_d, N
from xof import G, PRF
from polynomial import *
from conversion import *

""" 
Algorithm 13 : K-PKE.KeyGen(d)

Input : randomness d in B^32
Output : (ek, dk) pair of encryption-decryption keys
with : ek in B^(384*k + 32), and dk in B^(384*k)
"""
def PKE_KeyGen(d, k, eta_1):
    if len(d) != 32:
        raise ValueError(f"Mauvaise longueur de la seed")

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
    
    s_ntt = [NTT(s[i]) for i in range(k)]
    e_ntt = [NTT(e[i]) for i in range(k)]

    t_ntt = []
    for i in range(k):
        pol_temp = PolynomialNTT()
        for j in range(k):
            pol_temp = pol_temp + A_ntt[i][j] * s_ntt[j]
        pol_temp = pol_temp + e_ntt[i]
        t_ntt.append(pol_temp)
    
    ek = b""
    dk = b""
    for i in range(k):
        ek = ek + ByteEncode(t_ntt[i].coeffs)
        dk = dk + ByteEncode(s_ntt[i].coeffs)
    ek = ek + rho

    return ek, dk

""" 
Algorithm 14 : K-PKE.Encrypt(ek, m, r)

Input : encryption key ek in B^(384*k + 32)
Input : message m in B^32
Input : randomness r in B^32
Output : ciphertext c in B^(32 * (d_u * k + d_v))
"""
def PKE_Encrypt(ek: bytes, m: bytes, r: bytes, k: int, eta_1: int, eta_2: int, d_u: int, d_v: int):
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
    y_ntt = [NTT(y[i]) for i in range(k)]

    u = []
    for i in range(k):
        pol_temp = PolynomialNTT()
        for j in range(k):
            pol_temp = pol_temp + A_ntt[j][i] * y_ntt[j]
        u.append(inverse_NTT(pol_temp) + e_1[i])
    
    mu_temp = ByteDecode(m, 1)
    mu = Polynomial([Decompress(mu_temp[i], 1) for i in range(N)])

    v_ntt_temp = PolynomialNTT()
    for i in range(k):
        v_ntt_temp += t_ntt[i] * y_ntt[i]
    v = inverse_NTT(v_ntt_temp) + e_2 + mu

    c_1 = b""
    for i in range(k):
        c_1 += ByteEncode([Compress(u[i].coeffs[j], d_u) for j in range(N)], d_u)
    c_2 = ByteEncode([Compress(v.coeffs[i], d_v) for i in range(N)], d_v)

    return c_1 + c_2

""" 
Algorithm 15 : K-PKE.Decrypt(dk, c)

Input : decryption key dk in B^(384*k)
Input : ciphertext c in B^(32 * (d_u*k + d_v))
Output : message m in B^32
"""
def PKE_Decrypt(dk: bytes, c: bytes, k: int, d_u: int, d_v: int) -> bytes:
    c_1 = c[0:32 * d_u * k]
    c_2 = c[32 * d_u * k:32 * (d_u * k + d_v)]

    u_prime = []
    for i in range(k):
        decode = ByteDecode(c_1[32*d_u*i:32*d_u*(i+1)], d_u)
        u_prime.append(Polynomial([Decompress(decode[j], d_u) for j in range(N)]))

    v_prime = Polynomial([Decompress(ByteDecode(c_2, d_u)[j], d_u) for j in range(N)])

    s_ntt = [PolynomialNTT(ByteDecode(dk[384*i:384*(i+1)], CONST_d)) for i in range(k)]
    pdt_temp = PolynomialNTT()
    for i in range(k):
        pdt_temp += s_ntt[i] * NTT(u_prime[i])
    w = v_prime - inverse_NTT(pdt_temp)
    m = ByteEncode([Compress(w.coeffs[i], 1) for i in range(N)], 1)
    return m

# --- Exemple d'utilisation et tests ---
if __name__ == '__main__':
    ek, dk = PKE_KeyGen(b"Salut de la part de moi meme lee", 3, 3)
    print(ek)
    print(dk)

    ciphertext = PKE_Encrypt(ek, b"Salut de la part de moi meme lee", b"Salut de la part de moi meme lee", 3, 3, 3, 11, 11)
    print(ciphertext)

    mess_decrypt = PKE_Decrypt(dk, ciphertext, 3, 11, 11)
    print(mess_decrypt)