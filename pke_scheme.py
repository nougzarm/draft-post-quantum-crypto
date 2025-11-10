from xof import G, PRF
from polynomial import SampleNTT, SamplePolyCBD, NTT, PolynomialNTT
from conversion import ByteEncode

""" 
Correspond à l'algorithme 13
"""
def PKE_KeyGen(d, k, eta_1):
    rho, gamma = G(d + bytes([k]))
    N = 0

    A_ntt = []
    for i in range(k):
        temp_line = []
        for j in range(k):
            temp_line.append(SampleNTT(rho + bytes([j]) + bytes([i])))
        A_ntt.append(temp_line)

    s = []
    for i in range(k):
        s.append(SamplePolyCBD(PRF(eta_1, gamma, bytes([N])), eta_1))
        N += 1
    
    e = []
    for i in range(k):
        e.append(SamplePolyCBD(PRF(eta_1, gamma, bytes([N])), eta_1))
        N += 1
    
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

# --- Exemple d'utilisation et tests ---
if __name__ == '__main__':
    ek, dk = PKE_KeyGen(b"Salut de la part de moi meme lee", 3, 3)
    print(ek)
    print(dk)