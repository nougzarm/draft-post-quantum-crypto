from constants import CONST_d
from hash import G, PRF
from polynomial import *
from conversion import *

class K_PKE:
    """
    Implements the K-PKE (FIPS 203) scheme as a class 
    which contains the scheme parameters.
    """
    def __init__(self, k: int, eta_1: int, eta_2: int, d_u: int, d_v: int):
        if k not in (2, 3, 4):
            raise ValueError(f"Unauthorized value for k")
        if eta_1 not in (2, 3) or eta_2 not in (2, 3):
            raise ValueError(f"Unauthorized value for eta_1 or eta_2")
        
        self.k = k
        self.eta_1 = eta_1
        self.eta_2 = eta_2
        self.d_u = d_u
        self.d_v = d_v

    """ 
    Algorithm 13 : K-PKE.KeyGen(d)

    Input : randomness d in B^32
    Output : (ek, dk) pair of encryption-decryption keys
    with : ek in B^(384*k + 32), and dk in B^(384*k)
    """
    def KeyGen(self, d: bytes):
        if len(d) != 32:
            raise ValueError(f"Unauthorized value for `d` seed length")

        rho, gamma = G(d + bytes([self.k]))
        N_var = 0

        A_ntt = []
        for i in range(self.k):
            temp_line = []
            for j in range(self.k):
                temp_line.append(SampleNTT(rho + bytes([j]) + bytes([i])))
            A_ntt.append(temp_line)

        s = []
        for i in range(self.k):
            s.append(SamplePolyCBD(PRF(self.eta_1, gamma, bytes([N_var])), self.eta_1))
            N_var += 1
        
        e = []
        for i in range(self.k):
            e.append(SamplePolyCBD(PRF(self.eta_1, gamma, bytes([N_var])), self.eta_1))
            N_var += 1
        
        s_ntt = [NTT(poly) for poly in s]
        e_ntt = [NTT(poly) for poly in e]

        t_ntt = []
        for i in range(self.k):
            pol_temp = PolynomialNTT()
            for j in range(self.k):
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
    def Encrypt(self, ek: bytes, m: bytes, r: bytes):
        if len(ek) != 384*self.k + 32 or len(m) != 32 or len(r) != 32:
            raise ValueError(f"Unauthorized length for ek, m or r")
        
        N_var = 0
        t_ntt = [PolynomialNTT(ByteDecode(ek[384*i : 384*(i+1)], CONST_d)) for i in range(self.k)]
        rho = ek[384*self.k:]

        A_ntt = []
        for i in range(self.k):
            temp_line = []
            for j in range(self.k):
                temp_line.append(SampleNTT(rho + bytes([j]) + bytes([i])))
            A_ntt.append(temp_line)

        y = []
        for i in range(self.k):
            y.append(SamplePolyCBD(PRF(self.eta_1, r, bytes([N_var])), self.eta_1))
            N_var += 1

        e_1 = []
        for i in range(self.k):
            e_1.append(SamplePolyCBD(PRF(self.eta_2, r, bytes([N_var])), self.eta_2))
            N_var += 1

        e_2 = SamplePolyCBD(PRF(self.eta_2, r, bytes([N_var])), self.eta_2)
        y_ntt = [NTT(poly) for poly in y]

        u = []
        for i in range(self.k):
            pol_temp = PolynomialNTT()
            for j in range(self.k):
                pol_temp = pol_temp + A_ntt[j][i] * y_ntt[j]
            u.append(inverse_NTT(pol_temp) + e_1[i])
        
        mu = Polynomial([Decompress(b, 1) for b in ByteDecode(m, 1)])

        v_ntt_temp = PolynomialNTT()
        for i in range(self.k):
            v_ntt_temp += t_ntt[i] * y_ntt[i]
        v = inverse_NTT(v_ntt_temp) + e_2 + mu

        c_1 = b"".join([ByteEncode([Compress(coeff, self.d_u) for coeff in poly.coeffs], self.d_u) for poly in u])
        c_2 = ByteEncode([Compress(coeff, self.d_v) for coeff in v.coeffs], self.d_v)

        return c_1 + c_2

    """ 
    Algorithm 15 : K-PKE.Decrypt(dk, c)

    Input : decryption key dk in B^(384*k)
    Input : ciphertext c in B^(32 * (d_u*k + d_v))
    Output : message m in B^32
    """
    def Decrypt(self, dk: bytes, c: bytes) -> bytes:
        if len(dk) != 384*self.k or len(c) != 32*(self.d_u*self.k + self.d_v):
            raise ValueError(f"Unauthorized length for ek, m or r")

        c_1 = c[:32 * self.d_u * self.k]
        c_2 = c[32 * self.d_u * self.k:]

        u_prime = []
        for i in range(self.k):
            decode = ByteDecode(c_1[32*self.d_u*i:32*self.d_u*(i+1)], self.d_u)
            u_prime.append(Polynomial([Decompress(coeff, self.d_u) for coeff in decode]))

        v_prime = Polynomial([Decompress(coeff, self.d_v) for coeff in ByteDecode(c_2, self.d_v)])

        s_ntt = [PolynomialNTT(ByteDecode(dk[384*i:384*(i+1)], CONST_d)) for i in range(self.k)]
        pdt_temp = PolynomialNTT()
        for i in range(self.k):
            pdt_temp += s_ntt[i] * NTT(u_prime[i])
        w = v_prime - inverse_NTT(pdt_temp)
        m = ByteEncode([Compress(coeff, 1) for coeff in w.coeffs], 1)
        return m

# --- Example of use and test ---
if __name__ == '__main__':
    # -------------------------------------------------
    # --- Definition of parameters and K-PKE scheme ---
    # -------------------------------------------------
    k, eta_1, eta_2, d_u, d_v = 3, 2, 2, 10, 4
    pke_scheme = K_PKE(k, eta_1, eta_2, d_u, d_v)

    seed = b"Salut de la part de moi meme lee"
    ek, dk = pke_scheme.KeyGen(seed)

    message = b"Ce message est tres confidentiel"
    ciphertext = pke_scheme.Encrypt(ek, message, seed)

    mess_decrypt = pke_scheme.Decrypt(dk, ciphertext)
    assert mess_decrypt == message