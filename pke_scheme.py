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
    assert ciphertext.hex() == "012ac1758bc94772b397ca25074f4a215bdf198f247b7c752570718c8cb343026ab5d3d2f3d077b027eadb4f48e5f03b2e6269a526404b2da74b3f37fece1d855839434f9d9248bae4d368cf641ec582de41d5844123b0154e9ec72e1bf945c65e3b3b07fd838c1b2f810f1ba7b6edc8ff2f8c30cdc5bb962a9cf003763442388ff329714fff31d74614572c3d29106a58400e8c0192fe956a48f80b0d9ae0702b5ab92e3fa21b08185418acd32f7e95f451e5577138bf88c04e792544f325dacff933cb44bca9ed3c947d4b1af6bed402dd9abefdd752cf835924c1497f3fb0e8a5fc0af2e4256120f0eeac759194661a6e3fdb21f7b2dd69bc35cecc827fa63639dab275a2979b52db602a7bb82bbaeb00ff77e0f2a0c9eb62cc67eb374cf930b59afa48b1bffcb4ec35c9050a5b3f3ee1e7602eec383095b3405a5c2a9a34a1bd65349706ace75e4e5700661a49097bc395e3529cea3dad0a60360166fd6c39a3e4448b7b9a019810ae1f2788ea4e59c70fc3a86402bce1de829b300c765fc04fb868ddbfe18415742d87d9c61b04dbb25212a4d0f94cef95b1a0ae14802d7a2ed594c72744fd8edb3b5042bb097e6b3ee2453ea11f8ec3c605de358ab9e20d030c709963084da663a0d9960fe219f565ddd28de3cf55700ca52fefacaeff1eb4a33acd0e03451f7426cd366d2bc2ec15908fe8df228d18eb895cb02bc58881dc7d0257212e8a0629ce9e7dfbc1d6e5674ad03ecb856896effefdf4a2e04b8d2751588d50202e6561c557058bc4987f91e992039a8c113a0ee0526b8bdfe3794988e7def3d274db03bb44b6641cc1796ebdfac2168d40aa2bbee9676d8f7526883579f3244c80ba7c052adeaa25e897621c2e723738ab1d3d357be714f1c1098185e46df87152ab4036da585f5c6c8afe971d9ffefa49bd446e4c625e9e9455c79d7f8f744c4e6baccb8cb85dfbb06f10348ee605eb6764623175fcfd90ceb9c62e5969618bf4663650798d96acd35c5840ba5eb9cf01b61f62677648e4f4087589be566edc9df121f686665b1eb56ab265807125abba488df00d174d6f01aa9b5c70b83ae18cfced6aad04eebfb41831d65b4169cd36f0d6a18888d1244eba5b659a2be54f70ee2d3c4a6431b83f63b676dc636169b8d3f3aa8ac3b285339fd657087745a70324a35904c501f9a60d3d89463e063ea9757c381b33bf1aa3ec6acfef970e54a1369e5d123e357f4b28dedaf0775fe24014414a83a6b603cd2d0e51aab08238b11f7edc685697328adf7fce4bf05e20de54b4843f163060dc2848685338584a90660d52fdf9f482f49669fee04bdd9a0c4296de160cf2405e249844de8ba1ba815bc6ad86146a8798ea723f00601e77f1455872be02cabf47dde765913ed904b34eb00efee1d7bc3181b4dddb3441b12d5660803a50658a2bb567ccf50af9ef7e07903902265f43d57270374a30d89bc964ec5a076cc8276c4788e289957fb0efa5a7d5ea688ff56c55e91488c4b79bc3177fcf2c469b7c9b"

    mess_decrypt = pke_scheme.Decrypt(dk, ciphertext)
    assert mess_decrypt == message