import secrets
from pke_scheme import *
from hash import H, G, J

class ML_KEM:
    """
    Implements the ML-KEM (FIPS 203) scheme as a class 
    which contains the scheme parameters.
    """
    def __init__(self, k: int, eta_1: int, eta_2: int, d_u: int, d_v: int):
        self.pke = K_PKE(k, eta_1, eta_2, d_u, d_v)

    """ 
    Algorithm 16 : ML-KEM.KeyGen_internal(d, z)
    Uses randomness to generate an encapsulation key and a corresponding decapsulation key.

    Input : randomness d in B^32
    Input : randomness z in B^32
    Output : encapsulation key ek in B^(384*k + 32)
    Output : decapsulation key dk in B^(768*k + 96)
    """
    def KeyGen_internal(self, d: bytes, z: bytes):
        if len(z) != 32:
            raise ValueError(f"Mauvaise longueur de la seed z")
        
        ek_pke, dk_pke = self.pke.KeyGen(d)
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
    def Encaps_internal(self, ek: bytes, m: bytes):
        K, r = G(m + H(ek))
        c = self.pke.Encrypt(ek, m, r)
        return K, c

    """ 
    Algorithm 18 : ML-KEM.Decaps_internal(dk, c)
    Uses the decapsulation key to produce a shared secret key from a ciphertext.

    Input : decapsulation key dk in B^(768*k + 96)
    Input : ciphertext c in B^(32 * (d_u*k + d_v))
    Output : shared secret key K in B^32
    """
    def Decaps_internal(self, dk: bytes, c: bytes):
        dk_pke = dk[:384 * self.pke.k]
        ek_pke = dk[384 * self.pke.k:768 * self.pke.k + 32]
        h = dk[768 * self.pke.k + 32:768 * self.pke.k + 64]
        z = dk[768 * self.pke.k + 64:]
        m_prime = self.pke.Decrypt(dk_pke, c)
        K_prime, r_prime = G(m_prime + h)
        K_bar = J(z + c)
        c_prime = self.pke.Encrypt(ek_pke, m_prime, r_prime)

        if c != c_prime:
            K_prime = K_bar
        
        return K_prime

    """ 
    Algorithm 19 : ML-KEM.KeyGen()
    Generates an encapsulation key and a corresponding decapsulation key.

    Output : encapsulation key ek in B^(384*k + 32)
    Output : decapsulation key dk in B^(768*k + 96)
    """
    def KeyGen(self):
        seed_d = secrets.token_bytes(32)
        seed_z = secrets.token_bytes(32)

        ek, dk = self.KeyGen_internal(seed_d, seed_z)

        return ek, dk

    """ 
    Algorithm 20 : ML-KEM.Encaps(ek)
    Uses the encapsulation key to generate a shared secret key and an associated ciphertext

    Input : encapsulation key ek in B^(384*k + 32)
    Output : shared secret key K in B^32
    Output : ciphertext c in B^(32 * (d_u*k + d_v))
    """
    def Encaps(self, ek: bytes):
        m = secrets.token_bytes(32)
        K, c = self.Encaps_internal(ek, m)
        return K, c

    """ 
    Algorithm 21 : ML-KEM.Decaps(dk, c)
    Uses the decapsulation key to produce a shared secret key from a ciphertext.

    Input : decapsulation key dk in B^(768*k + 96)
    Input : ciphertext c in B^(32 * (d_u*k + d_v))
    Output : shared secret key K in B^32
    """
    def Decaps(self, dk: bytes, c: bytes):
        K_prime = self.Decaps_internal(dk, c)
        return K_prime

# --- Example of use and test ---
if __name__ == '__main__':
    # --------------------------------------------------
    # --- Definition of parameters and ML-KEM scheme ---
    # --------------------------------------------------
    k, eta_1, eta_2, d_u, d_v = 3, 2, 2, 10, 4
    kem_scheme = ML_KEM(k, eta_1, eta_2, d_u, d_v)

    # --------------------------------------------------
    # --- Testing of 'internal' algorithms -------------
    # --------------------------------------------------
    d = H(b"randomness d")
    z = J(b"randomness z")
    ek, dk = kem_scheme.KeyGen_internal(d, z)

    seed = H(b"seed permettant l encapsulation")
    K, c = kem_scheme.Encaps_internal(ek, seed)

    K_decaps = kem_scheme.Decaps_internal(dk, c)
    assert K_decaps == K

    # --------------------------------------------------
    # --- Testing of main algorithms -------------------
    # --------------------------------------------------
    ek, dk = kem_scheme.KeyGen()

    K, c = kem_scheme.Encaps(ek)

    K_decaps = kem_scheme.Decaps(dk, c)
    assert K_decaps == K