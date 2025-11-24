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
    assert c.hex() == "aaaae490a2820e03d5252fb685d64e3bbcaf7e5119c39c5e96168297cb21cc291acfa96f7443b0fe25176f87cc722a742d917a7c13a189e9c97a326a398486cc11bc3301b70c38d93b98d4bc53761e847166a6f9bc0eac3b1f648404f9ff20feb92dfa68dc6e5ae697d9f853c5a4c486bbc9344665fcb6319872f2ca021042712cf412f0c622f93be7cdbed75654a8826ecd5734a843f331ee9e10306b2e287cf81c9621434020db2a55182ea543c14d28274375a76f7764ff09517d32b2dc0d97ae908136aa054111b23e948b038ade262fbdd78e3e84243582d8a9a836109ab9b0ad4b8eb2468ae9750437903d8fecee33c6b0a986d34fcda3b3e8926d39f3b19c0dc03b7a066d92b5b756495b6bd6ec472235b757d20a50b7733c2a03cb516f378e0b4a5b48daf4a324e21d93ce65221261734a5978d8ff5870e06fb61de7ea04acb1bf20cbd7a6de9627f5707685640389fb89c98695314eac05231ac04d8ae92cc99f05405b692bd9d1d0a411285668f4e422143a7ddfc544d13446f0caae9e1387a1f91f19d08cc2be7c6eb31337f8680e87d11d4768dd97dd517eafcde4641b588e729b9e5928372868cf9ce443dd45b142b6f79383041b2676e0b9dab5166f9f7101d824dad711b6fb2d8d7e370038da229d545a82a7cf705fcd223273d29bf47ff49b2fb1f37a9d7463fe61ad4d91dbb5ba5a89c6a4c8ed0d2e69aa866d2ed5f056f72d3caf6ab1e13fdf1da78fe26c84844c3b52c758bf79d855e32734b58e742f795920d71a87c1f9204d60d1c9b3800a64035cd5a5de6f6de8774103ec18080296cafe747a9384ce0fe1faad8c0d256fe2311df570fb4f539fc8d8bfd645371e91808aada68c48263b4d74cf071f7a1564c06d0e17f4855c26f8387cf45b42ade887110c63f29817cf7c0a155a3e2259592943685a2f5c0c59aa8001f07148b076e4ca8abc73e70b028f5431da1fc12a0e066f0674ee05f697c2b415bf132a90be4b3f66ffad9186bc7990593f970e590edf553180d66abb7ab0f940e75bac02df54b51177857bd5317ad27f7a3420e5affe5527c9710de6f28049f4700ceca2a23c7eefb4195812684b5bdc31bc85eb330a8948388d90db3ab677b7f54d7fbc418e98fce6f2f811143d952986e9cef0adc12e7a00e345b210f68de2513c83e21757b9a29b614e30c932c538df1ff2c9342fa8af49164d97338d489f06f807f7edd84d2b8f51d283a237ef595be4a7b0e9d60d9fcdb0d20a63d1f924133618e8c393344c6edb1d9f68c3f710dfbfaf00b93ee5ff4a3ac2ef439126ae370f357fb4e44f43178e9bd6893113e8f7bdbf08afcb751d1e2b07d2d9e6cc1924a7277956ca226416b64f6357a3eb0b1ef8164f6d03d96c34f7cbc72a3aae4f2ffae05f93a18d3c79e2674b3a19045457905b340af018092a19d2360dcf40d24fd7e9a89a80ae802a3a278714bc72793e58f4af84890f6fd9cc4f5a844c9ba65463289592e95d6e4a5998b6626229d0d753f6d22cc5686650ce454f9b10"

    K_decaps = kem_scheme.Decaps_internal(dk, c)
    assert K_decaps == K

    # --------------------------------------------------
    # --- Testing of main algorithms -------------------
    # --------------------------------------------------
    ek, dk = kem_scheme.KeyGen()

    K, c = kem_scheme.Encaps(ek)

    K_decaps = kem_scheme.Decaps(dk, c)
    assert K_decaps == K