from Crypto.Hash import SHAKE128
from hashlib import shake_256, sha3_256, sha3_512

""" 
The XOF class is a wrapper for the SHAKE128 sponge.
This definition is described on pages 19 and 20 of the spec [FIPS 203]
"""
class XOF:
    def __init__(self):
        self._shake = SHAKE128.new()

    @classmethod
    def Init(cls):
        return cls()

    def Absorb(self, data: bytes):
        self._shake.update(data)

    def Squeeze(self, length: int) -> bytes:
        return self._shake.read(length)
    
""" 
Matches the definition in (4.2) and in (4.3)
PRF : {2, 3} x B^32 x B -> B^(64*eta)
"""
def PRF(eta, s: bytes, b: bytes):
    if eta != 2 and eta != 3:
        raise ValueError(f"Unauthorized value for eta")
    
    shake = shake_256(s + b)
    return shake.digest(64 * eta)

""" 
Matches the definition in (4.4)
H : B* -> B^32
J : B* -> B^32
"""
def H(s: bytes) -> bytes:
    hash_obj = sha3_256(s)
    return hash_obj.digest()

def J(s: bytes) -> bytes:
    shake = shake_256(s)
    return shake.digest(32)

""" 
Matches the definition in (4.5)
G : B* -> B^32 x B^32
"""
def G(c: bytes):
    hash_obj = sha3_512(c)
    result = hash_obj.digest()
    a = result[:32]
    b = result[32:]
    return a, b

# --- Example of use and test ---
if __name__ == '__main__':
    prf_result = PRF(2, b"qjdhfyritoprlkdjfkrjfbdnzyhdjrtr", b"a")
    assert prf_result.hex() == "eedb2631fdc3c6748dc567534e90eb016d087e6c088f3de6f815e854e6a78daf4181a01d80f26c1f9d2816f95e2427b8e261cc45dc2a98f96a81db2235b0f4d02c4a6b2ad94e3444dc921fc0ed378bca86a9eec7179c45be3f6b9809a4770012e7cd143872e45b7bf8f34e6819102d5a55f32a1f9d105a8b3dfe25af75d76f93"

    h_result = H(b"qjdhfyritoprlkdjfkrjfbdnzyhdjrtr")
    assert h_result.hex() == "af791f788a6048e5f16b9ee9ef12add7a3fcdf2d615f79960c588bdc9824178f"

    j_result = J(b"qjdhfyritoprlkdjfkrjfbdnzyhdjrtr")
    assert j_result.hex() == "1ffbe9a12ca007f5e869838bd0ba33284554800575b87b1023bbfe41a7332b7a"

    (g_a, g_b) = G(b"qjdhfyritoprlkdjfkrjfbdnzyhdjrtr")
    assert (g_a.hex(), g_b.hex()) == ("132f6750e8aafeee8cff75bafdf1cae43307ac23878d5403990b33664bdec268", "73fe4185b09c291388961a4420b40a44705538502490b755b27e88d723f85192")



    