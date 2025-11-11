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
    prf_result = PRF(3, b"qjdhfyritoprlkdjfkrjfbdnzyhdjrtr", b"a")
    shake = shake_256()
    shake.update(b"qjdhfyritoprlkdjfkrjfbdnzyhdjrtr" + b"a")
    manual_res = shake.digest(8*64*3)
    assert prf_result == manual_res