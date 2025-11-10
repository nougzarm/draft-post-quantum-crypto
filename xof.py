from Crypto.Hash import SHAKE128
from hashlib import shake_256, sha3_256, sha3_512

""" 
La classe XOF est un wrapper pour l'éponge SHAKE128.
Cette définition est décrite dans pages 19 et 20 de la spec
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
Correspond à la définition dans (4.2) et (4.3)
"""
def PRF(eta, s: bytes, b: bytes):
    if eta != 2 and eta != 3:
        raise ValueError(f"Mauvaise valeur pour eta")
    
    shake = shake_256(s + b)
    return shake.digest(64 * eta)

""" 
Correspond aux définitions dans (4.4)
"""
def H(s: bytes) -> bytes:
    hash_obj = sha3_256(s)
    return hash_obj.digest()

def J(s: bytes) -> bytes:
    shake = shake_256(s)
    return shake.digest(8 * 32)

""" 
Correspond à la définition dans (4.5)
"""
def G(c: bytes):
    hash_obj = sha3_512(c)
    result = hash_obj.digest()
    a = result[:32]
    b = result[32:]
    return a, b


""" 
Ensemble de tests des implémentations
"""
if __name__ == '__main__':
    prf_result = PRF(3, b"qjdhfyritoprlkdjfkrjfbdnzyhdjrtr", b"a")
    shake = shake_256()
    shake.update(b"qjdhfyritoprlkdjfkrjfbdnzyhdjrtr" + b"a")
    manual_res = shake.digest(8*64*3)
    assert prf_result == manual_res