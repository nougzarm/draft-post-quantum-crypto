from Crypto.Hash import SHAKE128
from hashlib import shake_256

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
    
def PRF(eta, s: bytes, b: bytes):
    if eta != 2 and eta != 3:
        raise ValueError(f"Mauvaise valeur pour eta")
    
    shake = shake_256(s + b)
    return shake.digest(8 * 64 * eta)

if __name__ == '__main__':
    prf_result = PRF(3, b"qjdhfyritoprlkdjfkrjfbdnzyhdjrtr", b"a")
    shake = shake_256()
    shake.update(b"qjdhfyritoprlkdjfkrjfbdnzyhdjrtr" + b"a")
    manual_res = shake.digest(8*64*3)
    assert prf_result == manual_res