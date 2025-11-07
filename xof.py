from Crypto.Hash import SHAKE128

class XOF:
    def __init__(self):
        self._shake = SHAKE128.new()

    def Absorb(self, data: bytes):
        self._shake.update(data)

    def Squeeze(self, length: int) -> bytes:
        return self._shake.read(length)
