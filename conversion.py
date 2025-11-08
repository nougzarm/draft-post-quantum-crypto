CONST_d = 12

def BitToBytes(b) -> bytes:
    if len(b) % 8 != 0:
        raise ValueError(f"Le tableau de bits n'a pas une longueur multiple de 8")
    
    l = len(b)
    B = [0] * (l // 8)
    for i in range(l):
        B[i//8] += b[i] * (2**(i % 8))
    return bytes(B)

def BytesToBits(B: bytes):
    C = list(B)
    b = [0] * (8*len(C))
    for i in range(len(C)):
        for j in range(8):
            b[8*i + j] = C[i] % 2
            C[i] = C[i] // 2
    return b

def ByteEncode(F, d=CONST_d) -> bytes:
    b = [0] * (256*d)
    for i in range(256):
        a = F[i]
        for j in range(d):
            b[i*d + j] = a % 2
            a = (a - b[i*d + j]) // 2
    B = BitToBytes(b)
    return B

def ByteDecode(B: bytes, d=CONST_d, m=3329):
    if len(B) // 32 != d:
        raise ValueError(f"Mauvaise longueur")

    F = [0] * 256
    b = BytesToBits(B)
    for i in range(256):
        for j in range(d):
            F[i] = (F[i] + b[i*d + j] * (2**j)) % m
    return F

if __name__ == '__main__':
    B = b"salut tous le monde. Comment allez vous"
    assert BitToBytes(BytesToBits(B)) == B
    print("test réussi")

    b = [1, 1, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0,
        0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 
        1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 
        1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 
        0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 0, 0, 
        0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 
        1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 
        0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 
        1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0, 
        1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0]
    assert BytesToBits(BitToBytes(b)) == b
    print("test réussi")

