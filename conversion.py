from constants import CONST_d, Q, N

""" 
Algorithm 3 : BitsToBytes(b)
Converts a bit array (of a length that is a multiple of eight) into an array of bytes.

Input : b in {0, 1}^(8*r)
Output : B in B^r
"""
def BitToBytes(b) -> bytes:
    if len(b) % 8 != 0:
        raise ValueError(f"Le tableau de bits n'a pas une longueur multiple de 8")
    
    l = len(b)
    B = [0] * (l // 8)
    for i in range(l):
        B[i//8] += b[i] * (2**(i % 8))
    return bytes(B)

""" 
Algorithm 4 : BytesToBits(B)
Performs the inverse of BitsToBytes, converting a byte array into a bit array

Input : B in B^r
Output : b in {0, 1}^(8*r)
"""
def BytesToBits(B: bytes):
    C = list(B)
    b = [0] * (8*len(C))
    for i in range(len(C)):
        for j in range(8):
            b[8*i + j] = C[i] % 2
            C[i] = C[i] // 2
    return b

""" 
Algorithm 5 : ByteEncode_d(F)
Encodes an array of d-bit integers into a byte array for 1 <= d <= 12

Input : integer array F in Z_m^N, where m = 2^d if d < 12, and m = Q if d = 12
Output : B in B^(32*d)
"""
def ByteEncode(F, d=CONST_d) -> bytes:
    b = [0] * (N * d)
    for i in range(N):
        a = F[i]
        for j in range(d):
            b[i*d + j] = a % 2
            a = (a - b[i*d + j]) // 2
    B = BitToBytes(b)
    return B

""" 
Algorithm 6 : ByteEncode_d(F)
Decodes a byte array into an array of d-bit integers for 1 <= d <= 12

Input : B in B^(32*d)
Output : integer array F in Z_m^N, where m = 2^d if d < 12, and m = Q if d = 12
"""
def ByteDecode(B: bytes, d=CONST_d, m=Q):
    if len(B) // 32 != d:
        raise ValueError(f"Mauvaise longueur")

    F = [0] * N
    b = BytesToBits(B)
    for i in range(N):
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



