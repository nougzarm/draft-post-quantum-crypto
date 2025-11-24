from constants import CONST_d, Q, N

def round_up(x):
    return int(x + 0.5)
    
"""
Compression and decompression functions
described on page 21 of the spec [FIPS 203]

Compress_d : Z_Q -> Z_(2**d)
Decompress_d : Z_(2**d) -> Z_Q
"""
def Compress(x: int, d: int):
    if d < 0 or d > 11:
        raise ValueError(f"Unauthorized value for d")
    
    d_pow = 2**d
    return round_up((d_pow/Q)*x) % d_pow

def Decompress(y: int, d: int):
    if d < 0 or d > 11:
        raise ValueError(f"Unauthorized value for d")
    
    return round_up((Q / (2**d)) * y)

""" 
Algorithm 3 : BitsToBytes(b)
Converts a bit array (of a length that is a multiple of eight) into an array of bytes.

Input : b in {0, 1}^(8*r)
Output : B in B^r
"""
def BitsToBytes(b) -> bytes:
    if len(b) % 8 != 0:
        raise ValueError(f"Bit array does not have length multiple of 8")
    
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
    b = [0] * (8 * len(C))
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
def ByteEncode(F: list, d: int = CONST_d) -> bytes:
    if d > 12 or d < 0 :
        raise ValueError(f"Unauthorized value for d")

    if len(F) != N:
        raise ValueError(f"Unauthorized length for F")
    
    b = [0] * (N * d)
    for i in range(N):
        a = F[i]
        for j in range(d):
            b[i*d + j] = a % 2
            a = (a - b[i*d + j]) // 2
    B = BitsToBytes(b)
    return B

""" 
Algorithm 6 : ByteEncode_d(F)
Decodes a byte array into an array of d-bit integers for 1 <= d <= 12

Input : B in B^(32*d)
Output : integer array F in Z_m^N, where m = 2^d if d < 12, and m = Q if d = 12
"""
def ByteDecode(B: bytes, d=CONST_d):
    if d > 12 or d < 0 :
        raise ValueError(f"Unauthorized value for d")

    if len(B) // 32 != d:
        raise ValueError(f"Unauthorized length")
    
    if d == CONST_d: m = Q
    else: m = 2**d

    F = [0] * N
    b = BytesToBits(B)
    for i in range(N):
        for j in range(d):
            F[i] = (F[i] + b[i*d + j] * (2**j)) % m
    return F

# --- Example of use and test ---
if __name__ == '__main__':
    assert Compress(1933, 11) == 1189
    assert Decompress(Compress(1933, 11), 11) == 1933
    assert Decompress(2001, 11) == 3253
    assert Compress(Decompress(2001, 11), 11) == 2001

    B = b"salut tous le monde. Comment allez vous"
    assert BitsToBytes(BytesToBits(B)) == B

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
    assert BytesToBits(BitsToBytes(b)) == b

    from polynomial import SampleNTT

    F = SampleNTT(b"Salut de la part de moi meme le ka").coeffs
    F_rev = ByteDecode(ByteEncode(F))
    assert F == F_rev