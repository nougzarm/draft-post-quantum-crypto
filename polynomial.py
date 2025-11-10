from constants import N, Q, ZETAS
from xof import XOF
from conversion import *
from utils import MultiplyNTTs

def add_lists(a: list, b: list):
    if len(a) != len(b):
        raise ValueError(f"Listes de longueurs différentes")
    
    new_list = []
    for i in range(len(a)):
        new_list.append((a[i] + b[i]) % Q)
    return new_list

def sub_lists(a: list, b: list):
    if len(a) != len(b):
        raise ValueError(f"Listes de longueurs différentes")
    
    new_list = []
    for i in range(len(a)):
        new_list.append((a[i] - b[i]) % Q)
    return new_list

class Polynomial:
    """
    Représente un polynôme dans l'anneau R_Q = Z_Q[X] / (X^N + 1)
    """
    
    def __init__(self, coeffs=None):
        if coeffs is None:
            self.coeffs = [0] * N
        else:
            if len(coeffs) != N:
                raise ValueError(f"Le polynôme doit avoir exactement {N} coefficients, mais en a reçu {len(coeffs)}")
            self.coeffs = [int(c) % Q for c in coeffs]

    def __add__(self, other):
        if not isinstance(other, Polynomial):
            return NotImplemented
            
        return Polynomial(add_lists(self.coeffs, other.coeffs))

    def __sub__(self, other):
        if not isinstance(other, Polynomial):
            return NotImplemented
            
        return Polynomial(sub_lists(self.coeffs, other.coeffs))
    
    def __mul__(self, other):
        if not isinstance(other, Polynomial):
            return NotImplemented
            
        new_coeffs = [0] * N
        for i in range(N):
            for j in range(N):
                product = (self.coeffs[i] * other.coeffs[j])
                
                k = i + j
                if k < N:
                    new_coeffs[k] = (new_coeffs[k] + product) % Q
                else:
                    k_prime = k - N
                    new_coeffs[k_prime] = (new_coeffs[k_prime] - product) % Q
 
        return Polynomial(new_coeffs)
    
    def __eq__(self, other):
        """
        Surcharge l'opérateur ==.
        La vérification se fait en TEMPS CONSTANT
        """
        if not isinstance(other, Polynomial):
            return NotImplemented
        
        result = True
        for i in range(N):
            if self.coeffs[i] != other.coeffs[i]:
                result = False

        return result

    # --- Méthodes utilitaires pour un usage facile ---
    def __repr__(self):
        """
        Affiche le polynôme sous une forme mathématique lisible.
        ex: 8X^2 + 10X + 3
        """
        terms = []
        for i in range(N - 1, -1, -1):
            c = self.coeffs[i]
            
            if c == 0:
                continue
            
            term_str = ""
            
            if c != 1 or i == 0:
                term_str += str(c)
                
            if i > 0: # Terme non constant
                if c != 1:
                    term_str += "*"
                     
                term_str += "X" # Ajoute 'X'
                if i > 1:
                    term_str += f"^{i}" # Ajoute la puissance
            
            terms.append(term_str)
        
        if not terms:
            return "0"
            
        return " + ".join(terms)

    def __getitem__(self, index):
        """Permet d'accéder à un coefficient (ex: poly[i])."""
        return self.coeffs[index]

    def __setitem__(self, index, value):
        """Permet de définir un coefficient (ex: poly[i] = v)."""
        self.coeffs[index] = int(value) % Q
    
class PolynomialNTT:
    """
    Représente un polynôme dans l'anneau T_Q : somme direct des Z_Q[X] / (X^2 - ZETA**(2*BitRev(i) + 1))
    """
    def __init__(self, coeffs=None):
        if coeffs is None:
            self.coeffs = [0] * N
        else:
            if len(coeffs) != N:
                raise ValueError(f"Le polynôme doit avoir exactement {N} coefficients, mais en a reçu {len(coeffs)}")
            self.coeffs = [int(c) % Q for c in coeffs]

    def __add__(self, other):
        if not isinstance(other, PolynomialNTT):
            return NotImplemented
            
        return PolynomialNTT(add_lists(self.coeffs, other.coeffs))

    def __sub__(self, other):
        if not isinstance(other, PolynomialNTT):
            return NotImplemented
            
        return PolynomialNTT(sub_lists(self.coeffs, other.coeffs))

    def __mul__(self, other):
        if not isinstance(other, PolynomialNTT):
            return NotImplemented
        
        product_list = MultiplyNTTs(self.coeffs, other.coeffs)
        return PolynomialNTT(product_list)

""" 
Correspond à l'algorithme 7 de la spec 
"""
def SampleNTT(B: bytes) -> PolynomialNTT:
    if len(B) != 34:
        raise ValueError(f"Mauvaise taille pour B")
    
    a = [0] * 256
    ctx = XOF.Init()
    ctx.Absorb(B)
    j = 0
    while j < 256:
        C = ctx.Squeeze(3)
        d1 = C[0] + 256*(C[1] % 16)
        d2 = (C[1] // 16) + 16*C[2]
        if d1 < Q:
            a[j] = d1
            j += 1
        if d2 < Q and j < 256:
            a[j] = d2
            j += 1
    return PolynomialNTT(a)

""" 
Correspond à l'algorithme 8 de la spec 
"""
def SamplePolyCBD(B: bytes, eta=3) -> Polynomial:
    if len(B) != 64*eta:
        raise ValueError(f"Mauvaise taille pour B")
    
    b = BytesToBits(B)
    f = [0] * 256
    for i in range(256):
        x = 0
        for j in range(eta):
            x += b[2*i*eta + j]
        y = 0
        for j in range(eta):
            y += b[2*i*eta + eta + j]
        f[i] = (x - y) % Q
    return Polynomial(f)

""" 
Correspond à l'algorithme 9 de la spec 
"""
def NTT(f: Polynomial) -> PolynomialNTT:
    C = f.coeffs.copy()
    i = 1
    len = 128
    while len > 1:
        for start in range(0, 256, 2 * len):
            zeta = ZETAS[i]
            i += 1
            for j in range(start, start + len, 1):
                t = (zeta * C[j + len]) % Q
                C[j + len] = (C[j] - t) % Q
                C[j] = (C[j] + t) % Q
        len = len // 2
    return PolynomialNTT(C)

""" 
Correspond à l'algorithme 10 de la spec 
"""
def inverse_NTT(f_ntt: PolynomialNTT) -> Polynomial:
    C = f_ntt.coeffs.copy()
    i = 127
    len = 2 
    while len <= 128:
        for start in range(0, 256, 2 * len):
            zeta = ZETAS[i]
            i -= 1
            for j in range(start, start + len, 1):
                t = C[j]
                C[j] = (t + C[j + len]) % Q
                C[j + len] = (zeta * (C[j + len] - t)) % Q
        len = len * 2

    for i in range(256):
        C[i] = (C[i] * 3303) % Q

    return Polynomial(C)

# --- Exemple d'utilisation et tests ---
if __name__ == '__main__':
    a = Polynomial([1, 0, 2, 3] + [0] * (N - 4))
    assert inverse_NTT(NTT(a)) == a
    print(a)

    b = Polynomial([1, 0, 2, 3, 7, 9] + [0] * (N - 6))
    print(b)

    c = a + b
    print(c) 
    print(f"Coefficient c[0]: {c[0]}") 

    d = a - b
    print(f"Soustraction (a - b): {d}")
    print(f"Coefficient d[0]: {d[0]}")

    p1 = Polynomial([1, 2, 4, 4, 3, 1, 6, 6, 4, 3] + [0]*246)
    p2 = Polynomial([3, 4, 8, 10, 27, 273, 12, 982, 12, 42, 9] + [0]*245)
    assert inverse_NTT(NTT(p1) * NTT(p2)) == p1 * p2
    # print(f"Produit p1 * p2 = {p1 * p2}") # Affiche le produit