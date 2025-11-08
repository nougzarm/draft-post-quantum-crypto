from constants import CONST_N, CONST_Q
from xof import XOF

class Polynomial:
    """
    Représente un polynôme dans l'anneau R_q = Z_q[X] / (X^n + 1)
    pour les paramètres Kyber (n=256, q=3329).
    """
    
    def __init__(self, coeffs=None):
        """
        Initialise le polynôme.
        Si 'coeffs' est None, initialise un polynôme nul.
        Sinon, utilise la liste de coefficients fournie.
        """
        self.n = CONST_N
        self.q = CONST_Q
        
        if coeffs is None:
            # Polynome nul
            self.coeffs = [0] * self.n
        else:
            if len(coeffs) != self.n:
                raise ValueError(f"Le polynôme doit avoir exactement {self.n} coefficients, mais en a reçu {len(coeffs)}")
            self.coeffs = [int(c) % self.q for c in coeffs]

    def __add__(self, other):
        """
        Surcharge l'opérateur d'addition (self + other).
        L'addition est effectuée coefficient par coefficient, modulo q.
        """
        if not isinstance(other, Polynomial):
            return NotImplemented
            
        new_coeffs = []
        for i in range(self.n):
            new_coeff = (self.coeffs[i] + other.coeffs[i]) % self.q
            new_coeffs.append(new_coeff)
            
        return Polynomial(new_coeffs)

    def __sub__(self, other):
        """
        Surcharge l'opérateur de soustraction (self - other).
        La soustraction est effectuée coefficient par coefficient, modulo q.
        """
        if not isinstance(other, Polynomial):
            return NotImplemented
            
        new_coeffs = []
        for i in range(self.n):
            new_coeff = (self.coeffs[i] - other.coeffs[i]) % self.q
            new_coeffs.append(new_coeff)
            
        return Polynomial(new_coeffs)
    
    def __mul__(self, other):
        """
        Multiplication polynomiale standard (Convolution) : a(x) * b(x).
        Complexité O(n^2).
        
        Prend en compte la réduction X^n = -1.
        """
        if not isinstance(other, Polynomial):
            return NotImplemented
            
        new_coeffs = [0] * self.n
        
        for i in range(self.n):
            for j in range(self.n):
                # Calcule le produit de a[i] * b[j]
                product = (self.coeffs[i] * other.coeffs[j])
                
                # Calcule le nouvel index k = i + j
                k = i + j
                
                if k < self.n:
                    # Si k < n, on ajoute simplement à c[k]
                    # c[k] = (c[k] + a[i]*b[j]) % q
                    new_coeffs[k] = (new_coeffs[k] + product) % self.q
                else:
                    # Si k >= n, on utilise X^n = -1.
                    # X^k = X^(n + (k-n)) = X^n * X^(k-n) = -1 * X^(k-n)
                    # On doit donc *soustraire* le produit de c[k-n]
                    k_prime = k - self.n
                    # c[k_prime] = (c[k_prime] - a[i]*b[j]) % q
                    new_coeffs[k_prime] = (new_coeffs[k_prime] - product) % self.q
                    
        return Polynomial(new_coeffs)

    def pointwise_multiply(self, other):
        """
        Multiplication "pointwise" (Hadamard) : c[i] = a[i] * b[i].
        Complexité O(n).
        
        C'est l'opération utilisée DANS LE DOMAINE NTT.
        """
        if not isinstance(other, Polynomial):
            raise TypeError("Ne peut multiplier qu'avec un autre Polynomial")
            
        new_coeffs = []
        for i in range(self.n):
            new_coeff = (self.coeffs[i] * other.coeffs[i]) % self.q
            new_coeffs.append(new_coeff)
            
        return Polynomial(new_coeffs)

    # --- Méthodes utilitaires pour un usage facile ---

    def __repr__(self):
        """
        Affiche le polynôme sous une forme mathématique lisible.
        ex: 8X^2 + 10X + 3
        """
        terms = []
        for i in range(self.n - 1, -1, -1):
            c = self.coeffs[i]
            
            if c == 0:
                continue
            
            term_str = ""
            
            if c != 1 or i == 0:
                term_str += str(c)
                
            # --- Gère la variable X et la puissance ---
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
        self.coeffs[index] = int(value) % self.q

    def __len__(self):
        """Permet d'utiliser len(poly)."""
        return self.n
    
class PolynomialNNT:
    """
    Représente un polynôme dans l'anneau T_q = [...]
    pour les paramètres Kyber (n=256, q=3329).
    """
    
    def __init__(self, coeffs=None):
        self.n = CONST_N
        self.q = CONST_Q
        
        if coeffs is None:
            # Polynome nul
            self.coeffs = [0] * self.n
        else:
            if len(coeffs) != self.n:
                raise ValueError(f"Le polynôme doit avoir exactement {self.n} coefficients, mais en a reçu {len(coeffs)}")
            self.coeffs = [int(c) % self.q for c in coeffs]

""" 
Correspond à l'algorithme 7 de la spec 
"""
def SampleNNT(B: bytes) -> PolynomialNNT:
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
        if d1 < CONST_Q:
            a[j] = d1
            j += 1
        if d2 < CONST_Q and j < 256:
            a[j] = d2
            j += 1
    return PolynomialNNT(a)
            


# --- Exemple d'utilisation ---
if __name__ == '__main__':
    # Crée un polynôme 'a'
    coeffs_a = [1, 0, 2, 3] + [0] * (CONST_N - 4)
    a = Polynomial(coeffs_a)

    # Crée un polynôme 'b'
    coeffs_b = [1, 0, 2, 3, 7, 9] + [0] * (CONST_N - 6)
    b = Polynomial(coeffs_b)

    # Addition
    c = a + b
    print(f"Addition (a + b): {c}") 
    print(f"Coefficient c[0]: {c[0]}") 

    # Soustraction
    d = a - b
    print(f"Soustraction (a - b): {d}")
    print(f"Coefficient d[0]: {d[0]}")

    # Création d'un polynôme nul
    z = Polynomial()
    print(f"Polynôme nul: {z}")

    p1 = Polynomial([1, 2] + [0]*254) # p1 = 1 + 2X
    p2 = Polynomial([3, 4] + [0]*254) # p2 = 3 + 4X

    # 1. Multiplication Pointwise (facile)
    p_pointwise = p1.pointwise_multiply(p2)
    # Attendu: [1*3, 2*4, 0*0, ...] = [3, 8, 0, ...]
    print(f"Pointwise: {p_pointwise}")

    # 2. Multiplication Standard (compliquée)
    # (1 + 2X) * (3 + 4X) = 1*3 + 1*4X + 2X*3 + 2X*4X
    # = 3 + 4X + 6X + 8X^2
    # = 3 + 10X + 8X^2
    p_standard = p1 * p2 
    print(f"Standard : {p_standard}") # Attendu: [3, 10, 8, 0, ...]
    
    # Exemple avec réduction X^n = -1
    # (supposons n=4 pour l'exemple)
    # (X^2) * (X^3) = X^5 = X^(4+1) = X^4 * X^1 = -1 * X^1 = -X
    # (Testez ceci en changeant KYBER_N=4 temporairement)