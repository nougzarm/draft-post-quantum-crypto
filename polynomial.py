# Constantes globales pour les paramètres de Kyber
KYBER_N = 256
KYBER_Q = 3329

class Polynomial:
    """
    Représente un polynôme dans l'anneau R_q = Z_q[X] / (X^n + 1)
    pour les paramètres Kyber (n=256, q=3329).
    
    Les coefficients sont stockés sous forme de liste Python standard.
    """
    
    def __init__(self, coeffs=None):
        """
        Initialise le polynôme.
        Si 'coeffs' est None, initialise un polynôme nul.
        Sinon, utilise la liste de coefficients fournie.
        """
        self.n = KYBER_N
        self.q = KYBER_Q
        
        if coeffs is None:
            # Initialise un polynôme avec 256 coefficients nuls
            self.coeffs = [0] * self.n
        else:
            if len(coeffs) != self.n:
                raise ValueError(f"Le polynôme doit avoir exactement {self.n} coefficients, mais en a reçu {len(coeffs)}")
            # S'assure que tous les coefficients sont bien dans Z_q
            self.coeffs = [int(c) % self.q for c in coeffs]

    def __add__(self, other):
        """
        Surcharge l'opérateur d'addition (self + other).
        L'addition est effectuée coefficient par coefficient, modulo q.
        """
        if not isinstance(other, Polynomial):
            # Gère le cas où on essaie d'ajouter autre chose qu'un polynôme
            return NotImplemented
            
        new_coeffs = []
        for i in range(self.n):
            # Calcule (a_i + b_i) mod q
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
            # Calcule (a_i - b_i) mod q
            new_coeff = (self.coeffs[i] - other.coeffs[i]) % self.q
            new_coeffs.append(new_coeff)
            
        return Polynomial(new_coeffs)
    
    def __mul__(self, other):
        """
        Multiplication polynomiale standard (Convolution) : a(x) * b(x).
        Complexité O(n^2).
        
        C'est lent et n'est PAS utilisé pour les opérations principales de Kyber,
        mais c'est mathématiquement correct.
        
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
        """Représentation textuelle pour le débogage."""
        # Affiche les 3 premiers et le dernier coefficient pour la lisibilité
        coeffs_preview = ', '.join(map(str, self.coeffs[:3]))
        return f"Polynomial(coeffs=[{coeffs_preview}, ..., {self.coeffs[-1]}], n={self.n}, q={self.q})"

    def __getitem__(self, index):
        """Permet d'accéder à un coefficient (ex: poly[i])."""
        return self.coeffs[index]

    def __setitem__(self, index, value):
        """Permet de définir un coefficient (ex: poly[i] = v)."""
        self.coeffs[index] = int(value) % self.q

    def __len__(self):
        """Permet d'utiliser len(poly)."""
        return self.n

# --- Exemple d'utilisation ---
if __name__ == '__main__':
    # Crée un polynôme 'a' avec des 1 partout
    coeffs_a = [1] * KYBER_N
    a = Polynomial(coeffs_a)

    # Crée un polynôme 'b' avec des 2 partout
    coeffs_b = [2] * KYBER_N
    b = Polynomial(coeffs_b)

    # Addition
    c = a + b
    print(f"Addition (a + b): {c}") # Devrait avoir des 3
    print(f"Coefficient c[0]: {c[0]}") # Devrait être 3

    # Soustraction
    d = a - b
    print(f"Soustraction (a - b): {d}") # Devrait avoir des -1 (mod 3329)
    print(f"Coefficient d[0]: {d[0]}") # Devrait être 3328

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