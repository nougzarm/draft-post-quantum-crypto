import unittest
from kem_scheme import ML_KEM

class TestMLKEM(unittest.TestCase):
    def setUp(self):
        """
        Initializes ML_KEM instances for each parameter set
        """
        self.params_512 = {"k": 2, "eta_1": 3, "eta_2": 2, "d_u": 10, "d_v": 4}
        self.kyber_512 = ML_KEM(**self.params_512)

        self.params_768 = {"k": 3, "eta_1": 2, "eta_2": 2, "d_u": 10, "d_v": 4}
        self.kyber_768 = ML_KEM(**self.params_768)

        self.params_1024 = {"k": 4, "eta_1": 2, "eta_2": 2, "d_u": 11, "d_v": 5}
        self.kyber_1024 = ML_KEM(**self.params_1024)

    def _run_kem_test(self, kem_instance: ML_KEM, test_name: str):
        """
        Help function to run a complete KEM cycle (KeyGen, Encaps, Decaps)
        """
        print(f"\n--- Running the test : {test_name} ---")
        
        # 1. KeyGen
        ek, dk = kem_instance.KeyGen()
        print(f"  Generated keys (ek: {len(ek)} bytes, dk: {len(dk)} bytes)")

        # 2. Encapsulation
        K_encaps, c = kem_instance.Encaps(ek)
        print(f"  Encapsulated key (K) : {K_encaps.hex()}")
        print(f"  Ciphertext generated (c) : {len(c)} bytes")

        # 3. Décapsulation
        K_decaps = kem_instance.Decaps(dk, c)
        print(f"  Decapsulated key (K') : {K_decaps.hex()}")

        # 4. Vérification
        self.assertEqual(K_encaps, K_decaps, f"TEST {test_name} FAILED: Keys do not match !")
        print(f"  ✅ SUCCESS : {test_name}")

    def test_ml_kem_512(self):
        """ Tests ML-KEM-512 """
        self._run_kem_test(self.kyber_512, "ML-KEM-512")

    def test_ml_kem_768(self):
        """ Tests ML-KEM-768 """
        self._run_kem_test(self.kyber_768, "ML-KEM-768")

    def test_ml_kem_1024(self):
        """ Tests ML-KEM-1024 """
        self._run_kem_test(self.kyber_1024, "ML-KEM-1024")

if __name__ == '__main__':
    unittest.main()