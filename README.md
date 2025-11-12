# Educational Implementation of Kyber (FIPS 203 / ML-KEM) in Python

This project is a pure Python implementation of **Kyber**, the lattice-based Key Encapsulation Mechanism (KEM) algorithm selected by NIST for post-quantum standardization (now published as **FIPS 203**: **ML-KEM**).

## ⚠️ Fundamental Security Warning

This implementation is developed **FOR EDUCATIONAL AND RESEARCH PURPOSES ONLY**.

## Features

This project provides a complete, from-scratch implementation of the ML-KEM standard, including:
- **Full KEM Scheme (IND-CCA2):** Implements `ML-KEM.KeyGen`, `ML-KEM.Encaps`, and `ML-KEM.Decaps`.
- **Underlying PKE Scheme (IND-CPA):** Implements `K-PKE.KeyGen`, `K-PKE.Encrypt`, and `K-PKE.Decrypt`.
- **Polynomial Arithmetic:** Provides a Polynomial class for all operations in the ring $R_Q = \mathbb{Z}_Q[X] / (X^N + 1)$.
- **Number Theoretic Transform (NTT):** Includes correct implementations of `NTT` and `inverse_NTT` (Algorithms 9 & 10) for fast polynomial multiplication, with a corresponding `PolynomialNTT` class.
- **Cryptographic Primitives:** Implements all required hash functions (`XOF`, `PRF`, `H`, `J`, `G`) as specified by FIPS 203, using `pycryptodome` and `hashlib`.
- **Conversion & Sampling:** Correctly implements `SampleNTT`, `SamplePolyCBD`, `Compress`/`Decompress`, and `ByteEncode`/`ByteDecode`.
- **Parameter Support:** A full `unittest` suite validates all three official parameter sets: **ML-KEM-512**, **768**, and **1024**.

## Project Structure

The code is structured modularly to mirror the FIPS 203 specification:
- `constants.py`: Defines core constants like `N`, `Q`, and the pre-computed `ZETAS` twiddle factors.
- `hash.py`: Wrappers for all cryptographic hash functions (SHAKE-128, SHAKE-256, SHA3-256, SHA3-512).
- `conversion.py`: Handles all serialization (`ByteEncode`/`ByteDecode`), bit-packing (`BitToBytes`/`BytesToBits`), and `Compress`/`Decompress` functions.
- `polynomial.py`: The core of the project. Implements the `Polynomial` and `PolynomialNTT` classes, all polynomial arithmetic, `NTT`/`inverse_NTT`, and sampling functions (`SampleNTT`, `SamplePolyCBD`).
- `utils.py`: Contains helper functions for the NTT, such as `BaseCaseMultiply` (Algorithm 12).
- `pke_scheme.py`: Implements the `K_PKE` class, representing the IND-CPA secure public-key encryption scheme (Algorithms 13-15).
- `kem_scheme.py`: Implements the final `ML_KEM` class, building the IND-CCA2 secure Key Encapsulation Mechanism on top of `K_PKE` (Algorithms 16-21).
- `test_ml_kem.py`: A `unittest` file that runs a full KeyGen, Encapsulation, and Decapsulation cycle for all three parameter sets to verify correctness.

## How to Use 

The project is set up for testing using Python's built-in `unittest` module.

1. Ensure you have the required dependencies (primarily `pycryptodome` for the hash functions):

```bash
pip install pycryptodome
```

2. Run the main test file from your terminal:

```bash
python test_ml_kem.py
```

3. This will execute the full KEM cycle for ML-KEM-512, 768, and 1024, printing the status and verifying that the encapsulated and decapsulated keys match.