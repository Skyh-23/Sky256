# Sky256  
## A Custom 256-bit Block Cipher for Cryptographic Research and Education

---

## Abstract

Sky256 is a custom-designed 256-bit symmetric block cipher created for cryptographic research, learning, and experimentation.  
It explores modern block cipher construction concepts such as substitution–permutation networks, key-dependent transformations, and high-round diffusion, while intentionally avoiding claims of formal or standardized security guarantees.

Sky256 is **not positioned as a replacement for standardized cryptographic primitives**, but as a transparent and auditable cipher design intended to study block cipher structure, design trade-offs, and system-level integration behavior.

---

## 1. Design Goals

Sky256 was designed with the following goals:

- Explore block cipher construction principles  
- Provide a large block size (256-bit) for structural experimentation  
- Demonstrate substitution, permutation, and diffusion layers  
- Enable code-level transparency and readability  
- Support educational and cryptographic research use cases  

### Non-goals

Sky256 explicitly does **not** aim to:

- Claim provable or peer-reviewed cryptographic security  
- Replace standardized ciphers such as AES  
- Guarantee resistance against all known cryptanalytic attacks  
- Provide side-channel resistance in software implementations  

---

## 2. Cipher Overview

Sky256 is a symmetric block cipher operating on fixed-size blocks with a fixed-size key.

**Core parameters:**

- Block size: 256 bits  
- Key size: 256 bits  
- Number of rounds: 32  

The cipher follows a substitution–permutation design inspired by modern block ciphers, with additional key-dependent transformations to explore diffusion behavior.

---

## 3. Round Structure

Each encryption round applies the following operations:

- Dual S-box substitution  
- Byte-level permutation  
- Column mixing over GF(2⁸)  
- Key-dependent rotations  
- Round key whitening  

These operations are applied iteratively across multiple rounds to increase diffusion and non-linearity.

Sky256 is designed as a **confidentiality primitive only** and does not provide authentication or integrity protection on its own.

---

## 4. Key Schedule

Sky256 derives round keys from the master key using deterministic expansion and permutation mechanisms.

Design intent:

- Ensure each round uses a distinct subkey  
- Introduce key-dependent variation across rounds  
- Avoid simple repetition or linear key reuse  

No formal claims are made regarding resistance to related-key or advanced cryptanalytic attacks.

---

## 5. Encryption and Decryption

Sky256 supports reversible encryption and decryption through inverse round transformations.

- Encryption applies forward round operations  
- Decryption applies inverse substitution, permutation, and mixing  

Correct decryption is guaranteed only when the correct key is provided.

---

## 6. Security Considerations

Sky256 does **not** claim cryptographic strength equivalent to standardized ciphers.

Important considerations:

- No public cryptanalysis has been performed  
- The design has not undergone academic peer review  
- Side-channel resistance is not guaranteed in Python implementations  
- Security depends on correct system-level integration  

Sky256 should never be used directly without an authenticated encryption framework.

---

## 7. Intended Use Cases

Sky256 is intended for:

- Cryptography education  
- Cipher design experimentation  
- Academic discussion and learning  
- Integration testing within higher-level encryption systems  
- Studying block cipher internals  

---

## 8. Not Recommended Use Cases

Sky256 is **not recommended** for:

- High-risk or public-facing production systems  
- Environments requiring standardized or certified cryptography  
- Scenarios involving strong side-channel adversaries  
- Compliance-driven security deployments  

---

## 9. Relationship to Sky256X

Sky256 serves as the cryptographic core for **Sky256X**, which provides:

- Key derivation  
- Authentication  
- Replay protection  
- Fail-closed behavior  

Sky256X addresses many system-level risks that Sky256 alone does not.

---

## 10. Security Claims (Precise)

Sky256 claims:

- Correct reversible encryption under the same key  
- Demonstration of modern block cipher construction concepts  

Sky256 does **not** claim:

- Formal security proofs  
- Resistance to advanced cryptanalysis  
- Suitability as a standalone secure encryption system  

---

## 11. Conclusion

Sky256 demonstrates how a custom block cipher can be structured using modern cryptographic concepts while maintaining transparency and educational value.

It should be viewed as a **research and learning artifact**, not as a production security primitive.

---

## License & Disclaimer

This project is provided for educational and experimental purposes only.  
No warranty of fitness for any particular purpose is implied.  
Any use of this cipher is entirely the responsibility of the user.
