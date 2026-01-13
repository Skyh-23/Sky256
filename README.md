# Sky256

Sky256 is a custom 256-bit symmetric block cipher created for cryptographic research, education, and experimentation.  
It is designed to explore block cipher construction concepts such as substitution–permutation networks, diffusion layers, and key-dependent transformations, with a focus on transparency and code readability.

Sky256 is **not a standardized cryptographic primitive** and does not claim formal or peer-reviewed security.

---

## Purpose

Sky256 exists to:

- Explore block cipher design principles
- Study substitution, permutation, and diffusion layers
- Provide a large 256-bit block size for experimentation
- Serve as an educational and research artifact
- Enable transparent and auditable cipher code

---

## Scope

Sky256 is intended for:

- Cryptography education
- Cipher design experimentation
- Academic learning and discussion
- Integration testing inside higher-level encryption systems

Sky256 is **not intended** to replace standardized ciphers such as AES.

---

## Design Summary

- Block size: 256 bits  
- Key size: 256 bits  
- Rounds: 32  
- Structure: Substitution–Permutation network  
- Operations include:
  - Dual S-box substitution
  - Byte permutation
  - GF(2⁸) column mixing
  - Key-dependent rotations
  - Round key whitening

Sky256 provides **confidentiality only** and does not include authentication or integrity protection.

---

## Security Notes

- Sky256 has not undergone public cryptanalysis
- No formal security proofs are claimed
- Side-channel resistance is not guaranteed in software
- Correct security depends on proper system-level integration

Sky256 should not be used directly for real-world secure communication without an authenticated encryption framework.

---

## Relationship to Sky256X

Sky256 serves as the cryptographic core for **Sky256X**, which provides:

- Key derivation
- Authentication
- Replay protection
- Fail-closed behavior

Sky256X addresses system-level security concerns that Sky256 alone does not.

---

## Responsibility

This project is provided as-is.  
All usage decisions and associated risks are the responsibility of the user.

---

## License

MIT License
