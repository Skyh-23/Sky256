import os
import struct
import hmac
import hashlib
import time as _time
from typing import List, Tuple
from collections import OrderedDict


class BoundedNonceCache:
    def __init__(self, max_size: int = 10000, ttl_seconds: int = 600):
        self._cache = OrderedDict()
        self._max_size = max_size
        self._ttl = ttl_seconds
    
    def _prune_expired(self):
        current = int(_time.time())
        expired = [k for k, v in self._cache.items() if current - v > self._ttl]
        for k in expired:
            del self._cache[k]
    
    def add(self, nonce_id: bytes) -> bool:
        self._prune_expired()
        if nonce_id in self._cache:
            return False
        if len(self._cache) >= self._max_size:
            self._cache.popitem(last=False)
        self._cache[nonce_id] = int(_time.time())
        return True
    
    def contains(self, nonce_id: bytes) -> bool:
        self._prune_expired()
        return nonce_id in self._cache


class KDFMode:
    PBKDF2 = "PBKDF2"
    ARGON2ID = "ARGON2ID"


def _derive_key_pbkdf2(password: str, salt: bytes, iterations: int = 600_000) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations, dklen=32)


def _derive_key_argon2id(password: str, salt: bytes, time_cost: int = 3, memory_cost: int = 65536, parallelism: int = 4) -> bytes:
    try:
        from argon2.low_level import hash_secret_raw, Type
        return hash_secret_raw(
            secret=password.encode('utf-8'),
            salt=salt,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=32,
            type=Type.ID
        )
    except ImportError:
        raise RuntimeError("Argon2 not available. Install 'argon2-cffi' package or use PBKDF2.")


def secure_random_bytes(length: int) -> bytes:
    if length < 0:
        raise ValueError("Length must be non-negative")
    return os.urandom(length)


def constant_time_bytes_eq(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0


def secure_zero_memory(data: bytearray) -> None:
    if not isinstance(data, bytearray):
        return
    for i in range(len(data)):
        data[i] = 0


def validate_timestamp(timestamp: int, max_age_seconds: int = 300, max_future_seconds: int = 60) -> bool:
    current_time = int(_time.time())
    age = current_time - timestamp
    if age > max_age_seconds:
        return False
    if age < -max_future_seconds:
        return False
    return True


def derive_master_key(password: str, salt: bytes = None, iterations: int = 600_000, kdf_mode: str = KDFMode.PBKDF2) -> tuple:
    if salt is None:
        salt = secure_random_bytes(32)
    elif len(salt) != 32:
        raise ValueError("Salt must be exactly 32 bytes")
    
    if kdf_mode == KDFMode.ARGON2ID:
        master_key = _derive_key_argon2id(password, salt)
    else:
        master_key = _derive_key_pbkdf2(password, salt, iterations)
    
    return salt, master_key


def derive_subkeys(master_key: bytes, salt: bytes) -> dict:
    def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
        t = b""
        okm = b""
        i = 0
        while len(okm) < length:
            i += 1
            t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
            okm += t
        return okm[:length]
    
    prk = hmac.new(salt, master_key, hashlib.sha256).digest()
    
    return {
        'K_sky256x_enc': hkdf_expand(prk, b"CipherSuite-v1-Sky256X-ENC", 32),
        'K_sky256x_mac': hkdf_expand(prk, b"CipherSuite-v1-Sky256X-MAC", 32),
        'K_aesgcm_enc': hkdf_expand(prk, b"CipherSuite-v1-AES256GCM-ENC", 32),
        'K_metadata': hkdf_expand(prk, b"CipherSuite-v1-METADATA", 32),
        'K_future': hkdf_expand(prk, b"CipherSuite-v1-FUTURE-RESERVED", 32),
    }


def _compute_aad(version: int, timestamp_bytes: bytes, salt: bytes) -> bytes:
    salt_hash = hashlib.sha256(salt).digest()[:8]
    return bytes([version]) + timestamp_bytes + salt_hash


class Sky256:
    BLOCK_SIZE = 32
    KEY_SIZE = 32
    ROUNDS = 32
    
    SBOX1 = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    ]
    
    SBOX2 = [
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    ]
    
    INV_SBOX1 = [0] * 256
    INV_SBOX2 = [0] * 256
    
    @classmethod
    def _init_inverse_sboxes(cls):
        for i in range(256):
            cls.INV_SBOX1[cls.SBOX1[i]] = i
            cls.INV_SBOX2[cls.SBOX2[i]] = i
    
    def __init__(self, key: bytes):
        if len(key) != self.KEY_SIZE:
            raise ValueError(f"Key must be exactly {self.KEY_SIZE} bytes")
        self.key = key
        self.round_keys = self._key_schedule(key)
        if not self.INV_SBOX1[0]:
            self._init_inverse_sboxes()
    
    def _key_schedule(self, key: bytes) -> List[bytes]:
        round_keys = []
        state = bytearray(key)
        
        for r in range(self.ROUNDS + 1):
            round_keys.append(bytes(state))
            temp = bytearray(32)
            for i in range(32):
                t1 = self.SBOX1[state[i]]
                t2 = self.SBOX2[state[(i + 7) % 32]]
                t3 = state[(i + 13) % 32]
                t4 = state[(i + 19) % 32]
                mix = (t1 ^ t2) + (t3 ^ t4)
                mix = (mix * 251) % 256
                mix ^= (r + 1) & 0xFF
                rot_val = state[(i + 23) % 32]
                mix = ((mix << (rot_val % 5)) | (mix >> (8 - (rot_val % 5)))) & 0xFF
                temp[i] = mix
            state = temp
        
        return round_keys
    
    def _substitute(self, block: bytearray, inverse: bool = False) -> None:
        for i in range(32):
            if not inverse:
                block[i] = self.SBOX1[block[i]] if i % 2 == 0 else self.SBOX2[block[i]]
            else:
                block[i] = self.INV_SBOX1[block[i]] if i % 2 == 0 else self.INV_SBOX2[block[i]]
    
    @staticmethod
    def _mod_inverse(a, m):
        def extended_gcd(a, b):
            if a == 0:
                return b, 0, 1
            gcd, x1, y1 = extended_gcd(b % a, a)
            x = y1 - (b // a) * x1
            y = x1
            return gcd, x, y
        
        gcd, x, _ = extended_gcd(a % m, m)
        if gcd != 1:
            return None
        return (x % m + m) % m
    
    def _permute_bits(self, block: bytearray, inverse: bool = False) -> None:
        if not hasattr(self, '_perm_table') or not hasattr(self, '_perm_table_inv'):
            perm = list(range(32))
            for i in range(32):
                key_byte = self.key[i]
                new_pos = (i + key_byte) % 32
                perm[i], perm[new_pos] = perm[new_pos], perm[i]
            
            self._perm_table = perm
            self._perm_table_inv = [0] * 32
            for i in range(32):
                self._perm_table_inv[perm[i]] = i
        
        temp = bytearray(32)
        if not inverse:
            for i in range(32):
                temp[self._perm_table[i]] = block[i]
        else:
            for i in range(32):
                temp[self._perm_table_inv[i]] = block[i]
        block[:] = temp
    
    def _mix_columns(self, block: bytearray, inverse: bool = False) -> None:
        temp = bytearray(32)
        
        if not inverse:
            for col in range(4):
                offset = col * 8
                for i in range(8):
                    idx = offset + i
                    t = self._gmul(block[offset + i], 0x02)
                    t ^= self._gmul(block[offset + (i + 1) % 8], 0x03)
                    t ^= block[offset + (i + 2) % 8]
                    t ^= block[offset + (i + 3) % 8]
                    t ^= self._gmul(block[offset + (i + 4) % 8], 0x02)
                    t ^= self._gmul(block[offset + (i + 5) % 8], 0x03)
                    t ^= block[offset + (i + 6) % 8]
                    t ^= block[offset + (i + 7) % 8]
                    temp[idx] = t
        else:
            for col in range(4):
                offset = col * 8
                for i in range(8):
                    idx = offset + i
                    t = self._gmul(block[offset + i], 0x0e)
                    t ^= self._gmul(block[offset + (i + 1) % 8], 0x0b)
                    t ^= self._gmul(block[offset + (i + 2) % 8], 0x0d)
                    t ^= self._gmul(block[offset + (i + 3) % 8], 0x09)
                    t ^= self._gmul(block[offset + (i + 4) % 8], 0x36)
                    t ^= self._gmul(block[offset + (i + 5) % 8], 0x36)
                    t ^= self._gmul(block[offset + (i + 6) % 8], 0xe3)
                    t ^= self._gmul(block[offset + (i + 7) % 8], 0x8c)
                    temp[idx] = t
        
        block[:] = temp
    
    def _gmul(self, a: int, b: int) -> int:
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            hi_bit = a & 0x80
            a = (a << 1) & 0xFF
            if hi_bit:
                a ^= 0x1B
            b >>= 1
        return p
    
    def _add_round_key(self, block: bytearray, round_key: bytes) -> None:
        for i in range(32):
            block[i] ^= round_key[i]
    
    def _rotate_bytes(self, block: bytearray, inverse: bool = False) -> None:
        if not hasattr(self, '_rotate_perm') or not hasattr(self, '_rotate_perm_inv'):
            indices = list(range(32))
            for i in range(32):
                key_val = self.key[i % 32]
                j = (i + key_val) % 32
                indices[i], indices[j] = indices[j], indices[i]
            
            used = set()
            perm = [0] * 32
            for i in range(32):
                if indices[i] not in used:
                    perm[i] = indices[i]
                    used.add(indices[i])
                else:
                    for k in range(32):
                        if k not in used:
                            perm[i] = k
                            used.add(k)
                            break
            
            self._rotate_perm = perm
            self._rotate_perm_inv = [0] * 32
            for i in range(32):
                self._rotate_perm_inv[perm[i]] = i
        
        temp = bytearray(32)
        if not inverse:
            for i in range(32):
                temp[i] = block[self._rotate_perm[i]]
        else:
            for i in range(32):
                temp[i] = block[self._rotate_perm_inv[i]]
        block[:] = temp
    
    def _nonlinear_mix(self, block: bytearray) -> None:
        for i in range(32):
            a = block[i]
            b = block[(i + 11) % 32]
            c = block[(i + 23) % 32]
            result = (a ^ b) + (c & 0xFF)
            result = (result * 251) % 256
            result ^= ((a << 3) | (a >> 5)) & 0xFF
            result ^= ((b >> 2) | (b << 6)) & 0xFF
            block[i] = result
    
    def _encrypt_block(self, block: bytes) -> bytes:
        state = bytearray(block)
        self._add_round_key(state, self.round_keys[0])
        for r in range(self.ROUNDS):
            self._substitute(state)
            self._permute_bits(state)
            self._mix_columns(state)
            self._rotate_bytes(state)
            self._add_round_key(state, self.round_keys[r + 1])
        return bytes(state)
    
    def _decrypt_block(self, block: bytes) -> bytes:
        state = bytearray(block)
        for r in range(self.ROUNDS - 1, -1, -1):
            self._add_round_key(state, self.round_keys[r + 1])
            self._rotate_bytes(state, inverse=True)
            self._mix_columns(state, inverse=True)
            self._permute_bits(state, inverse=True)
            self._substitute(state, inverse=True)
        self._add_round_key(state, self.round_keys[0])
        return bytes(state)
    
    def _pad(self, data: bytes) -> bytes:
        pad_len = self.BLOCK_SIZE - (len(data) % self.BLOCK_SIZE)
        return data + bytes([pad_len] * pad_len)
    
    def _unpad(self, data: bytes) -> bytes:
        pad_len = data[-1]
        if pad_len > self.BLOCK_SIZE or pad_len == 0:
            raise ValueError("Invalid padding")
        for i in range(pad_len):
            if data[-(i + 1)] != pad_len:
                raise ValueError("Invalid padding")
        return data[:-pad_len]
    
    def encrypt(self, plaintext: bytes, iv: bytes = None) -> bytes:
        if iv is None:
            iv = os.urandom(self.BLOCK_SIZE)
        elif len(iv) != self.BLOCK_SIZE:
            raise ValueError(f"IV must be {self.BLOCK_SIZE} bytes")
        
        padded = self._pad(plaintext)
        ciphertext = bytearray(iv)
        prev_block = iv
        
        for i in range(0, len(padded), self.BLOCK_SIZE):
            block = padded[i:i + self.BLOCK_SIZE]
            xored = bytes(a ^ b for a, b in zip(block, prev_block))
            encrypted = self._encrypt_block(xored)
            ciphertext.extend(encrypted)
            prev_block = encrypted
        
        return bytes(ciphertext)
    
    def decrypt(self, ciphertext: bytes) -> bytes:
        if len(ciphertext) < self.BLOCK_SIZE:
            raise ValueError("Ciphertext too short")
        if len(ciphertext) % self.BLOCK_SIZE != 0:
            raise ValueError("Ciphertext length must be multiple of block size")
        
        iv = ciphertext[:self.BLOCK_SIZE]
        plaintext = bytearray()
        prev_block = iv
        
        for i in range(self.BLOCK_SIZE, len(ciphertext), self.BLOCK_SIZE):
            block = ciphertext[i:i + self.BLOCK_SIZE]
            decrypted = self._decrypt_block(block)
            xored = bytes(a ^ b for a, b in zip(decrypted, prev_block))
            plaintext.extend(xored)
            prev_block = block
        
        return self._unpad(bytes(plaintext))


class Sky256X:
    VERSION = 0x01
    NONCE_SIZE = 16
    MAC_SIZE = 32
    TIMESTAMP_SIZE = 8
    HEADER_SIZE = 1 + TIMESTAMP_SIZE + NONCE_SIZE
    DEFAULT_KDF_ITERATIONS = 600_000
    
    def __init__(self, master_key: bytes, kdf_salt: bytes):
        if len(master_key) != 32:
            raise ValueError("Master key must be 32 bytes")
        if len(kdf_salt) != 32:
            raise ValueError("KDF salt must be 32 bytes")
        
        self._master_key_array = bytearray(master_key)
        self.kdf_salt = kdf_salt
        self._nonce_cache = BoundedNonceCache()
        
        kek = self._hkdf_expand(master_key, b"Sky256X-v1-KEK", 32)
        kmac = self._hkdf_expand(master_key, b"Sky256X-v1-MAC", 32)
        
        self._kek_array = bytearray(kek)
        self._kmac_array = bytearray(kmac)
        self.kek = bytes(kek)
        self.kmac = bytes(kmac)
    
    def __del__(self):
        if hasattr(self, '_master_key_array'):
            secure_zero_memory(self._master_key_array)
        if hasattr(self, '_kek_array'):
            secure_zero_memory(self._kek_array)
        if hasattr(self, '_kmac_array'):
            secure_zero_memory(self._kmac_array)
    
    @staticmethod
    def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
        t = b""
        okm = b""
        i = 0
        while len(okm) < length:
            i += 1
            t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
            okm += t
        return okm[:length]
    
    @classmethod
    def derive_key_from_password(cls, password: str, salt: bytes = None, iterations: int = None, kdf_mode: str = KDFMode.PBKDF2) -> tuple:
        if salt is None:
            salt = os.urandom(32)
        elif len(salt) != 32:
            raise ValueError("Salt must be 32 bytes")
        
        if iterations is None:
            iterations = cls.DEFAULT_KDF_ITERATIONS
        
        if kdf_mode == KDFMode.ARGON2ID:
            master_key = _derive_key_argon2id(password, salt)
        else:
            master_key = _derive_key_pbkdf2(password, salt, iterations)
        
        return salt, master_key
    
    @classmethod
    def from_password(cls, password: str, salt: bytes = None, iterations: int = None, kdf_mode: str = KDFMode.PBKDF2):
        kdf_salt, master_key = cls.derive_key_from_password(password, salt, iterations, kdf_mode)
        master_key_array = bytearray(master_key)
        try:
            instance = cls(master_key, kdf_salt)
            return instance, kdf_salt
        finally:
            secure_zero_memory(master_key_array)
    
    def _derive_session_key(self, nonce: bytes, timestamp_bytes: bytes) -> bytes:
        context = nonce + timestamp_bytes
        return self._hkdf_expand(self.kek, context, 32)
    
    def encrypt(self, plaintext: bytes) -> bytes:
        nonce = os.urandom(self.NONCE_SIZE)
        timestamp = int(_time.time())
        timestamp_bytes = timestamp.to_bytes(self.TIMESTAMP_SIZE, 'big')
        version_byte = bytes([self.VERSION])
        
        nonce_id = nonce + timestamp_bytes
        if not self._nonce_cache.add(nonce_id):
            raise RuntimeError("SECURITY VIOLATION: Nonce reuse detected.")
        
        session_key = self._derive_session_key(nonce, timestamp_bytes)
        session_key_array = bytearray(session_key)
        
        try:
            cipher = Sky256(session_key)
            ciphertext = cipher.encrypt(plaintext)
            header = version_byte + timestamp_bytes + nonce
            aad = _compute_aad(self.VERSION, timestamp_bytes, self.kdf_salt)
            message = header + ciphertext
            mac = hmac.new(self.kmac, aad + message, hashlib.sha256).digest()
            return message + mac
        finally:
            secure_zero_memory(session_key_array)
    
    def decrypt(self, encrypted_message: bytes, max_age_seconds: int = 300) -> bytes:
        min_size = self.HEADER_SIZE + Sky256.BLOCK_SIZE + self.MAC_SIZE
        if len(encrypted_message) < min_size:
            raise ValueError("Invalid message: too short")
        
        version = encrypted_message[0]
        timestamp_bytes = encrypted_message[1:9]
        nonce = encrypted_message[9:25]
        ciphertext = encrypted_message[25:-32]
        received_mac = encrypted_message[-32:]
        
        if version != self.VERSION:
            raise ValueError(f"Unsupported version: {version:#x}")
        
        aad = _compute_aad(version, timestamp_bytes, self.kdf_salt)
        message = encrypted_message[:-32]
        expected_mac = hmac.new(self.kmac, aad + message, hashlib.sha256).digest()
        
        if not constant_time_bytes_eq(received_mac, expected_mac):
            raise ValueError("Authentication failed: MAC verification failed")
        
        timestamp = int.from_bytes(timestamp_bytes, 'big')
        if not validate_timestamp(timestamp, max_age_seconds):
            raise ValueError("Message expired or replayed")
        
        session_key = self._derive_session_key(nonce, timestamp_bytes)
        session_key_array = bytearray(session_key)
        
        try:
            cipher = Sky256(session_key)
            plaintext = cipher.decrypt(ciphertext)
            return plaintext
        finally:
            secure_zero_memory(session_key_array)


class CipherSuite:
    SKY256X = 0x01
    AES256GCM = 0x02
    NAMES = {0x01: "SKY256X", 0x02: "AES256GCM"}
    
    @classmethod
    def is_valid(cls, mode: int) -> bool:
        return mode in (cls.SKY256X, cls.AES256GCM)
    
    @classmethod
    def get_name(cls, mode: int) -> str:
        return cls.NAMES.get(mode, f"UNKNOWN({mode:#x})")


class AES256GCM:
    VERSION = CipherSuite.AES256GCM
    NONCE_SIZE = 12
    TAG_SIZE = 16
    TIMESTAMP_SIZE = 8
    HEADER_SIZE = 1 + TIMESTAMP_SIZE + NONCE_SIZE
    
    def __init__(self, encryption_key: bytes, metadata_key: bytes):
        if len(encryption_key) != 32:
            raise ValueError("AES-256 key must be 32 bytes")
        if len(metadata_key) != 32:
            raise ValueError("Metadata key must be 32 bytes")
        
        self._enc_key_array = bytearray(encryption_key)
        self._meta_key_array = bytearray(metadata_key)
        self.encryption_key = encryption_key
        self.metadata_key = metadata_key
        self._nonce_cache = BoundedNonceCache()
        
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            self._aesgcm_available = True
        except ImportError:
            raise RuntimeError("AES-GCM requires the 'cryptography' package. Install it with: pip install cryptography")
    
    def __del__(self):
        if hasattr(self, '_enc_key_array'):
            secure_zero_memory(self._enc_key_array)
        if hasattr(self, '_meta_key_array'):
            secure_zero_memory(self._meta_key_array)
    
    def encrypt(self, plaintext: bytes, salt: bytes = b"") -> bytes:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        
        nonce = secure_random_bytes(self.NONCE_SIZE)
        timestamp = int(_time.time())
        timestamp_bytes = timestamp.to_bytes(self.TIMESTAMP_SIZE, 'big')
        
        nonce_id = nonce + timestamp_bytes
        if not self._nonce_cache.add(nonce_id):
            raise RuntimeError("SECURITY VIOLATION: Nonce reuse detected in AES-GCM")
        
        version_byte = bytes([self.VERSION])
        aad = _compute_aad(self.VERSION, timestamp_bytes, salt if salt else self.metadata_key)
        
        aesgcm = AESGCM(self.encryption_key)
        ct_with_tag = aesgcm.encrypt(nonce, plaintext, aad)
        ciphertext = ct_with_tag[:-16]
        tag = ct_with_tag[-16:]
        
        return version_byte + timestamp_bytes + nonce + ciphertext + tag
    
    def decrypt(self, encrypted_message: bytes, max_age_seconds: int = 300, salt: bytes = b"") -> bytes:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        
        min_size = self.HEADER_SIZE + self.TAG_SIZE + 1
        if len(encrypted_message) < min_size:
            raise ValueError("Invalid AES-GCM message: too short")
        
        version = encrypted_message[0]
        timestamp_bytes = encrypted_message[1:9]
        nonce = encrypted_message[9:21]
        ciphertext = encrypted_message[21:-16]
        tag = encrypted_message[-16:]
        
        if version != self.VERSION:
            raise ValueError(f"Invalid cipher suite: expected AES256GCM, got {version:#x}")
        
        timestamp = int.from_bytes(timestamp_bytes, 'big')
        if not validate_timestamp(timestamp, max_age_seconds):
            raise ValueError("Message expired or replayed (timestamp validation failed)")
        
        aad = _compute_aad(version, timestamp_bytes, salt if salt else self.metadata_key)
        
        aesgcm = AESGCM(self.encryption_key)
        ct_with_tag = ciphertext + tag
        try:
            plaintext = aesgcm.decrypt(nonce, ct_with_tag, aad)
            return plaintext
        except Exception:
            raise ValueError("AES-GCM authentication failed")


class UnifiedCipher:
    DEFAULT_MODE = "AES256GCM"
    VALID_MODES = {"SKY256X", "AES256GCM"}
    
    def __init__(self, password: str, salt: bytes = None, kdf_mode: str = KDFMode.PBKDF2):
        self.salt, master_key = derive_master_key(password, salt, kdf_mode=kdf_mode)
        self._master_key_array = bytearray(master_key)
        self.master_key = master_key
        self.subkeys = derive_subkeys(master_key, self.salt)
        self._sky256x = None
        self._aesgcm = None
    
    def __del__(self):
        if hasattr(self, '_master_key_array'):
            secure_zero_memory(self._master_key_array)
        if hasattr(self, 'subkeys'):
            for k, v in self.subkeys.items():
                arr = bytearray(v)
                secure_zero_memory(arr)
    
    @property
    def sky256x(self) -> Sky256X:
        if self._sky256x is None:
            self._sky256x = Sky256X(self.subkeys['K_sky256x_enc'], self.salt)
            self._sky256x.kmac = self.subkeys['K_sky256x_mac']
        return self._sky256x
    
    @property
    def aesgcm(self) -> AES256GCM:
        if self._aesgcm is None:
            self._aesgcm = AES256GCM(self.subkeys['K_aesgcm_enc'], self.subkeys['K_metadata'])
        return self._aesgcm
    
    def encrypt(self, plaintext: bytes, mode: str = None) -> bytes:
        if mode is None:
            mode = self.DEFAULT_MODE
        mode = mode.upper()
        if mode not in self.VALID_MODES:
            raise ValueError(f"Invalid mode: {mode}. Valid modes: {self.VALID_MODES}")
        if mode == "SKY256X":
            return self.sky256x.encrypt(plaintext)
        elif mode == "AES256GCM":
            return self.aesgcm.encrypt(plaintext, self.salt)
    
    def decrypt(self, encrypted_message: bytes, max_age_seconds: int = 300) -> bytes:
        if len(encrypted_message) < 1:
            raise ValueError("Invalid message: empty")
        version = encrypted_message[0]
        if version == CipherSuite.SKY256X:
            return self.sky256x.decrypt(encrypted_message, max_age_seconds)
        elif version == CipherSuite.AES256GCM:
            return self.aesgcm.decrypt(encrypted_message, max_age_seconds, self.salt)
        else:
            raise ValueError(f"Unknown cipher suite: {version:#x}")
    
    def wipe_keys(self) -> None:
        secure_zero_memory(self._master_key_array)
        for k, v in self.subkeys.items():
            arr = bytearray(v)
            secure_zero_memory(arr)


def encrypt_message(plaintext: bytes, password: str, mode: str = "AES256GCM", salt: bytes = None, kdf_mode: str = KDFMode.PBKDF2) -> tuple:
    if not isinstance(plaintext, bytes):
        raise ValueError("Plaintext must be bytes")
    if not password:
        raise ValueError("Password cannot be empty")
    
    cipher = None
    try:
        cipher = UnifiedCipher(password, salt, kdf_mode)
        ciphertext = cipher.encrypt(plaintext, mode)
        return ciphertext, cipher.salt
    finally:
        if cipher:
            cipher.wipe_keys()


def decrypt_message(ciphertext: bytes, password: str, salt: bytes, max_age_seconds: int = 300, kdf_mode: str = KDFMode.PBKDF2) -> bytes:
    if not ciphertext:
        raise ValueError("Ciphertext cannot be empty")
    if not password:
        raise ValueError("Password cannot be empty")
    if not salt or len(salt) != 32:
        raise ValueError("Salt must be exactly 32 bytes")
    
    cipher = None
    try:
        cipher = UnifiedCipher(password, salt, kdf_mode)
        return cipher.decrypt(ciphertext, max_age_seconds)
    finally:
        if cipher:
            cipher.wipe_keys()


def generate_key_from_password(password: str) -> bytes:
    return hashlib.sha256(password.encode()).digest()
