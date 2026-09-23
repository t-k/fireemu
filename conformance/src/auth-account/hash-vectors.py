# /// script
# requires-python = ">=3.12"
# dependencies = ["bcrypt==4.2.1", "argon2-cffi==23.1.0", "cryptography"]
# ///
"""Fixed password-hash import vectors for the AUTH-ACCOUNT corpus (test password, made-up keys).

Regenerate with `uv run conformance/src/auth-account/hash-vectors.py > conformance/src/auth-account/hash-vectors.json`.
The conventions (MD5 round chaining, HMAC message order, PBKDF key length, Firebase scrypt) are
the ones production accepted in the 2026-09-23 sandbox exploration.
"""
import base64, hashlib, hmac, json
import argon2.low_level as a2
import bcrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

PW, SALT = b"password123", b"salt-value-01"
KEY = b"fireemu-test-signer-key-not-a-secret-0123456789"
SEP = b"\x01"
b64 = lambda b: base64.b64encode(b).decode()
v = {}
def add(name, options, hash_bytes, salt=SALT):
    user = {"passwordHash": b64(hash_bytes)}
    if salt is not None: user["salt"] = b64(salt)
    v[name] = {"options": options, "user": user}

def md5_rounds(r):
    x = hashlib.md5(SALT + PW).digest()
    for _ in range(r): x = hashlib.md5(x + PW).digest()
    return x.hex().encode()
for r in (0, 1, 2): add(f"MD5-r{r}", {"hashAlgorithm": "MD5", "rounds": r}, md5_rounds(r))
for algo, fn in {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}.items():
    add(f"{algo}-r1", {"hashAlgorithm": algo, "rounds": 1}, fn(SALT + PW).digest())
    add(f"{algo}-r2", {"hashAlgorithm": algo, "rounds": 2}, fn(fn(SALT + PW).digest()).digest())
    add(f"{algo}-r1-password-and-salt", {"hashAlgorithm": algo, "rounds": 1, "passwordHashOrder": "PASSWORD_AND_SALT"}, fn(PW + SALT).digest())
for algo, name in {"HMAC_MD5": "md5", "HMAC_SHA1": "sha1", "HMAC_SHA256": "sha256", "HMAC_SHA512": "sha512"}.items():
    add(f"{algo}-default", {"hashAlgorithm": algo, "signerKey": b64(KEY)}, hmac.new(KEY, PW + SALT, name).digest())
    add(f"{algo}-salt-and-password", {"hashAlgorithm": algo, "signerKey": b64(KEY), "passwordHashOrder": "SALT_AND_PASSWORD"}, hmac.new(KEY, SALT + PW, name).digest())
add("PBKDF_SHA1", {"hashAlgorithm": "PBKDF_SHA1", "rounds": 1000}, hashlib.pbkdf2_hmac("sha1", PW, SALT, 1000, 20))
add("PBKDF_SHA1-dk64", {"hashAlgorithm": "PBKDF_SHA1", "rounds": 1000}, hashlib.pbkdf2_hmac("sha1", PW, SALT, 1000, 64))
add("PBKDF2_SHA256", {"hashAlgorithm": "PBKDF2_SHA256", "rounds": 1000}, hashlib.pbkdf2_hmac("sha256", PW, SALT, 1000, 32))
d = hashlib.scrypt(PW, salt=SALT + SEP, n=1 << 14, r=8, p=1, dklen=64, maxmem=2**31 - 1)
e = Cipher(algorithms.AES(d[:32]), modes.CTR(b"\x00" * 16)).encryptor()
add("SCRYPT", {"hashAlgorithm": "SCRYPT", "signerKey": b64(KEY), "saltSeparator": b64(SEP), "rounds": 8, "memoryCost": 14}, e.update(KEY) + e.finalize())
add("STANDARD_SCRYPT", {"hashAlgorithm": "STANDARD_SCRYPT", "cpuMemCost": 1024, "blockSize": 8, "parallelization": 1, "dkLen": 64}, hashlib.scrypt(PW, salt=SALT, n=1024, r=8, p=1, dklen=64))
add("BCRYPT", {"hashAlgorithm": "BCRYPT"}, bcrypt.hashpw(PW, b"$2a$10$abcdefghijklmnopqrstuu"), salt=None)
for t, typ in (("ARGON2_ID", a2.Type.ID), ("ARGON2_I", a2.Type.I), ("ARGON2_D", a2.Type.D)):
    add(f"ARGON2-{t}", {"hashAlgorithm": "ARGON2", "argon2Parameters": {"hashType": t, "iterations": 2, "memoryCostKib": 1024, "parallelism": 1, "hashLengthBytes": 32}},
        a2.hash_secret_raw(PW, SALT, time_cost=2, memory_cost=1024, parallelism=1, hash_len=32, type=typ))
print(json.dumps(v, indent=2, sort_keys=True))
