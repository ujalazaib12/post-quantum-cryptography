"""
exp03_hkdf.py

Goal: Show how to take ONE shared secret (e.g. what ML-KEM's Decaps() gives you)
      and derive TWO independent-looking keys from it using HKDF:
        - an encryption key   (for AES-256-GCM on the image data)
        - an index key        (for HMAC-based searchable index, see exp02)

This avoids ever reusing the same raw key for two different jobs.

Run:
    python exp03_hkdf.py
"""

import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def derive_key(shared_secret: bytes, info: bytes, length: int = 32) -> bytes:
    """
    HKDF = HMAC-based Key Derivation Function.
    - shared_secret: the raw input key material (e.g. ML-KEM's output K)
    - info: a context/label string that makes each derived key unique
             for its purpose, even from the same shared_secret
    - salt=None here for simplicity; in production use a random salt
      exchanged alongside the ciphertext, or a fixed protocol-defined salt.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info,
    )
    return hkdf.derive(shared_secret)


def main():
    # Simulate the 32-byte shared secret you'd get from ML-KEM's Decaps().
    shared_secret = os.urandom(32)
    print("Shared secret (from ML-KEM, simulated):", shared_secret.hex())
    print()

    # Derive two keys from the SAME shared secret using different "info" labels.
    encryption_key = derive_key(shared_secret, info=b"image-encryption-key")
    index_key = derive_key(shared_secret, info=b"searchable-index-key")

    print("Derived encryption key (for AES-256-GCM):", encryption_key.hex())
    print("Derived index key      (for HMAC index): ", index_key.hex())
    print()

    print("Are the two derived keys different?", encryption_key != index_key)
    assert encryption_key != index_key

    print()
    print("Reproducibility check: deriving again with the same secret + info")
    print("gives back the SAME key (HKDF is deterministic given the same inputs).")
    encryption_key_again = derive_key(shared_secret, info=b"image-encryption-key")
    print("Matches original encryption key?", encryption_key_again == encryption_key)
    assert encryption_key_again == encryption_key

    print()
    print("Takeaway: one shared secret -> many purpose-specific keys, just by")
    print("changing the 'info' label. This is exactly the pattern to use so")
    print("the AES-256 encryption key and the HMAC index key (exp02) are never")
    print("the same key, even though they both trace back to one ML-KEM secret.")


if __name__ == "__main__":
    main()
