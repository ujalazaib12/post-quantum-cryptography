"""
exp01_aes_gcm.py

Goal: Show AES-256-GCM protecting a real file (a .docx), and prove the "AEAD"
      claim from the notes: if the ciphertext is tampered with, decryption
      FAILS instead of silently returning garbage.

Inputs / outputs (all binary):
    INPUT:  D:\\BlockChain\\week01\\W1D1.docx
    OUTPUT: W1D1.docx.enc          (encrypted file)
            W1D1.recovered.docx    (decrypted copy — should match the original)

Run:
    python exp01_aes_gcm.py
"""

import os
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Real Word document to encrypt (binary bytes, not a text string).
INPUT_PATH = Path(r"D:\BlockChain\week01\W1D1.docx")
# Keep experiment artefacts next to this script.
OUT_DIR = Path(__file__).resolve().parent
CIPHERTEXT_PATH = OUT_DIR / "W1D1.docx.enc"
RECOVERED_PATH = OUT_DIR / "W1D1.recovered.docx"


def main():
    if not INPUT_PATH.is_file():
        raise FileNotFoundError(f"Input file not found: {INPUT_PATH}")

    # 1. Generate a random 256-bit (32-byte) AES key.
    #    In a real system this key would come from ML-KEM's shared secret (or HKDF).
    key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(key)

    # 2. A 96-bit (12-byte) nonce is required for GCM.
    #    MUST be unique per encryption with the same key (nonce reuse = broken).
    nonce = os.urandom(12)

    # 3. Read the real file as raw bytes (works for .docx, DICOM, images, etc.).
    plaintext = INPUT_PATH.read_bytes()
    print(f"Input file:          {INPUT_PATH}")
    print(f"Original size:       {len(plaintext)} bytes")

    # 4. Optional associated data: authenticated but NOT encrypted
    
    associated_data = INPUT_PATH.name.encode("utf-8") 

    # --- ENCRYPT ---
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    # Store nonce || ciphertext so we can decrypt later without a separate sidecar.
    # (GCM tag is already appended inside `ciphertext` by the library.)
    CIPHERTEXT_PATH.write_bytes(nonce + ciphertext)
    print(f"Encrypted file:      {CIPHERTEXT_PATH}")
    print(f"Ciphertext size:     {len(ciphertext)} bytes "
          f"(+ {len(nonce)}-byte nonce on disk = {CIPHERTEXT_PATH.stat().st_size})")
    print(f"Ciphertext preview:  {ciphertext[:32].hex()}...")
    print()

    # --- DECRYPT (normal case: should succeed and recreate the file) ---
    blob = CIPHERTEXT_PATH.read_bytes()
    nonce_r, ciphertext_r = blob[:12], blob[12:]
    decrypted = aesgcm.decrypt(nonce_r, ciphertext_r, associated_data)
    RECOVERED_PATH.write_bytes(decrypted)

    print("[OK] Decryption succeeded.")
    print(f"Recovered file:      {RECOVERED_PATH}")
    print(f"Recovered size:      {len(decrypted)} bytes")
    assert decrypted == plaintext, "Recovered bytes do not match the original file!"
    print("[OK] Recovered file bytes == original file bytes.")
    print()

    # --- DECRYPT (tampered ciphertext: should FAIL) ---
    # Flip a single bit to simulate an attacker modifying the file on disk/in transit.
    tampered = bytearray(ciphertext_r)
    tampered[0] ^= 0x01
    tampered = bytes(tampered)

    print("Tampering with ciphertext (flipped 1 bit)...")
    try:
        aesgcm.decrypt(nonce_r, tampered, associated_data)
        print("[UNEXPECTED] Decryption succeeded on tampered data — this should never happen!")
    except InvalidTag:
        print("[EXPECTED] Decryption FAILED: InvalidTag raised.")
        print("This is AEAD's authentication guarantee working correctly:")
        print("tampered ciphertext is rejected instead of returning a corrupted .docx.")


if __name__ == "__main__":
    main()
