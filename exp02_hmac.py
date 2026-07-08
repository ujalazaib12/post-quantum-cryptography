"""
exp02_hmac.py

Goal: Show two properties of HMAC-SHA256 that matter for the notes:
  1. Same keyword + same key  -> always the SAME tag (deterministic).
  2. Same keyword + different key -> a DIFFERENT, unrelated-looking tag.

Why this matters ("seed of the trapdoor idea"):
  In Searchable Symmetric Encryption (SSE), you often can't index encrypted
  keywords directly (AES-GCM ciphertext is different every time due to the
  nonce). But HMAC(key, keyword) is deterministic, so it can be used to build
  a secure, searchable index: same keyword always maps to the same tag,
  so you can look it up - but only someone with the key could have produced
  that tag in the first place (that's the "trapdoor").

Run:
    python exp02_hmac.py
"""

import hmac
import hashlib
import os


def hmac_sha256(key: bytes, message: bytes) -> str:
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def main():
    key_a = os.urandom(32)  # 256-bit key #1
    key_b = os.urandom(32)  # 256-bit key #2 (different from key_a)

    keywords = ["fracture", "mri", "fracture", "ct-scan"]

    print("=== Same key, multiple keywords ===")
    tags_with_key_a = {}
    for word in keywords:
        tag = hmac_sha256(key_a, word.encode())
        tags_with_key_a.setdefault(word, []).append(tag)
        print(f"HMAC(key_a, {word!r}) = {tag}")

    print()
    print("=== Property 1: same keyword + same key -> same tag ===")
    fracture_tags = tags_with_key_a["fracture"]
    print("Both 'fracture' tags equal:", fracture_tags[0] == fracture_tags[1])
    assert fracture_tags[0] == fracture_tags[1]

    print()
    print("=== Property 2: same keyword + different key -> different tag ===")
    word = "fracture"
    tag_key_a = hmac_sha256(key_a, word.encode())
    tag_key_b = hmac_sha256(key_b, word.encode())
    print(f"HMAC(key_a, {word!r}) = {tag_key_a}")
    print(f"HMAC(key_b, {word!r}) = {tag_key_b}")
    print("Tags equal?", tag_key_a == tag_key_b)
    assert tag_key_a != tag_key_b

    print()
    print("Takeaway: the tag is a deterministic fingerprint of (key, message).")
    print("Without the key, you cannot predict or forge the tag for a given")
    print("keyword - that's what makes it usable as a secure search index.")


if __name__ == "__main__":
    main()
