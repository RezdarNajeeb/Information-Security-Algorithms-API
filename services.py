import random

chars = list(chr(i) for i in range(256) if chr(i).isprintable())

def caesar_encrypt(text: str, shift: int) -> str:
    return ''.join(chars[(chars.index(c) + shift) % len(chars)] if c in chars else c for c in text)

def caesar_decrypt(text: str, shift: int) -> str:
    return ''.join(chars[(chars.index(c) - shift) % len(chars)] if c in chars else c for c in text)

def caesar_brute_force(text: str) -> dict:
    return {shift: caesar_decrypt(text, shift) for shift in range(1, len(chars))}

def generate_mono_key() -> str:
    shuffled = chars.copy()
    random.shuffle(shuffled)
    return ''.join(shuffled)

def mono_encrypt(text: str, key: str) -> str:
    mapping = dict(zip(chars, key))
    return ''.join(mapping[c] if c in mapping else c for c in text)

def mono_decrypt(text: str, key: str) -> str:
    reverse_mapping = dict(zip(key, chars))
    return ''.join(reverse_mapping[c] if c in reverse_mapping else c for c in text)
