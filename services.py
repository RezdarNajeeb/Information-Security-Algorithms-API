import random
from typing import Dict, List

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


# DES Service Functions
def generate_des_key() -> str:
    """Generate a random 64-bit key as a string of 0s and 1s."""
    return ''.join([str(random.randint(0, 1)) for _ in range(64)])


def remove_parity_bits(key: str) -> str:
    """Remove the parity bits at positions 8, 16, 24, etc."""
    parity_positions = [8, 16, 24, 32, 40, 48, 56, 64]
    adjusted_positions = [pos - 1 for pos in parity_positions]

    key_without_parity = ''
    for i in range(len(key)):
        if i not in adjusted_positions:
            key_without_parity += key[i]

    return key_without_parity


def split_key(key: str) -> tuple:
    """Split the 56-bit key into two 28-bit halves."""
    c = key[:28]
    d = key[28:]
    return c, d


def left_rotate(bits: str, n: int) -> str:
    """Perform a left circular shift on the bits by n positions."""
    return bits[n:] + bits[:n]


def apply_pc2(c: str, d: str) -> str:
    """Apply Permutation Choice 2 to get a 48-bit subkey."""
    combined = c + d
    ignore_positions = [9, 18, 22, 25, 35, 38, 43, 54]

    all_positions = list(range(1, 57))
    valid_positions = [pos for pos in all_positions if pos not in ignore_positions]

    random.shuffle(valid_positions)
    pc2_table = valid_positions[:48]
    pc2_adjusted = [pos - 1 for pos in pc2_table]

    subkey = ''
    for pos in pc2_adjusted:
        subkey += combined[pos]

    return subkey


def generate_subkeys(master_key: str) -> List[str]:
    """Generate 16 subkeys from the master key."""
    key_56bit = remove_parity_bits(master_key)
    c, d = split_key(key_56bit)

    rotation_schedule = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

    subkeys = []
    for round_num in range(16):
        rotations = rotation_schedule[round_num]
        c = left_rotate(c, rotations)
        d = left_rotate(d, rotations)

        subkey = apply_pc2(c, d)
        subkeys.append(subkey)

    return subkeys


# ASCII Conversion Functions
def ascii_to_binary(text: str) -> str:
    """Convert ASCII text to binary representation."""
    binary = ''
    for char in text:
        binary += format(ord(char), '08b')
    return binary


def binary_to_ascii(binary: str) -> str:
    """Convert binary representation back to ASCII text."""
    text = ''
    for i in range(0, len(binary), 8):
        byte = binary[i:i + 8]
        text += chr(int(byte, 2))
    return text


# DES Encryption Functions
def apply_initial_permutation(message: str) -> str:
    """Apply the Initial Permutation (IP) to the 64-bit message."""
    ip_table = [
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    ]

    ip_adjusted = [pos - 1 for pos in ip_table]

    permuted = ''
    for pos in ip_adjusted:
        permuted += message[pos]

    return permuted


def split_message(message: str) -> tuple:
    """Split the 64-bit message into two 32-bit halves."""
    l = message[:32]
    r = message[32:]
    return l, r


def expansion_function(r_block: str) -> str:
    """Expand the 32-bit R block to 48 bits using the E-box."""
    e_box = [
        32, 1, 2, 3, 4, 5,
        4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1
    ]

    e_box_adjusted = [pos - 1 for pos in e_box]

    expanded = ''
    for pos in e_box_adjusted:
        expanded += r_block[pos]

    return expanded


def xor(bits1: str, bits2: str) -> str:
    """Perform bitwise XOR between two bit strings."""
    result = ''
    for b1, b2 in zip(bits1, bits2):
        result += '1' if b1 != b2 else '0'
    return result


def apply_sbox(bits: str) -> str:
    """Apply the 8 S-boxes to transform 48 bits to 32 bits."""
    s_boxes = [
        # S1
        [
            [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
            [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
            [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
            [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
        ],
        # S2
        [
            [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
            [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
            [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
            [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
        ],
        # S3
        [
            [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
            [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
            [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
            [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
        ],
        # S4
        [
            [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
            [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
            [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
            [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
        ],
        # S5
        [
            [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
            [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
            [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
            [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
        ],
        # S6
        [
            [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
            [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
            [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
            [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
        ],
        # S7
        [
            [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
            [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
            [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
            [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
        ],
        # S8
        [
            [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
            [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
            [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
            [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
        ]
    ]

    bit_groups = [bits[i:i + 6] for i in range(0, 48, 6)]

    output = ''
    for i, group in enumerate(bit_groups):
        row = int(group[0] + group[5], 2)
        col = int(group[1:5], 2)

        value = s_boxes[i][row][col]
        output += format(value, '04b')

    return output


def apply_pbox(bits: str) -> str:
    """Apply the P-box permutation to the 32-bit input."""
    p_box = [
        16, 7, 20, 21, 29, 12, 28, 17,
        1, 15, 23, 26, 5, 18, 31, 10,
        2, 8, 24, 14, 32, 27, 3, 9,
        19, 13, 30, 6, 22, 11, 4, 25
    ]

    p_box_adjusted = [pos - 1 for pos in p_box]

    permuted = ''
    for pos in p_box_adjusted:
        permuted += bits[pos]

    return permuted


def apply_final_permutation(message: str) -> str:
    """Apply the Final Permutation (FP) to the 64-bit message."""
    fp_table = [
        40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25
    ]

    fp_adjusted = [pos - 1 for pos in fp_table]

    permuted = ''
    for pos in fp_adjusted:
        permuted += message[pos]

    return permuted


def f_function(r_block: str, subkey: str) -> str:
    """Implement the F function of the Feistel network."""
    expanded = expansion_function(r_block)
    mixed = xor(expanded, subkey)
    substituted = apply_sbox(mixed)
    permuted = apply_pbox(substituted)

    return permuted


def des_core_encrypt(message: str, subkeys: List[str]) -> str:
    """Encrypt a 64-bit message using DES with the given subkeys."""
    message = apply_initial_permutation(message)
    left, right = split_message(message)

    for i in range(16):
        prev_right = right
        f_result = f_function(right, subkeys[i])
        right = xor(left, f_result)
        left = prev_right

    combined = right + left
    ciphertext = apply_final_permutation(combined)

    return ciphertext


# Main DES Service Functions
def des_encrypt_service(text: str, key: str) -> Dict[str, str]:
    """Encrypt text using DES."""
    # Validate input
    if len(text) != 8:
        raise ValueError("Text must be exactly 8 characters long")

    if key and len(key) != 64:
        raise ValueError("Key must be exactly 64 bits (characters of 0s and 1s)")

    # Convert text to binary
    plaintext_binary = ascii_to_binary(text)

    # Use provided key or generate new one
    master_key = key if key else generate_des_key()

    # Generate subkeys
    subkeys = generate_subkeys(master_key)

    # Encrypt
    ciphertext_binary = des_core_encrypt(plaintext_binary, subkeys)

    # Convert to ASCII for display
    try:
        ciphertext_ascii = binary_to_ascii(ciphertext_binary)
        # Handle non-printable characters
        ciphertext_display = ''.join(char for char in ciphertext_ascii)
    except:
        ciphertext_display = "[Binary data - cannot display as ASCII]"

    return {
        "ciphertext": ciphertext_display,
        "binary_ciphertext": ciphertext_binary,
        "key": master_key
    }


def des_decrypt_service(ciphertext: str, key: str) -> Dict[str, str]:
    """Decrypt text using DES."""
    # Validate key
    if len(key) != 64:
        raise ValueError("Key must be exactly 64 bits")

    # Handle different input formats
    if len(ciphertext) == 64 and all(c in '01' for c in ciphertext):
        # Binary input
        ciphertext_binary = ciphertext
    else:
        # ASCII input - convert to binary
        if len(ciphertext) != 8:
            raise ValueError("Ciphertext must be exactly 8 characters or 64 bits")
        ciphertext_binary = ascii_to_binary(ciphertext)

    # Generate subkeys
    subkeys = generate_subkeys(key)

    # Decrypt (use reversed subkeys)
    plaintext_binary = des_core_encrypt(ciphertext_binary, subkeys[::-1])

    # Convert to ASCII
    plaintext_ascii = binary_to_ascii(plaintext_binary)

    return {
        "plaintext": plaintext_ascii,
        "binary_plaintext": plaintext_binary
    }
