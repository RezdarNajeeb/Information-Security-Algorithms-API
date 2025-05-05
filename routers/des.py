from fastapi import APIRouter, HTTPException
from models import DESRequest
from services import des_encrypt_service, des_decrypt_service, generate_des_key

router = APIRouter()


@router.get("/generate_key")
def generate_key():
    """Generate a random 64-bit DES key."""
    return {"key": generate_des_key()}


@router.post("/encrypt")
def encrypt(request: DESRequest):
    """Encrypt binary text using DES algorithm.
    The input must be a 64-bit binary string (0s and 1s)."""
    try:
        # Validate input is binary
        if len(request.text) != 64 or not all(c in '01' for c in request.text):
            raise ValueError("Input must be exactly 64 binary bits (0s and 1s only)")

        # Use provided key or generate a new one
        key = request.key if request.key else generate_des_key()

        result = des_encrypt_service(request.text, key)
        return {
            "encrypted_text": result["ciphertext"],
            "key": key,
            "binary_ciphertext": result["binary_ciphertext"]
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Encryption error: {str(e)}")


@router.post("/decrypt")
def decrypt(request: DESRequest):
    """Decrypt binary ciphertext using DES algorithm.
    Both input and key must be 64-bit binary strings (0s and 1s)."""
    try:
        # Validate input is binary
        if len(request.text) != 64 or not all(c in '01' for c in request.text):
            raise ValueError("Input must be exactly 64 binary bits (0s and 1s only)")

        if not request.key:
            raise HTTPException(status_code=400, detail="Key is required for decryption")

        if len(request.key) != 64 or not all(c in '01' for c in request.key):
            raise ValueError("Key must be exactly 64 binary bits (0s and 1s only)")

        result = des_decrypt_service(request.text, request.key)
        return {
            "decrypted_text": result["plaintext"],
            "binary_plaintext": result["binary_plaintext"]
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Decryption error: {str(e)}")
