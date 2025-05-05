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
    """Encrypt text using DES algorithm."""
    try:
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
    """Decrypt text using DES algorithm."""
    if not request.key:
        raise HTTPException(status_code=400, detail="Key is required for decryption")

    try:
        result = des_decrypt_service(request.text, request.key)
        return {
            "decrypted_text": result["plaintext"],
            "binary_plaintext": result["binary_plaintext"]
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Decryption error: {str(e)}")