from fastapi import APIRouter
from models import MonoRequest
from services import mono_encrypt, mono_decrypt, generate_mono_key

router = APIRouter()

@router.get("/generate_key")
def generate_key():
    return {"key": generate_mono_key()}

@router.post("/encrypt")
def encrypt(request: MonoRequest):
    return {"encrypted_text": mono_encrypt(request.text, request.key)}

@router.post("/decrypt")
def decrypt(request: MonoRequest):
    return {"decrypted_text": mono_decrypt(request.text, request.key)}
