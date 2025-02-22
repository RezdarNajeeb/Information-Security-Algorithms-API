from fastapi import APIRouter
from models import CaesarRequest
from services import caesar_encrypt, caesar_decrypt, caesar_brute_force

router = APIRouter()

@router.post("/encrypt")
def encrypt(request: CaesarRequest):
    return {"encrypted_text": caesar_encrypt(request.text, request.shift)}

@router.post("/decrypt")
def decrypt(request: CaesarRequest):
    return {"decrypted_text": caesar_decrypt(request.text, request.shift)}

@router.post("/brute_force")
def brute_force(request: CaesarRequest):
    return {"possible_decryptions": caesar_brute_force(request.text)}