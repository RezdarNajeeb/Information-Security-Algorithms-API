from pydantic import BaseModel, validator


class CaesarRequest(BaseModel):
    text: str
    shift: int


class MonoRequest(BaseModel):
    text: str
    key: str  # Must be a 1-to-1 mapping


class DESRequest(BaseModel):
    text: str
    key: str = None  # Optional: will generate if not provided

    @validator('text')
    def validate_text(cls, v):
        if len(v) != 64 or not all(c in '01' for c in v):
            raise ValueError("Text must be exactly 64 binary bits (0s and 1s only)")
        return v

    @validator('key', pre=True)
    def validate_key(cls, v):
        if v is not None and (len(v) != 64 or not all(c in '01' for c in v)):
            raise ValueError("Key must be exactly 64 binary bits (0s and 1s only)")
        return v