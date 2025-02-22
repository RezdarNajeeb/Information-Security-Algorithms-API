from pydantic import BaseModel

class CaesarRequest(BaseModel):
    text: str
    shift: int

class MonoRequest(BaseModel):
    text: str
    key: str  # Must be a 1-to-1 mapping