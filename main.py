from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from routers import caesar, mono, des

app = FastAPI(title="Encryption API", description="API for encryption and decryption algorithms")

# Enable CORS for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Change this in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(caesar.router, prefix="/caesar", tags=["Caesar Cipher"])
app.include_router(mono.router, prefix="/mono", tags=["Monoalphabetic Cipher"])
app.include_router(des.router, prefix="/des", tags=["DES Encryption"])

@app.get("/")
def home():
    return {"message": "Welcome to the Encryption API"}