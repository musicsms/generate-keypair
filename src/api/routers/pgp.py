from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field, model_validator, EmailStr
from typing import Optional
from services.pgp_service import PGPService
from datetime import datetime, timedelta

router = APIRouter()
generator = PGPService()

class PGPRequest(BaseModel):
    name: str = Field(..., min_length=1, description="Full name for the key")
    email: EmailStr = Field(..., description="Email address for the key")
    key_length: int = Field(2048, ge=2048, le=4096, description="Key length in bits")
    passphrase: Optional[str] = Field(None, min_length=8, description="Optional passphrase for private key")
    comment: Optional[str] = Field(None, description="Optional comment for the key")
    expiry_days: Optional[int] = Field(None, ge=1, description="Optional expiry time in days")

    @model_validator(mode="before")
    @classmethod
    def validate_fields(cls, values):
        # Validate name
        name = values.get("name")
        if not isinstance(name, str):
            raise ValueError("Name must be a string")
        if not name.strip():
            raise ValueError("Name cannot be empty")

        # Validate key_length
        key_length = values.get("key_length", 2048)
        if not isinstance(key_length, int):
            raise ValueError("Key length must be an integer")
        if key_length < 2048 or key_length > 4096:
            raise ValueError("Key length must be between 2048 and 4096 bits")

        # Validate passphrase
        passphrase = values.get("passphrase")
        if passphrase is not None:
            if not isinstance(passphrase, str):
                raise ValueError("Passphrase must be a string")
            if len(passphrase) < 8:
                raise ValueError("Passphrase must be at least 8 characters long")

        # Validate comment
        comment = values.get("comment")
        if comment is not None and not isinstance(comment, str):
            raise ValueError("Comment must be a string")

        # Validate expiry_days
        expiry_days = values.get("expiry_days")
        if expiry_days is not None:
            if not isinstance(expiry_days, int):
                raise ValueError("Expiry days must be an integer")
            if expiry_days < 1:
                raise ValueError("Expiry days must be at least 1")

        return values

class PGPResponse(BaseModel):
    public_key: str
    private_key: str

@router.post("/generate", response_model=PGPResponse,
            summary="Generate PGP key pair",
            response_description="Returns a pair of PGP keys")
async def generate_pgp_key(request: PGPRequest):
    """
    Generate a PGP key pair with the specified parameters.
    
    - **name**: Full name for the key
    - **email**: Email address for the key
    - **key_length**: Key length in bits (minimum 2048)
    - **passphrase**: Optional passphrase to encrypt the private key
    - **comment**: Optional comment for the key
    - **expiry_days**: Optional expiry time in days
    """
    try:
        public_key, private_key = generator.generate_keypair(
            name=request.name,
            email=request.email,
            key_length=request.key_length,
            passphrase=request.passphrase,
            comment=request.comment,
            expiry_days=request.expiry_days
        )
        
        return PGPResponse(
            public_key=public_key,
            private_key=private_key
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
