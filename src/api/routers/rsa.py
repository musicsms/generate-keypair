from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field, model_validator, ValidationError
from typing import Optional
from services.rsa_service import RSAService

router = APIRouter()
generator = RSAService()

class RSAKeyRequest(BaseModel):
    key_size: int = Field(..., ge=2048, le=4096, description="Size of the RSA key in bits")
    password: Optional[str] = Field(None, min_length=8, description="Optional password to encrypt the private key")
    public_exponent: int = Field(65537, description="Public exponent for RSA key generation")

    @model_validator(mode="before")
    @classmethod
    def validate_fields(cls, values):
        # Validate key_size
        key_size = values.get("key_size")
        if not isinstance(key_size, int):
            raise ValueError("Key size must be an integer")
        if key_size < 2048 or key_size > 4096:
            raise ValueError("Key size must be between 2048 and 4096 bits")

        # Validate public_exponent
        public_exponent = values.get("public_exponent")
        if not isinstance(public_exponent, int):
            raise ValueError("Public exponent must be an integer")
        if public_exponent not in [3, 65537]:  # Common values
            raise ValueError("Public exponent must be 3 or 65537")

        # Validate password
        password = values.get("password")
        if password is not None:
            if not isinstance(password, str):
                raise ValueError("Password must be a string")
            if len(password) < 8:
                raise ValueError("Password must be at least 8 characters long")

        return values

class RSAKeyResponse(BaseModel):
    public_key: str
    private_key: str

@router.post("/generate", response_model=RSAKeyResponse,
            summary="Generate RSA key pair",
            response_description="Returns a pair of RSA keys in PEM format")
async def generate_rsa_keys(request: RSAKeyRequest):
    """
    Generate an RSA key pair with the specified parameters.
    
    - **key_size**: Size of the RSA key in bits (minimum 2048)
    - **password**: Optional password to encrypt the private key
    - **public_exponent**: Public exponent for RSA key generation (default: 65537)
    """
    try:
        public_key, private_key = generator.generate_keypair(
            key_size=request.key_size,
            public_exponent=request.public_exponent,
            password=request.password
        )
        
        return RSAKeyResponse(
            public_key=public_key,
            private_key=private_key
        )
    except ValidationError as e:
        raise HTTPException(status_code=422, detail=e.errors())
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
