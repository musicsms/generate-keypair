from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field, model_validator, ValidationError
from typing import Optional, Literal
from services.ssh_service import SSHService

router = APIRouter()
generator = SSHService()

class SSHKeyRequest(BaseModel):
    key_type: Literal["rsa", "ed25519"] = Field(..., description="Type of SSH key to generate")
    key_size: Optional[int] = Field(None, description="Key size in bits (required for RSA)")
    comment: Optional[str] = Field(None, description="Comment to add to the public key")
    password: Optional[str] = Field(None, min_length=8, description="Optional password to encrypt the private key")

    @model_validator(mode="before")
    @classmethod
    def validate_fields(cls, values):
        # Validate key_type
        key_type = values.get("key_type")
        if not isinstance(key_type, str):
            raise ValueError("Key type must be a string")
        key_type = key_type.lower()
        if key_type not in ["rsa", "ed25519"]:
            raise ValueError("Key type must be 'rsa' or 'ed25519'")
        values["key_type"] = key_type

        # Validate key_size for RSA
        key_size = values.get("key_size")
        if key_type == "rsa":
            if key_size is None:
                raise ValueError("Key size is required for RSA keys")
            if not isinstance(key_size, int):
                raise ValueError("Key size must be an integer")
            if key_size < 2048 or key_size > 4096:
                raise ValueError("RSA key size must be between 2048 and 4096 bits")
        elif key_type == "ed25519" and key_size is not None:
            raise ValueError("Key size is not applicable for Ed25519 keys")

        # Validate comment
        comment = values.get("comment")
        if comment is not None and not isinstance(comment, str):
            raise ValueError("Comment must be a string")

        # Validate password
        password = values.get("password")
        if password is not None:
            if not isinstance(password, str):
                raise ValueError("Password must be a string")
            if len(password) < 8:
                raise ValueError("Password must be at least 8 characters long")

        return values

class SSHKeyResponse(BaseModel):
    public_key: str
    private_key: str

@router.post("/generate", response_model=SSHKeyResponse,
            summary="Generate SSH key pair",
            response_description="Returns a pair of SSH keys")
async def generate_ssh_keys(request: SSHKeyRequest):
    """
    Generate an SSH key pair with the specified parameters.
    
    - **key_type**: Type of SSH key to generate ("rsa" or "ed25519")
    - **key_size**: Key size in bits (required for RSA, must be >= 2048)
    - **comment**: Optional comment to add to the public key
    - **password**: Optional password to encrypt the private key
    """
    try:
        public_key, private_key = generator.generate_keypair(
            key_type=request.key_type,
            key_size=request.key_size,
            comment=request.comment,
            password=request.password
        )
        
        return SSHKeyResponse(
            public_key=public_key,
            private_key=private_key
        )
    except ValidationError as e:
        raise HTTPException(status_code=422, detail=e.errors())
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
