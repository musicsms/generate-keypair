from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field, model_validator
from typing import List
from services.passphrase_service import PasswordService

router = APIRouter()
generator = PasswordService()

class PassphraseRequest(BaseModel):
    length: int = Field(..., ge=8, le=128, description="Length of the passphrase")
    use_digits: bool = Field(True, description="Include numbers in the passphrase")
    use_special: bool = Field(True, description="Include special characters")
    use_uppercase: bool = Field(True, description="Include uppercase letters")
    use_lowercase: bool = Field(True, description="Include lowercase letters")
    excluded_chars: str = Field("", description="Characters to exclude from generation")
    count: int = Field(1, ge=1, le=100, description="Number of passwords to generate")

    @model_validator(mode="before")
    @classmethod
    def validate_fields(cls, values):
        # Validate length
        length = values.get("length")
        if not isinstance(length, int):
            raise ValueError("Length must be an integer")
        if length < 8 or length > 128:
            raise ValueError("Length must be between 8 and 128")

        # Validate count
        count = values.get("count", 1)
        if not isinstance(count, int):
            raise ValueError("Count must be an integer")
        if count < 1 or count > 100:
            raise ValueError("Count must be between 1 and 100")

        # Validate boolean fields
        for field in ["use_digits", "use_special", "use_uppercase", "use_lowercase"]:
            value = values.get(field)
            if not isinstance(value, bool):
                raise ValueError(f"{field} must be a boolean")

        # Validate excluded_chars
        excluded_chars = values.get("excluded_chars")
        if not isinstance(excluded_chars, str):
            raise ValueError("Excluded characters must be a string")

        return values

class PassphraseResponse(BaseModel):
    passwords: List[str]

@router.post("/generate", response_model=PassphraseResponse,
            summary="Generate secure passphrases",
            response_description="Returns a list of secure passphrases")
async def generate_passphrase(request: PassphraseRequest):
    """
    Generate one or more secure passphrases based on the specified parameters.
    
    - **length**: Length of the passphrase (8-128 characters)
    - **use_digits**: Include numbers in the passphrase
    - **use_special**: Include special characters
    - **use_uppercase**: Include uppercase letters
    - **use_lowercase**: Include lowercase letters
    - **excluded_chars**: Characters to exclude from generation
    - **count**: Number of passwords to generate (1-100)
    """
    # Validate that at least one character set is enabled
    if not any([request.use_digits, request.use_special, request.use_uppercase, request.use_lowercase]):
        raise HTTPException(
            status_code=400,
            detail="At least one character set must be enabled"
        )
    try:
        passwords = generator.generate_password(
            length=request.length,
            use_digits=request.use_digits,
            use_special=request.use_special,
            use_uppercase=request.use_uppercase,
            use_lowercase=request.use_lowercase,
            excluded_chars=request.excluded_chars,
            count=request.count
        )
        
        return PassphraseResponse(
            passwords=passwords
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
