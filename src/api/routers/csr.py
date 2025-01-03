from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field, model_validator, EmailStr, ValidationError
from typing import Optional
from services.csr_service import CSRService
import re

router = APIRouter()
generator = CSRService()

class CSRRequest(BaseModel):
    private_key_pem: str = Field(..., description="PEM-formatted private key")
    common_name: str = Field(..., description="Common Name (CN) for the certificate")
    country: Optional[str] = Field(None, min_length=2, max_length=2, description="Two-letter country code")
    state: Optional[str] = Field(None, description="State or province")
    locality: Optional[str] = Field(None, description="City or locality")
    organization: Optional[str] = Field(None, description="Organization name")
    organizational_unit: Optional[str] = Field(None, description="Organizational unit name")
    email: Optional[EmailStr] = Field(None, description="Email address")
    password: Optional[str] = Field(None, description="Optional password for private key")
    subject_alternative_names: Optional[Union[str, List[str]]] = Field(None, description="Comma-separated SANs")


    @model_validator(mode="before")
    @classmethod
    def validate_fields(cls, values):
        # Validate private_key_pem
        private_key = values.get("private_key_pem")
        if not isinstance(private_key, str):
            raise ValueError("Private key must be a string")
        if not re.match(r"-----BEGIN .*PRIVATE KEY-----.*-----END .*PRIVATE KEY-----", private_key, re.DOTALL):
            raise HTTPException(status_code=400, detail="Invalid private key format")

        # Validate common_name
        common_name = values.get("common_name")
        if not isinstance(common_name, str):
            raise ValueError("Common name must be a string")
        if not common_name:
            raise ValueError("Common name is required")

        # Validate country code
        country = values.get("country")
        if country is not None:
            if not isinstance(country, str):
                raise ValueError("Country code must be a string")
            if len(country) != 2:
                raise ValueError("Country code must be exactly 2 letters")
            values["country"] = country.upper()

        # Validate optional string fields
        for field in ["state", "locality", "organization", "organizational_unit", "password"]:
            value = values.get(field)
            if value is not None and not isinstance(value, str):
                raise ValueError(f"{field} must be a string")

        return values

class CSRResponse(BaseModel):
    csr: str

@router.post("/generate", response_model=CSRResponse,
            summary="Generate Certificate Signing Request",
            response_description="Returns a PEM-formatted CSR")
async def generate_csr(request: CSRRequest):
    """
    Generate a Certificate Signing Request (CSR) with the specified parameters.
    
    - **private_key_pem**: PEM-formatted private key
    - **common_name**: Common Name (CN) for the certificate
    - **country**: Optional two-letter country code
    - **state**: Optional state or province
    - **locality**: Optional city or locality
    - **organization**: Optional organization name
    - **organizational_unit**: Optional organizational unit name
    - **email**: Optional email address
    - **password**: Optional password for private key
    """
    try:
        csr = generator.generate_csr(
            private_key_pem=request.private_key_pem,
            common_name=request.common_name,
            country=request.country,
            state=request.state,
            locality=request.locality,
            organization=request.organization,
            organizational_unit=request.organizational_unit,
            email=request.email,
            password=request.password,
            subject_alternative_names=request.subject_alternative_names
        )
        
        return CSRResponse(
            csr=csr
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
