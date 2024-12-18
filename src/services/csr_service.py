from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from typing import Optional

class CSRService:
    @staticmethod
    def generate_csr(
        private_key_pem: str,
        common_name: str,
        country: Optional[str] = None,
        state: Optional[str] = None,
        locality: Optional[str] = None,
        organization: Optional[str] = None,
        organizational_unit: Optional[str] = None,
        email: Optional[str] = None,
        password: Optional[str] = None
    ) -> str:
        """
        Generate a Certificate Signing Request (CSR) using a private key
        Args:
            private_key_pem: Private key in PEM format
            common_name: Common Name (CN) for the certificate
            country: Country (C) two-letter code
            state: State/Province (ST)
            locality: Locality (L)
            organization: Organization (O)
            organizational_unit: Organizational Unit (OU)
            email: Email Address
            password: Password if the private key is encrypted
        Returns:
            CSR in PEM format
        Raises:
            ValueError: If private_key_pem is invalid or common_name is empty
        """
        if not private_key_pem:
            raise ValueError("Private key is required")
        if not common_name:
            raise ValueError("Common Name (CN) is required")

        try:
            # Load private key
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode(),
                password=password.encode() if password else None,
                backend=default_backend()
            )
        except Exception as e:
            raise ValueError(f"Invalid private key: {str(e)}")

        # Prepare subject attributes
        attributes = []
        attributes.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))
        
        if country:
            attributes.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country))
        if state:
            attributes.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state))
        if locality:
            attributes.append(x509.NameAttribute(NameOID.LOCALITY_NAME, locality))
        if organization:
            attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))
        if organizational_unit:
            attributes.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit))
        if email:
            attributes.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email))

        try:
            # Create CSR
            builder = x509.CertificateSigningRequestBuilder()
            builder = builder.subject_name(x509.Name(attributes))
            
            csr = builder.sign(
                private_key=private_key,
                algorithm=hashes.SHA256(),
                backend=default_backend()
            )

            # Serialize CSR to PEM format
            csr_pem = csr.public_bytes(serialization.Encoding.PEM)
            return csr_pem.decode()
        except Exception as e:
            raise ValueError(f"Error creating CSR: {str(e)}")
