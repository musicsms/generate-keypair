from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from typing import Optional
from cryptography.exceptions import InvalidKey

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
            try:
                private_key = serialization.load_pem_private_key(
                    private_key_pem.encode(),
                    password=password.encode() if password else None,
                    backend=default_backend()
                )
            except ValueError:
                if "encrypted" in private_key_pem and not password:
                    raise ValueError("Password required for encrypted private key")
                elif password and "encrypted" not in private_key_pem:
                    raise ValueError("Password provided for unencrypted private key")
                else:
                    raise ValueError("Invalid private key format")
            except Exception as e:
                raise ValueError(f"Error loading private key: {str(e)}")

            # Build CSR subject
            subject = []
            if common_name:
                subject.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))
            if country:
                subject.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country))
            if state:
                subject.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state))
            if locality:
                subject.append(x509.NameAttribute(NameOID.LOCALITY_NAME, locality))
            if organization:
                subject.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))
            if organizational_unit:
                subject.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit))
            if email:
                subject.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email))

            # Generate CSR
            csr = x509.CertificateSigningRequestBuilder().subject_name(
                x509.Name(subject)
            ).sign(
                private_key,
                hashes.SHA256(),
                default_backend()
            )

            # Return CSR in PEM format
            return csr.public_bytes(serialization.Encoding.PEM).decode()

        except ValueError as e:
            raise e
        except Exception as e:
            raise ValueError(f"Error generating CSR: {str(e)}")
