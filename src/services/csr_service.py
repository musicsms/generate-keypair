from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from typing import Optional, List
import ipaddress

class CSRService:
    @staticmethod
    def is_ip_address(value: str) -> bool:
        """
        Check if a string is a valid IP address (IPv4 or IPv6)
        
        Args:
            value: String to check
            
        Returns:
            True if the string is an IP address, False otherwise
        """
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

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
        password: Optional[str] = None,
        subject_alternative_names: Optional[List[str]] = None
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
            subject_alternative_names: List of Subject Alternative Names (SANs)
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
            
            # Add Subject Alternative Names if provided
            san_list = []
            
            # Add Common Name as SAN if it's an IP address
            # The Common Name is already in the subject, but modern browsers expect
            # all valid identifiers to be in the SAN extension as well
            if CSRService.is_ip_address(common_name):
                san_list.append(x509.IPAddress(ipaddress.ip_address(common_name)))
            else:
                san_list.append(x509.DNSName(common_name))
            
            # Add additional SANs if provided
            if subject_alternative_names and len(subject_alternative_names) > 0:
                for name in subject_alternative_names:
                    if name and name.strip():
                        name = name.strip()
                        # Skip if it's identical to common_name (already added)
                        if name == common_name:
                            continue
                        # Check if the name is an IP address
                        if CSRService.is_ip_address(name):
                            san_list.append(x509.IPAddress(ipaddress.ip_address(name)))
                        else:
                            san_list.append(x509.DNSName(name))
            
            if san_list:
                builder = builder.add_extension(
                    x509.SubjectAlternativeName(san_list),
                    critical=False
                )
            
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
