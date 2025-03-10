"""
CSR Validation Service for parsing and validating Certificate Signing Requests
"""
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
from cryptography.x509.oid import NameOID, ExtensionOID
import base64
import re
from typing import Dict, Any, List, Optional, Tuple

class CSRValidationService:
    """
    Service for validating and parsing Certificate Signing Requests (CSRs)
    """
    
    @staticmethod
    def validate_csr_format(csr_text: str) -> bool:
        """
        Check if the CSR text is in the correct PEM format
        
        Args:
            csr_text: The CSR text to validate
            
        Returns:
            True if the format is valid, False otherwise
        """
        # Check for begin and end markers
        if not ("-----BEGIN CERTIFICATE REQUEST-----" in csr_text and 
                "-----END CERTIFICATE REQUEST-----" in csr_text):
            return False
        
        # Basic structure check - should be base64 content between markers
        try:
            # Extract the base64 part
            b64_content = re.search(
                r"-----BEGIN CERTIFICATE REQUEST-----\s*(.+?)\s*-----END CERTIFICATE REQUEST-----",
                csr_text, 
                re.DOTALL
            )
            
            if not b64_content:
                return False
                
            # Remove any whitespace/newlines from the base64 content
            b64_clean = re.sub(r'\s+', '', b64_content.group(1))
            
            # Try to decode the base64 content
            base64.b64decode(b64_clean)
            return True
        except Exception:
            return False
    
    @staticmethod
    def parse_csr(csr_text: str) -> Dict[str, Any]:
        """
        Parse a CSR and extract detailed information
        
        Args:
            csr_text: The CSR in PEM format
            
        Returns:
            Dictionary containing detailed CSR information
            
        Raises:
            ValueError: If the CSR is invalid or can't be parsed
        """
        try:
            # Load the CSR
            csr = x509.load_pem_x509_csr(csr_text.encode('utf-8'), default_backend())
            
            # Extract basic information
            result = {
                "valid": csr.is_signature_valid,
                "version": csr.version.name
            }
            
            # Extract subject information
            subject = csr.subject
            subject_info = {}
            
            # Common attributes to extract
            oid_map = {
                NameOID.COMMON_NAME: "common_name",
                NameOID.COUNTRY_NAME: "country",
                NameOID.STATE_OR_PROVINCE_NAME: "state",
                NameOID.LOCALITY_NAME: "locality",
                NameOID.ORGANIZATION_NAME: "organization",
                NameOID.ORGANIZATIONAL_UNIT_NAME: "organizational_unit",
                NameOID.EMAIL_ADDRESS: "email_address",
                NameOID.DOMAIN_COMPONENT: "domain_component",
                NameOID.SURNAME: "surname",
                NameOID.GIVEN_NAME: "given_name",
                NameOID.TITLE: "title",
                NameOID.SERIAL_NUMBER: "serial_number",
                NameOID.PSEUDONYM: "pseudonym",
                NameOID.GENERATION_QUALIFIER: "generation_qualifier",
            }
            
            for attr in subject:
                oid = attr.oid
                if oid in oid_map:
                    field_name = oid_map[oid]
                    if field_name in subject_info:
                        # Handle multiple values for the same field
                        if isinstance(subject_info[field_name], list):
                            subject_info[field_name].append(attr.value)
                        else:
                            subject_info[field_name] = [subject_info[field_name], attr.value]
                    else:
                        subject_info[field_name] = attr.value
                else:
                    # Handle unknown OIDs
                    subject_info[f"oid_{oid.dotted_string}"] = attr.value
            
            result["subject"] = subject_info
            
            # Extract public key information
            public_key = csr.public_key()
            key_info = {}
            
            if isinstance(public_key, rsa.RSAPublicKey):
                key_info["algorithm"] = "RSA"
                key_info["key_size"] = public_key.key_size
                key_info["public_exponent"] = public_key.public_numbers().e
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                key_info["algorithm"] = "ECC"
                key_info["key_size"] = public_key.key_size
                key_info["curve"] = public_key.curve.name
            elif isinstance(public_key, dsa.DSAPublicKey):
                key_info["algorithm"] = "DSA"
                key_info["key_size"] = public_key.key_size
            else:
                key_info["algorithm"] = "Unknown"
            
            result["public_key"] = key_info
            
            # Extract signature algorithm
            sig_alg = csr.signature_algorithm_oid
            result["signature_algorithm"] = sig_alg._name
            
            # Calculate fingerprints
            fingerprints = {}
            for hash_class in [hashes.SHA1, hashes.SHA256, hashes.SHA384, hashes.SHA512]:
                hash_name = hash_class.name
                digest = csr.public_bytes(encoding=x509.encoding.PEM)
                fingerprint = hash_class()
                fingerprint.update(digest)
                fingerprints[hash_name] = fingerprint.finalize().hex()
            
            result["fingerprints"] = fingerprints
            
            # Extract extensions
            extensions = {}
            
            # Try to get SubjectAlternativeName
            try:
                san_extension = csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                san_value = san_extension.value
                
                sans = []
                for name in san_value:
                    if isinstance(name, x509.DNSName):
                        sans.append({"type": "DNS", "value": name.value})
                    elif isinstance(name, x509.IPAddress):
                        sans.append({"type": "IP", "value": str(name.value)})
                    elif isinstance(name, x509.RFC822Name):
                        sans.append({"type": "Email", "value": name.value})
                    elif isinstance(name, x509.UniformResourceIdentifier):
                        sans.append({"type": "URI", "value": name.value})
                    else:
                        sans.append({"type": "Other", "value": str(name)})
                
                extensions["subject_alternative_name"] = sans
            except x509.ExtensionNotFound:
                pass
            
            # Try to get other common extensions
            ext_oids = [
                (ExtensionOID.KEY_USAGE, "key_usage"),
                (ExtensionOID.EXTENDED_KEY_USAGE, "extended_key_usage"),
                (ExtensionOID.BASIC_CONSTRAINTS, "basic_constraints")
            ]
            
            for oid, name in ext_oids:
                try:
                    ext = csr.extensions.get_extension_for_oid(oid)
                    if hasattr(ext.value, 'oid'):
                        extensions[name] = [o._name for o in ext.value]
                    elif hasattr(ext.value, '__iter__') and not isinstance(ext.value, str):
                        extensions[name] = list(ext.value)
                    else:
                        extensions[name] = str(ext.value)
                except x509.ExtensionNotFound:
                    pass
            
            result["extensions"] = extensions
            
            return result
            
        except Exception as e:
            raise ValueError(f"Failed to parse CSR: {str(e)}")
    
    @staticmethod
    def get_formatted_subject_display(subject_info: Dict[str, Any]) -> List[Tuple[str, str]]:
        """
        Format the subject information for display
        
        Args:
            subject_info: Dictionary of subject information
            
        Returns:
            List of tuples with formatted field names and values
        """
        display_names = {
            "common_name": "Common Name (CN)",
            "country": "Country (C)",
            "state": "State/Province (ST)",
            "locality": "Locality (L)",
            "organization": "Organization (O)",
            "organizational_unit": "Organizational Unit (OU)",
            "email_address": "Email Address",
            "domain_component": "Domain Component (DC)",
            "surname": "Surname",
            "given_name": "Given Name",
            "title": "Title",
            "serial_number": "Serial Number",
            "pseudonym": "Pseudonym",
            "generation_qualifier": "Generation Qualifier",
        }
        
        result = []
        
        # First add the standard fields in a specific order if they exist
        priority_fields = [
            "common_name", "email_address", "organization", "organizational_unit", 
            "locality", "state", "country"
        ]
        
        for field in priority_fields:
            if field in subject_info:
                display_name = display_names.get(field, field)
                result.append((display_name, subject_info[field]))
        
        # Then add any remaining fields
        for field, value in subject_info.items():
            if field not in priority_fields:
                display_name = display_names.get(field, field)
                result.append((display_name, value))
        
        return result