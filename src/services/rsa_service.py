from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from typing import Tuple

class RSAService:
    @staticmethod
    def generate_keypair(
        key_size: int = 2048,
        public_exponent: int = 65537,
        password: str = None
    ) -> Tuple[str, str]:
        """
        Generate an RSA keypair with customizable parameters
        Returns: (public_key, private_key) as PEM strings
        """
        if key_size < 2048:
            raise ValueError("Key size must be at least 2048 bits for security")

        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=public_exponent,
            key_size=key_size,
            backend=default_backend()
        )

        # Get public key
        public_key = private_key.public_key()

        # Serialize private key
        encryption_algorithm = (
            serialization.BestAvailableEncryption(password.encode())
            if password else serialization.NoEncryption()
        )
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )

        # Serialize public key
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return public_pem.decode(), private_pem.decode()
