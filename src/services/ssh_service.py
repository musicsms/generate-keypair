import paramiko
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    PrivateFormat,
    BestAvailableEncryption,
    NoEncryption
)
from typing import Tuple
import io
import base64

class SSHService:
    @staticmethod
    def generate_keypair(
        key_type: str = "rsa",
        key_size: int = 2048,
        comment: str = "",
        password: str = None
    ) -> Tuple[str, str]:
        """
        Generate an SSH keypair with customizable parameters
        Returns: (public_key, private_key)
        """
        key = None
        
        if key_type.lower() == "rsa":
            key = paramiko.RSAKey.generate(key_size)
            # Get private key
            priv_file = io.StringIO()
            key.write_private_key(priv_file, password=password.encode() if password else None)
            private_key = priv_file.getvalue()
            
            # Get public key in OpenSSH format
            public_key = f"{key.get_name()} {key.get_base64()} {comment}"
            
        elif key_type.lower() == "ed25519":
            # Generate Ed25519 key using cryptography
            private_key_obj = ed25519.Ed25519PrivateKey.generate()
            public_key_obj = private_key_obj.public_key()
            
            # Get the raw key bytes
            private_bytes = private_key_obj.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.OpenSSH,
                encryption_algorithm=BestAvailableEncryption(password.encode()) if password else NoEncryption()
            )
            public_bytes = public_key_obj.public_bytes(
                encoding=Encoding.OpenSSH,
                format=PublicFormat.OpenSSH
            )
            
            private_key = private_bytes.decode()
            public_key = f"{public_bytes.decode()} {comment}"
        else:
            raise ValueError("Invalid key type")

        return public_key, private_key
