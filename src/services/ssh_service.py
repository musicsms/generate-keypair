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
        if key_type.lower() == "rsa":
            # Generate RSA key
            key = paramiko.RSAKey.generate(bits=key_size)
            
            # Get private key
            priv_file = io.StringIO()
            key.write_private_key(priv_file, password=password.encode() if password else None)
            private_key = priv_file.getvalue()
            
            # Get public key in OpenSSH format
            public_key = f"ssh-rsa {key.get_base64()} {comment}"
            
            return public_key, private_key
            
        elif key_type.lower() == "ed25519":
            # Generate Ed25519 key
            private_key_obj = ed25519.Ed25519PrivateKey.generate()
            public_key_obj = private_key_obj.public_key()
            
            # Export private key
            private_bytes = private_key_obj.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.OpenSSH,
                encryption_algorithm=BestAvailableEncryption(password.encode()) if password else NoEncryption()
            )
            private_key = private_bytes.decode()
            
            # Export public key
            public_bytes = public_key_obj.public_bytes(
                encoding=Encoding.Raw,
                format=PublicFormat.Raw
            )
            
            # Format OpenSSH public key
            key_type_bytes = b"ssh-ed25519"
            encoded_key = base64.b64encode(key_type_bytes + b"\x00\x00\x00 " + public_bytes).decode()
            public_key = f"ssh-ed25519 {encoded_key} {comment}"
            
            return public_key, private_key
        else:
            raise ValueError(f"Unsupported key type: {key_type}. Supported types are: rsa, ed25519")
