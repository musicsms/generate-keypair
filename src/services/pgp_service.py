import gnupg
from typing import Dict
import tempfile
import os

class PGPService:
    def __init__(self):
        # Create a temporary directory for GPG home
        self.gnupghome = tempfile.mkdtemp()
        self.gpg = gnupg.GPG(gnupghome=self.gnupghome)

    def generate_keypair(
        self,
        name: str,
        email: str,
        passphrase: str = None,
        comment: str = "",
        key_type: str = "RSA",
        key_length: int = 2048,
        subkey_type: str = "RSA",
        subkey_length: int = 2048,
        expire_date: str = "0"
    ) -> Dict[str, str]:
        """
        Generate a PGP keypair with customizable parameters
        Returns: Dictionary containing public key, private key, and fingerprint
        """
        if not passphrase:
            raise ValueError("Passphrase is required for PGP key generation")

        # Generate key with passphrase
        input_data = self.gpg.gen_key_input(
            key_type=key_type,
            key_length=key_length,
            subkey_type=subkey_type,
            subkey_length=subkey_length,
            name_real=name,
            name_comment=comment if comment else None,
            name_email=email,
            passphrase=passphrase,
            expire_date=expire_date
        )

        key = self.gpg.gen_key(input_data)
        if not key.fingerprint:
            raise ValueError("Failed to generate PGP key pair")
        
        # Export public key in ASCII armor format
        public_key = self.gpg.export_keys(
            key.fingerprint,
            armor=True
        )
        
        # Export private key with encryption
        # For GnuPG >= 2.1, we need to provide the passphrase for both export and encryption
        private_key = self.gpg.export_keys(
            key.fingerprint,
            secret=True,
            armor=True,
            passphrase=passphrase,
            expect_passphrase=False  # Don't expect a second passphrase prompt
        )
        
        # Verify we got both keys
        if not public_key or not private_key:
            raise ValueError("Failed to export keys")
        
        # Basic validation of key format
        if "BEGIN PGP PUBLIC KEY BLOCK" not in public_key:
            raise ValueError("Invalid public key format")
        if "BEGIN PGP PRIVATE KEY BLOCK" not in private_key:
            raise ValueError("Invalid private key format")
        
        return {
            "public_key": public_key,
            "private_key": private_key,
            "fingerprint": key.fingerprint
        }

    def __del__(self):
        # Cleanup temporary directory
        try:
            import shutil
            shutil.rmtree(self.gnupghome)
        except:
            pass
