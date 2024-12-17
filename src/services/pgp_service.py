import gnupg
from typing import Dict
import tempfile
import os
import shutil

class PGPService:
    def __init__(self):
        # Create a temporary directory for GPG home
        self.gnupghome = tempfile.mkdtemp()
        # Initialize GPG with specific options
        self.gpg = gnupg.GPG(
            gnupghome=self.gnupghome,
            use_agent=False,
            options=['--no-tty']
        )

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
        Returns: Dictionary containing public key, private key, fingerprint, and user ID
        """
        # Validate required fields
        if not name or not email:
            raise ValueError("Name and email are required for PGP key generation")
        if not passphrase:
            raise ValueError("Passphrase is required for PGP key generation")

        # Build user ID string
        user_id = name
        if comment:
            user_id += f" ({comment})"
        user_id += f" <{email}>"

        # Create key input data
        key_input = {
            'key_type': key_type,
            'key_length': key_length,
            'subkey_type': subkey_type,
            'subkey_length': subkey_length,
            'name_real': name,
            'name_email': email,
            'passphrase': passphrase,
            'expire_date': expire_date,
        }

        # Only add comment if it's provided
        if comment:
            key_input['name_comment'] = comment

        # Generate key
        print(f"\nGenerating key for user ID: {user_id}")
        key = self.gpg.gen_key(self.gpg.gen_key_input(**key_input))
        
        if not key.fingerprint:
            raise ValueError("Failed to generate PGP key pair")

        # Export public key
        public_key = self.gpg.export_keys(key.fingerprint, armor=True)
        if not public_key:
            raise ValueError("Failed to export public key")

        # Export private key
        private_key = self.gpg.export_keys(
            key.fingerprint,
            secret=True,
            armor=True,
            passphrase=passphrase
        )
        if not private_key:
            raise ValueError("Failed to export private key")

        # Get key info
        keys = self.gpg.list_keys()
        key_info = next((k for k in keys if k['fingerprint'] == key.fingerprint), None)
        
        if not key_info:
            raise ValueError("Could not find generated key in keyring")

        # Get the actual user ID from the key
        actual_uid = key_info['uids'][0] if key_info.get('uids') else user_id

        return {
            "public_key": public_key,
            "private_key": private_key,
            "fingerprint": key.fingerprint,
            "user_id": actual_uid
        }

    def __del__(self):
        # Clean up the temporary directory
        if hasattr(self, 'gnupghome') and os.path.exists(self.gnupghome):
            try:
                shutil.rmtree(self.gnupghome, ignore_errors=True)
            except Exception:
                pass  # Ignore cleanup errors
