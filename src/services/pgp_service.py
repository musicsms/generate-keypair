import gnupg
from typing import Dict, Tuple, Optional
import tempfile
import os
import shutil
from datetime import datetime, timedelta

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
        key_length: int = 2048,
        passphrase: Optional[str] = None,
        comment: Optional[str] = None,
        expiry_days: Optional[int] = None
    ) -> Tuple[str, str]:
        """
        Generate a PGP keypair with customizable parameters
        Returns: Tuple containing (public key, private key)
        """
        # Validate required fields
        if not name or not email:
            raise ValueError("Name and email are required for PGP key generation")

        # Build user ID string
        user_id = name
        if comment:
            user_id += f" ({comment})"
        user_id += f" <{email}>"

        # Calculate expiry date
        expire_date = "0"
        if expiry_days:
            expire_date = str(expiry_days)

        # Create key input data
        key_input = {
            'key_type': 'RSA',
            'key_length': key_length,
            'subkey_type': 'RSA',
            'subkey_length': key_length,
            'name_real': name,
            'name_email': email,
            'passphrase': passphrase if passphrase else '',
            'expire_date': expire_date,
        }

        # Only add comment if it's provided
        if comment:
            key_input['name_comment'] = comment

        # Generate key
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
            passphrase=passphrase if passphrase else ''
        )
        if not private_key:
            raise ValueError("Failed to export private key")

        return public_key, private_key

    def __del__(self):
        # Clean up temporary directory
        if hasattr(self, 'gnupghome') and os.path.exists(self.gnupghome):
            shutil.rmtree(self.gnupghome)
