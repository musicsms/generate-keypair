import unittest
from src.services.ssh_service import SSHService

class TestSSHService(unittest.TestCase):
    def setUp(self):
        self.service = SSHService()

    def test_generate_rsa_keypair(self):
        public_key, private_key = self.service.generate_keypair(
            key_type="rsa",
            key_size=2048,
            comment="test@example.com"
        )
        
        # Check public key format
        self.assertTrue(public_key.startswith("ssh-rsa "))
        self.assertIn("test@example.com", public_key)
        
        # Check private key format
        self.assertTrue(private_key.startswith("-----BEGIN"))
        self.assertTrue(private_key.endswith("-----END"))

    def test_generate_ed25519_keypair(self):
        public_key, private_key = self.service.generate_keypair(
            key_type="ed25519",
            comment="test@example.com"
        )
        
        # Check public key format
        self.assertTrue(public_key.startswith("ssh-ed25519 "))
        self.assertIn("test@example.com", public_key)
        
        # Check private key format
        self.assertTrue(private_key.startswith("-----BEGIN"))
        self.assertTrue(private_key.endswith("-----END"))

    def test_generate_rsa_keypair_with_password(self):
        public_key, private_key = self.service.generate_keypair(
            key_type="rsa",
            key_size=2048,
            comment="test@example.com",
            password="testpassword"
        )
        
        # Check for encryption indicators in private key
        self.assertIn("ENCRYPTED", private_key)

    def test_invalid_key_type(self):
        with self.assertRaises(ValueError):
            self.service.generate_keypair(key_type="invalid")
