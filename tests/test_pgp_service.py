import unittest
from src.services.pgp_service import PGPService

class TestPGPService(unittest.TestCase):
    def setUp(self):
        self.service = PGPService()

    def test_generate_rsa_keypair(self):
        keys = self.service.generate_keypair(
            name="Test User",
            email="test@example.com",
            passphrase="testpassphrase",
            key_type="RSA",
            key_length=2048
        )
        
        # Check key format
        self.assertIn("BEGIN PGP PUBLIC KEY BLOCK", keys["public_key"])
        self.assertIn("BEGIN PGP PRIVATE KEY BLOCK", keys["private_key"])
        self.assertTrue(keys["fingerprint"])

    def test_generate_keypair_with_comment(self):
        keys = self.service.generate_keypair(
            name="Test User",
            email="test@example.com",
            passphrase="testpassphrase",
            comment="Test Key",
            key_type="RSA",
            key_length=2048
        )
        
        # Check if comment is in the public key
        self.assertIn("Test Key", keys["public_key"])

    def test_generate_keypair_with_expiry(self):
        keys = self.service.generate_keypair(
            name="Test User",
            email="test@example.com",
            passphrase="testpassphrase",
            key_type="RSA",
            key_length=2048,
            expire_date="365"  # 1 year
        )
        
        self.assertTrue(keys["fingerprint"])

    def test_missing_passphrase(self):
        with self.assertRaises(ValueError):
            self.service.generate_keypair(
                name="Test User",
                email="test@example.com",
                passphrase=None
            )

    def test_missing_required_fields(self):
        with self.assertRaises(ValueError):
            self.service.generate_keypair(
                name="",
                email="test@example.com",
                passphrase="testpassphrase"
            )
