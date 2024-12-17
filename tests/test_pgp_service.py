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
        
        # Check user ID format
        expected_uid = "Test User <test@example.com>"
        self.assertEqual(expected_uid, keys["user_id"])

    def test_generate_keypair_with_comment(self):
        name = "Test User"
        comment = "Test Key"
        email = "test@example.com"
        
        keys = self.service.generate_keypair(
            name=name,
            email=email,
            passphrase="testpassphrase",
            comment=comment,
            key_type="RSA",
            key_length=2048
        )
        
        # Check key format
        self.assertIn("BEGIN PGP PUBLIC KEY BLOCK", keys["public_key"])
        self.assertIn("BEGIN PGP PRIVATE KEY BLOCK", keys["private_key"])
        self.assertTrue(keys["fingerprint"])
        
        # Check user ID format
        expected_uid = f"{name} ({comment}) <{email}>"
        self.assertEqual(expected_uid, keys["user_id"])

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
        self.assertIn("BEGIN PGP PUBLIC KEY BLOCK", keys["public_key"])
        self.assertIn("BEGIN PGP PRIVATE KEY BLOCK", keys["private_key"])

    def test_missing_required_fields(self):
        with self.assertRaises(ValueError):
            self.service.generate_keypair(
                name="",  # Empty name
                email="test@example.com",
                passphrase="testpassphrase"
            )
