import unittest
from src.services.rsa_service import RSAService

class TestRSAService(unittest.TestCase):
    def setUp(self):
        self.service = RSAService()

    def test_generate_keypair(self):
        public_key, private_key = self.service.generate_keypair(key_size=2048)
        
        # Check key format
        self.assertTrue(public_key.startswith("-----BEGIN PUBLIC KEY-----"))
        self.assertTrue(public_key.endswith("-----END PUBLIC KEY-----\n"))
        self.assertTrue(private_key.startswith("-----BEGIN PRIVATE KEY-----"))
        self.assertTrue(private_key.endswith("-----END PRIVATE KEY-----\n"))

    def test_generate_keypair_with_password(self):
        public_key, private_key = self.service.generate_keypair(
            key_size=2048,
            password="testpassword"
        )
        
        # Check for encryption indicators
        self.assertTrue(private_key.startswith("-----BEGIN ENCRYPTED PRIVATE KEY-----"))
        self.assertTrue(private_key.endswith("-----END ENCRYPTED PRIVATE KEY-----\n"))

    def test_invalid_key_size(self):
        with self.assertRaises(ValueError):
            self.service.generate_keypair(key_size=1024)  # Too small
