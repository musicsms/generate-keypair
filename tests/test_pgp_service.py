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
            key_length=2048
        )
        assert isinstance(keys, tuple)
        assert len(keys) == 2
        assert "BEGIN PGP PUBLIC KEY BLOCK" in keys[0]
        assert "BEGIN PGP PRIVATE KEY BLOCK" in keys[1]

    def test_generate_keypair_with_comment(self):
        name = "Test User"
        comment = "Test Key"
        email = "test@example.com"

        keys = self.service.generate_keypair(
            name=name,
            email=email,
            passphrase="testpassphrase",
            comment=comment,
            key_length=2048
        )
        assert isinstance(keys, tuple)
        assert len(keys) == 2
        assert "BEGIN PGP PUBLIC KEY BLOCK" in keys[0]
        assert "BEGIN PGP PRIVATE KEY BLOCK" in keys[1]

    def test_generate_keypair_with_expiry(self):
        keys = self.service.generate_keypair(
            name="Test User",
            email="test@example.com",
            passphrase="testpassphrase",
            key_length=2048,
            expiry_days=365  # 1 year
        )
        assert isinstance(keys, tuple)
        assert len(keys) == 2
        assert "BEGIN PGP PUBLIC KEY BLOCK" in keys[0]
        assert "BEGIN PGP PRIVATE KEY BLOCK" in keys[1]

    def test_missing_required_fields(self):
        with self.assertRaises(ValueError):
            self.service.generate_keypair(
                name="",  # Empty name
                email="test@example.com",
                passphrase="testpassphrase"
            )
