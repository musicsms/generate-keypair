import unittest
from src.services.csr_service import CSRService
from src.services.rsa_service import RSAService
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend

class TestCSRService(unittest.TestCase):
    def setUp(self):
        # Generate a test key pair for CSR creation
        self.rsa_service = RSAService()
        self.public_key, self.private_key = self.rsa_service.generate_keypair(key_size=2048)

    def test_generate_basic_csr(self):
        # Create a basic CSR with only common name
        csr_pem = CSRService.generate_csr(
            private_key_pem=self.private_key,
            common_name="test.example.com"
        )

        # Verify the CSR is valid PEM
        self.assertTrue(csr_pem.startswith('-----BEGIN CERTIFICATE REQUEST-----'))
        self.assertTrue(csr_pem.endswith('-----END CERTIFICATE REQUEST-----\n'))

        # Load and verify CSR
        csr = x509.load_pem_x509_csr(csr_pem.encode())
        self.assertTrue(csr.is_signature_valid)
        
        # Check common name
        common_name = next(
            attr.value for attr in csr.subject 
            if attr.oid == NameOID.COMMON_NAME
        )
        self.assertEqual(common_name, "test.example.com")

        # Verify that the public key in CSR matches our original public key
        csr_public_key = csr.public_key()
        original_public_key = serialization.load_pem_public_key(
            self.public_key.encode(),
            backend=default_backend()
        )
        
        # Compare public key numbers
        self.assertEqual(
            csr_public_key.public_numbers().n,
            original_public_key.public_numbers().n
        )
        self.assertEqual(
            csr_public_key.public_numbers().e,
            original_public_key.public_numbers().e
        )

    def test_generate_full_csr(self):
        # Create CSR with all fields
        csr_pem = CSRService.generate_csr(
            private_key_pem=self.private_key,
            common_name="test.example.com",
            country="US",
            state="California",
            locality="San Francisco",
            organization="Test Corp",
            organizational_unit="IT Department",
            email="test@example.com"
        )

        # Load CSR
        csr = x509.load_pem_x509_csr(csr_pem.encode())
        self.assertTrue(csr.is_signature_valid)

        # Helper function to get attribute value
        def get_attr(oid):
            return next((attr.value for attr in csr.subject if attr.oid == oid), None)

        # Verify all fields
        self.assertEqual(get_attr(NameOID.COMMON_NAME), "test.example.com")
        self.assertEqual(get_attr(NameOID.COUNTRY_NAME), "US")
        self.assertEqual(get_attr(NameOID.STATE_OR_PROVINCE_NAME), "California")
        self.assertEqual(get_attr(NameOID.LOCALITY_NAME), "San Francisco")
        self.assertEqual(get_attr(NameOID.ORGANIZATION_NAME), "Test Corp")
        self.assertEqual(get_attr(NameOID.ORGANIZATIONAL_UNIT_NAME), "IT Department")
        self.assertEqual(get_attr(NameOID.EMAIL_ADDRESS), "test@example.com")

    def test_generate_csr_with_encrypted_key(self):
        # Generate an encrypted private key
        _, encrypted_key = self.rsa_service.generate_keypair(
            key_size=2048,
            password="testpassword123"
        )

        # Create CSR using encrypted key
        csr_pem = CSRService.generate_csr(
            private_key_pem=encrypted_key,
            common_name="test.example.com",
            password="testpassword123"
        )

        # Verify CSR
        csr = x509.load_pem_x509_csr(csr_pem.encode())
        self.assertTrue(csr.is_signature_valid)

    def test_generate_csr_with_different_key_sizes(self):
        # Test CSR generation with different RSA key sizes
        for key_size in [2048, 3072, 4096]:
            with self.subTest(key_size=key_size):
                # Generate key pair with specific size
                public_key, private_key = self.rsa_service.generate_keypair(key_size=key_size)
                
                # Create CSR
                csr_pem = CSRService.generate_csr(
                    private_key_pem=private_key,
                    common_name=f"test-{key_size}.example.com"
                )
                
                # Verify CSR
                csr = x509.load_pem_x509_csr(csr_pem.encode())
                self.assertTrue(csr.is_signature_valid)
                
                # Verify key size
                csr_public_key = csr.public_key()
                self.assertIsInstance(csr_public_key, rsa.RSAPublicKey)
                self.assertEqual(csr_public_key.key_size, key_size)

    def test_invalid_private_key(self):
        # Test with invalid private key PEM
        with self.assertRaises(ValueError):
            CSRService.generate_csr(
                private_key_pem="invalid-key",
                common_name="test.example.com"
            )

    def test_wrong_password_for_encrypted_key(self):
        # Generate an encrypted private key
        _, encrypted_key = self.rsa_service.generate_keypair(
            key_size=2048,
            password="correctpassword"
        )

        # Try to create CSR with wrong password
        with self.assertRaises(ValueError):
            CSRService.generate_csr(
                private_key_pem=encrypted_key,
                common_name="test.example.com",
                password="wrongpassword"
            )

    def test_missing_required_fields(self):
        # Test missing common name
        with self.assertRaises(ValueError):
            CSRService.generate_csr(
                private_key_pem=self.private_key,
                common_name=""
            )

        # Test empty private key
        with self.assertRaises(ValueError):
            CSRService.generate_csr(
                private_key_pem="",
                common_name="test.example.com"
            )

if __name__ == '__main__':
    unittest.main()
