import pytest
import logging
from datetime import datetime
from fastapi.testclient import TestClient
from src.api.main import app
from src.api.middleware import RateLimitMiddleware
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)

@pytest.fixture
def client():
    with TestClient(app) as client:
        yield client

@pytest.fixture
def test_private_key():
    """Generate a test RSA private key"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pem.decode()

@pytest.fixture
def test_encrypted_private_key():
    """Generate a test password-protected RSA private key"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(b"test123")
    )
    return pem.decode()
