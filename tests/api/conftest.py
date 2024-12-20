import pytest
from fastapi.testclient import TestClient
from api.main import app
from api.middleware import RateLimitMiddleware

@pytest.fixture(autouse=True)
def clear_rate_limits():
    """Clear rate limits before each test"""
    # Find the rate limit middleware instance
    for middleware in app.user_middleware:  # Use user_middleware instead of middleware
        if isinstance(middleware.cls, RateLimitMiddleware):
            middleware.cls.requests.clear()  # Clear the requests dictionary
    yield

@pytest.fixture
def client():
    """Create a test client instance"""
    return TestClient(app)

@pytest.fixture
def valid_rsa_key():
    """Generate a valid RSA key for testing CSR generation"""
    from services.rsa_service import RSAService
    _, private_key = RSAService().generate_keypair(key_size=2048)
    return private_key

@pytest.fixture
def test_headers():
    """Headers for testing, including rate limit bypass"""
    return {
        "X-Test-IP": "test-ip-123"
    }
