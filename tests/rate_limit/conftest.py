import pytest
import uuid
from datetime import datetime, timedelta
from unittest.mock import patch
from fastapi.testclient import TestClient
from src.api.main import app
from src.api.middleware import RateLimitMiddleware

# Fixed timestamp for deterministic testing
FIXED_TIMESTAMP = datetime(2024, 12, 20, 11, 43, 31).timestamp()

@pytest.fixture(autouse=True)
def mock_time():
    """Mock time.time() to return a fixed timestamp for deterministic testing"""
    with patch('time.time', return_value=FIXED_TIMESTAMP) as mock_time:
        yield mock_time

@pytest.fixture
def advance_time(mock_time):
    """Helper fixture to advance the mocked time"""
    def _advance(seconds):
        nonlocal mock_time
        mock_time.return_value += seconds
    return _advance

@pytest.fixture
def client():
    """Test client with isolated rate limit state"""
    with TestClient(app) as client:
        yield client

@pytest.fixture
def unique_ip():
    """Generate a unique IP for each test case"""
    return f"test-ip-{uuid.uuid4()}"

@pytest.fixture(autouse=True)
def reset_rate_limit():
    """Reset rate limit state before each test"""
    RateLimitMiddleware.reset_state()
    yield

@pytest.fixture
def rate_limit_config():
    """Rate limit configuration for tests"""
    return {
        'requests_per_minute': 100,
        'time_window': 60,  # seconds
    }

@pytest.fixture
def make_request(client):
    """Helper fixture to make requests with consistent parameters"""
    def _make_request(endpoint, ip, json_data):
        return client.post(
            endpoint,
            json=json_data,
            headers={"X-Test-IP": ip}
        )
    return _make_request
