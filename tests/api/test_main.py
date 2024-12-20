import pytest
from fastapi.testclient import TestClient
from src.api.main import app, custom_openapi

client = TestClient(app)

def test_openapi_schema():
    """Test OpenAPI schema generation"""
    # First call should generate schema
    schema1 = custom_openapi()
    assert schema1 is not None
    assert schema1["info"]["title"] == "Secure Key Generator API"
    assert schema1["info"]["version"] == "1.0.0"
    
    # Second call should return cached schema
    schema2 = custom_openapi()
    assert schema2 is schema1  # Should return the same object

def test_cors_headers():
    """Test CORS headers are properly set"""
    response = client.options("/api/v1/passphrase/generate", 
        headers={
            "Origin": "http://example.com",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type",
        }
    )
    assert response.status_code == 200
    assert "access-control-allow-origin" in response.headers
    assert "access-control-allow-methods" in response.headers
    assert "access-control-allow-headers" in response.headers

def test_rate_limit_middleware():
    """Test rate limit middleware is properly configured"""
    response = client.post("/api/v1/passphrase/generate",
        json={
            "length": 16,
            "use_digits": True,
            "use_special": True,
            "use_uppercase": True,
            "use_lowercase": True,
            "excluded_chars": "",
            "count": 1
        },
        headers={"X-Test-IP": "test-ip-1"}
    )
    assert response.status_code == 200
    assert "X-RateLimit-Limit" in response.headers
    assert "X-RateLimit-Remaining" in response.headers
    assert "X-RateLimit-Reset" in response.headers

def test_404_handling():
    """Test handling of non-existent endpoints"""
    response = client.get("/non-existent-endpoint")
    assert response.status_code == 404
    assert response.json()["detail"] == "Not Found"

def test_method_not_allowed():
    """Test handling of incorrect HTTP methods"""
    response = client.get("/api/v1/passphrase/generate")
    assert response.status_code == 405
    assert response.json()["detail"] == "Method Not Allowed"
