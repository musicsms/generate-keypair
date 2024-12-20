import pytest
from fastapi.testclient import TestClient

def test_generate_pgp_success(client: TestClient):
    """Test successful PGP key generation with default parameters"""
    response = client.post("/api/v1/pgp/generate",
        json={
            "name": "Test User",
            "email": "test@example.com",
            "key_length": 2048,
            "passphrase": "strongpassphrase123"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert "private_key" in data
    assert "public_key" in data
    assert data["private_key"].startswith("-----BEGIN PGP PRIVATE KEY BLOCK-----")
    assert data["public_key"].startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----")

def test_generate_pgp_with_comment(client: TestClient):
    """Test PGP key generation with comment"""
    response = client.post("/api/v1/pgp/generate",
        json={
            "name": "Test User",
            "email": "test@example.com",
            "key_length": 2048,
            "passphrase": "strongpassphrase123",
            "comment": "Test Key"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert "private_key" in data
    assert "public_key" in data

def test_generate_pgp_with_expiry(client: TestClient):
    """Test PGP key generation with expiry"""
    response = client.post("/api/v1/pgp/generate",
        json={
            "name": "Test User",
            "email": "test@example.com",
            "key_length": 2048,
            "passphrase": "strongpassphrase123",
            "expiry_days": 365
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert "private_key" in data
    assert "public_key" in data

def test_generate_pgp_invalid_key_length(client: TestClient):
    """Test PGP key generation with invalid key length"""
    response = client.post("/api/v1/pgp/generate",
        json={
            "name": "Test User",
            "email": "test@example.com",
            "key_length": 1024,  # Too small
            "passphrase": "strongpassphrase123"
        }
    )
    assert response.status_code == 422

def test_generate_pgp_invalid_email(client: TestClient):
    """Test PGP key generation with invalid email"""
    response = client.post("/api/v1/pgp/generate",
        json={
            "name": "Test User",
            "email": "invalid-email",
            "key_length": 2048,
            "passphrase": "strongpassphrase123"
        }
    )
    assert response.status_code == 422

def test_generate_pgp_missing_required_fields(client: TestClient):
    """Test PGP key generation with missing required fields"""
    response = client.post("/api/v1/pgp/generate",
        json={
            "name": "Test User",
            "key_length": 2048
        }
    )
    assert response.status_code == 422

def test_generate_pgp_weak_passphrase(client: TestClient):
    """Test PGP key generation with weak passphrase"""
    response = client.post("/api/v1/pgp/generate",
        json={
            "name": "Test User",
            "email": "test@example.com",
            "key_length": 2048,
            "passphrase": "weak"
        }
    )
    assert response.status_code == 422
