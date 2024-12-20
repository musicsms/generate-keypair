import pytest
from fastapi.testclient import TestClient

def test_generate_ssh_rsa_success(client: TestClient):
    """Test successful SSH RSA key generation"""
    response = client.post("/api/v1/ssh/generate",
        json={
            "key_type": "rsa",
            "key_size": 2048,
            "comment": "test@example.com",
            "password": None
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert "private_key" in data
    assert "public_key" in data
    assert data["private_key"].startswith("-----BEGIN RSA PRIVATE KEY-----")
    assert "ssh-rsa" in data["public_key"]

def test_generate_ssh_ed25519_success(client: TestClient):
    """Test successful SSH Ed25519 key generation"""
    response = client.post("/api/v1/ssh/generate",
        json={
            "key_type": "ed25519",
            "comment": "test@example.com",
            "password": None
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert "private_key" in data
    assert "public_key" in data
    assert "ssh-ed25519" in data["public_key"]

def test_generate_ssh_with_password(client: TestClient):
    """Test SSH key generation with password protection"""
    response = client.post("/api/v1/ssh/generate",
        json={
            "key_type": "rsa",
            "key_size": 2048,
            "comment": "test@example.com",
            "password": "strongpassword123"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert "private_key" in data
    assert "public_key" in data
    assert data["private_key"].startswith("-----BEGIN RSA PRIVATE KEY-----")
    assert "ENCRYPTED" in data["private_key"]

def test_generate_ssh_invalid_key_type(client: TestClient):
    """Test SSH key generation with invalid key type"""
    response = client.post("/api/v1/ssh/generate",
        json={
            "key_type": "invalid",
            "key_size": 2048,
            "comment": "test@example.com",
            "password": None
        }
    )
    assert response.status_code == 422

def test_generate_ssh_invalid_key_size(client: TestClient):
    """Test SSH key generation with invalid key size"""
    response = client.post("/api/v1/ssh/generate",
        json={
            "key_type": "rsa",
            "key_size": 1024,  # Too small
            "comment": "test@example.com",
            "password": None
        }
    )
    assert response.status_code == 422

def test_generate_ssh_special_characters(client: TestClient):
    """Test SSH key generation with special characters in comment"""
    response = client.post("/api/v1/ssh/generate",
        json={
            "key_type": "rsa",
            "key_size": 2048,
            "comment": "test+special@example.com",
            "password": None
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert "private_key" in data
    assert "public_key" in data

def test_generate_ssh_missing_fields(client: TestClient):
    """Test SSH key generation with missing fields"""
    response = client.post("/api/v1/ssh/generate",
        json={}
    )
    assert response.status_code == 422

def test_generate_ssh_invalid_request_type(client: TestClient):
    """Test SSH key generation with invalid request type"""
    response = client.post("/api/v1/ssh/generate",
        json={
            "key_type": "rsa",
            "key_size": "invalid",
            "comment": "test@example.com",
            "password": None
        }
    )
    assert response.status_code == 422
