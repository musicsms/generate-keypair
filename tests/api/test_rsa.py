import pytest
from fastapi.testclient import TestClient
import re
import uuid

def test_generate_rsa_success(client: TestClient):
    """Test successful RSA key generation with default parameters"""
    response = client.post("/api/v1/rsa/generate", json={
        "key_size": 2048,
        "password": None,
        "public_exponent": 65537
    })
    assert response.status_code == 200
    data = response.json()
    assert "public_key" in data
    assert "private_key" in data
    assert data["public_key"].startswith("-----BEGIN PUBLIC KEY-----")
    assert data["private_key"].startswith("-----BEGIN PRIVATE KEY-----")

def test_generate_rsa_with_password(client: TestClient):
    """Test RSA key generation with password protection"""
    response = client.post("/api/v1/rsa/generate", json={
        "key_size": 2048,
        "password": "strongpassword123",
        "public_exponent": 65537
    })
    assert response.status_code == 200
    data = response.json()
    assert data["private_key"].startswith("-----BEGIN ENCRYPTED PRIVATE KEY-----")

def test_generate_rsa_key_sizes(client: TestClient):
    """Test RSA key generation with different key sizes"""
    # Minimum key size
    response = client.post("/api/v1/rsa/generate", json={
        "key_size": 2048,
        "password": None,
        "public_exponent": 65537
    })
    assert response.status_code == 200

    # Maximum key size
    response = client.post("/api/v1/rsa/generate", json={
        "key_size": 4096,
        "password": None,
        "public_exponent": 65537
    })
    assert response.status_code == 200

def test_generate_rsa_invalid_key_size(client: TestClient):
    """Test RSA key generation with invalid key sizes"""
    # Below minimum
    response = client.post("/api/v1/rsa/generate", json={
        "key_size": 1024,
        "password": None,
        "public_exponent": 65537
    })
    assert response.status_code == 422  # Validation error

    # Above maximum
    response = client.post("/api/v1/rsa/generate", json={
        "key_size": 8192,
        "password": None,
        "public_exponent": 65537
    })
    assert response.status_code == 422  # Validation error

def test_generate_rsa_invalid_password(client: TestClient):
    """Test RSA key generation with invalid password"""
    # Password too short
    response = client.post("/api/v1/rsa/generate", json={
        "key_size": 2048,
        "password": "short",
        "public_exponent": 65537
    })
    assert response.status_code == 422  # Validation error

def test_generate_rsa_invalid_public_exponent(client: TestClient):
    """Test RSA key generation with invalid public exponent"""
    response = client.post("/api/v1/rsa/generate", json={
        "key_size": 2048,
        "password": None,
        "public_exponent": 65536  # Not a valid public exponent
    })
    assert response.status_code == 422  # Validation error

def test_generate_rsa_missing_fields(client: TestClient):
    """Test RSA key generation with missing required fields"""
    response = client.post("/api/v1/rsa/generate", json={
        "password": None,
        "public_exponent": 65537
    })
    assert response.status_code == 422  # Validation error

def test_generate_rsa_invalid_request_type(client: TestClient):
    """Test RSA key generation with invalid request data types"""
    response = client.post("/api/v1/rsa/generate", json={
        "key_size": "2048",  # Should be integer
        "password": None,
        "public_exponent": 65537
    })
    assert response.status_code == 422  # Validation error
