import pytest
from fastapi.testclient import TestClient
import re

def test_generate_csr_success(client: TestClient, test_private_key):
    """Test successful CSR generation with all fields"""
    response = client.post("/api/v1/csr/generate",
        json={
            "private_key_pem": test_private_key,
            "common_name": "test.example.com",
            "country": "US",
            "state": "California",
            "locality": "San Francisco",
            "organization": "Test Corp",
            "organizational_unit": "IT",
            "email": "test@example.com"
        }
    )
    assert response.status_code == 200
    assert "-----BEGIN CERTIFICATE REQUEST-----" in response.json()["csr"]

def test_generate_csr_minimal_fields(client: TestClient, test_private_key):
    """Test CSR generation with only required fields"""
    response = client.post("/api/v1/csr/generate",
        json={
            "private_key_pem": test_private_key,
            "common_name": "test.example.com"
        }
    )
    assert response.status_code == 200
    assert "-----BEGIN CERTIFICATE REQUEST-----" in response.json()["csr"]

def test_generate_csr_with_password(client: TestClient, test_encrypted_private_key):
    """Test CSR generation with password-protected private key"""
    response = client.post("/api/v1/csr/generate",
        json={
            "private_key_pem": test_encrypted_private_key,
            "password": "test123",
            "common_name": "test.example.com"
        }
    )
    assert response.status_code == 200
    assert "-----BEGIN CERTIFICATE REQUEST-----" in response.json()["csr"]

def test_generate_csr_invalid_private_key(client: TestClient):
    """Test CSR generation with invalid private key"""
    response = client.post("/api/v1/csr/generate",
        json={
            "private_key_pem": "invalid-key",
            "common_name": "test.example.com"
        }
    )
    assert response.status_code == 400
    assert "Invalid private key format" in response.json()["detail"]

def test_generate_csr_missing_common_name(client: TestClient, test_private_key):
    """Test CSR generation without common name"""
    response = client.post("/api/v1/csr/generate",
        json={
            "private_key_pem": test_private_key
        }
    )
    assert response.status_code == 422

def test_generate_csr_invalid_email(client: TestClient, test_private_key):
    """Test CSR generation with invalid email"""
    response = client.post("/api/v1/csr/generate",
        json={
            "private_key_pem": test_private_key,
            "common_name": "test.example.com",
            "email": "invalid-email"
        }
    )
    assert response.status_code == 422

def test_generate_csr_invalid_country_code(client: TestClient, test_private_key):
    """Test CSR generation with invalid country code"""
    response = client.post("/api/v1/csr/generate",
        json={
            "private_key_pem": test_private_key,
            "common_name": "test.example.com",
            "country": "INVALID"
        }
    )
    assert response.status_code == 422

def test_generate_csr_special_characters(client: TestClient, test_private_key):
    """Test CSR generation with special characters in fields"""
    response = client.post("/api/v1/csr/generate",
        json={
            "private_key_pem": test_private_key,
            "common_name": "test.example.com",
            "organization": "Test & Corp",
            "organizational_unit": "IT/DevOps"
        }
    )
    assert response.status_code == 200
    assert "-----BEGIN CERTIFICATE REQUEST-----" in response.json()["csr"]
