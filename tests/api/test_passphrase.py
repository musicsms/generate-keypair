import pytest
from fastapi.testclient import TestClient
import uuid

def test_generate_passphrase_success(client: TestClient, test_headers):
    """Test successful passphrase generation with default parameters"""
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
        headers={"X-Test-IP": f"test-ip-{uuid.uuid4()}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "passwords" in data
    assert len(data["passwords"]) == 1
    assert len(data["passwords"][0]) == 16

def test_generate_multiple_passphrases(client: TestClient, test_headers):
    """Test generating multiple passphrases"""
    response = client.post("/api/v1/passphrase/generate",
        json={
            "length": 16,
            "use_digits": True,
            "use_special": True,
            "use_uppercase": True,
            "use_lowercase": True,
            "excluded_chars": "",
            "count": 5
        },
        headers={"X-Test-IP": f"test-ip-{uuid.uuid4()}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "passwords" in data
    assert len(data["passwords"]) == 5
    # Verify all passwords are unique
    assert len(set(data["passwords"])) == 5
    # Verify length of each password
    assert all(len(password) == 16 for password in data["passwords"])

def test_generate_passphrase_min_length(client: TestClient, test_headers):
    """Test passphrase generation with minimum allowed length"""
    response = client.post("/api/v1/passphrase/generate",
        json={
            "length": 8,
            "use_digits": True,
            "use_special": True,
            "use_uppercase": True,
            "use_lowercase": True,
            "excluded_chars": "",
            "count": 1
        },
        headers={"X-Test-IP": f"test-ip-{uuid.uuid4()}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "passwords" in data
    assert len(data["passwords"]) == 1
    assert len(data["passwords"][0]) == 8

def test_generate_passphrase_max_length(client: TestClient, test_headers):
    """Test passphrase generation with maximum allowed length"""
    response = client.post("/api/v1/passphrase/generate",
        json={
            "length": 128,
            "use_digits": True,
            "use_special": True,
            "use_uppercase": True,
            "use_lowercase": True,
            "excluded_chars": "",
            "count": 1
        },
        headers={"X-Test-IP": f"test-ip-{uuid.uuid4()}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "passwords" in data
    assert len(data["passwords"]) == 1
    assert len(data["passwords"][0]) == 128

def test_generate_passphrase_invalid_length(client: TestClient, test_headers):
    """Test passphrase generation with invalid length"""
    # Below minimum
    response = client.post("/api/v1/passphrase/generate",
        json={
            "length": 7,
            "use_digits": True,
            "use_special": True,
            "use_uppercase": True,
            "use_lowercase": True,
            "excluded_chars": "",
            "count": 1
        },
        headers={"X-Test-IP": f"test-ip-{uuid.uuid4()}"}
    )
    assert response.status_code == 422  # Validation error

    # Above maximum
    response = client.post("/api/v1/passphrase/generate",
        json={
            "length": 129,
            "use_digits": True,
            "use_special": True,
            "use_uppercase": True,
            "use_lowercase": True,
            "excluded_chars": "",
            "count": 1
        },
        headers={"X-Test-IP": f"test-ip-{uuid.uuid4()}"}
    )
    assert response.status_code == 422  # Validation error

def test_generate_passphrase_invalid_count(client: TestClient, test_headers):
    """Test passphrase generation with invalid count"""
    # Below minimum
    response = client.post("/api/v1/passphrase/generate",
        json={
            "length": 16,
            "use_digits": True,
            "use_special": True,
            "use_uppercase": True,
            "use_lowercase": True,
            "excluded_chars": "",
            "count": 0
        },
        headers={"X-Test-IP": f"test-ip-{uuid.uuid4()}"}
    )
    assert response.status_code == 422  # Validation error

    # Above maximum
    response = client.post("/api/v1/passphrase/generate",
        json={
            "length": 16,
            "use_digits": True,
            "use_special": True,
            "use_uppercase": True,
            "use_lowercase": True,
            "excluded_chars": "",
            "count": 101
        },
        headers={"X-Test-IP": f"test-ip-{uuid.uuid4()}"}
    )
    assert response.status_code == 422  # Validation error

def test_generate_passphrase_character_sets(client: TestClient, test_headers):
    """Test passphrase generation with different character set combinations"""
    # Only lowercase
    response = client.post("/api/v1/passphrase/generate",
        json={
            "length": 16,
            "use_digits": False,
            "use_special": False,
            "use_uppercase": False,
            "use_lowercase": True,
            "excluded_chars": "",
            "count": 1
        },
        headers={"X-Test-IP": f"test-ip-{uuid.uuid4()}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "passwords" in data
    password = data["passwords"][0]
    assert password.islower()

def test_generate_passphrase_excluded_chars(client: TestClient, test_headers):
    """Test passphrase generation with excluded characters"""
    excluded_chars = "aeiou0123"
    response = client.post("/api/v1/passphrase/generate",
        json={
            "length": 16,
            "use_digits": True,
            "use_special": True,
            "use_uppercase": True,
            "use_lowercase": True,
            "excluded_chars": excluded_chars,
            "count": 1
        },
        headers={"X-Test-IP": f"test-ip-{uuid.uuid4()}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "passwords" in data
    password = data["passwords"][0]
    assert not any(c in excluded_chars for c in password)

def test_generate_passphrase_invalid_request(client: TestClient, test_headers):
    """Test passphrase generation with invalid request data"""
    # No character types selected
    response = client.post("/api/v1/passphrase/generate",
        json={
            "length": 16,
            "use_digits": False,
            "use_special": False,
            "use_uppercase": False,
            "use_lowercase": False,
            "excluded_chars": "",
            "count": 1
        },
        headers={"X-Test-IP": f"test-ip-{uuid.uuid4()}"}
    )
    assert response.status_code == 400  # Bad request
