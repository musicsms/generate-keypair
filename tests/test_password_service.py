import pytest
from services.passphrase_service import PasswordService
import string

@pytest.fixture
def password_service():
    return PasswordService()

def test_generate_single_password(password_service):
    """Test generating a single password with default settings"""
    passwords = password_service.generate_password(length=16)
    assert len(passwords) == 1
    password = passwords[0]
    assert len(password) == 16
    # Verify it contains at least one of each character type
    assert any(c in string.ascii_lowercase for c in password)
    assert any(c in string.ascii_uppercase for c in password)
    assert any(c in string.digits for c in password)
    assert any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)

def test_generate_multiple_passwords(password_service):
    """Test generating multiple passwords"""
    # Test minimum count
    passwords = password_service.generate_password(length=16, count=1)
    assert len(passwords) == 1

    # Test medium count
    passwords = password_service.generate_password(length=16, count=10)
    assert len(passwords) == 10
    # Verify all passwords are unique
    assert len(set(passwords)) == 10

    # Test maximum count
    passwords = password_service.generate_password(length=16, count=100)
    assert len(passwords) == 100
    # Verify all passwords are unique
    assert len(set(passwords)) == 100

def test_password_character_types(password_service):
    """Test password generation with different character type combinations"""
    # Only lowercase
    passwords = password_service.generate_password(
        length=16,
        use_lowercase=True,
        use_uppercase=False,
        use_digits=False,
        use_special=False
    )
    password = passwords[0]
    assert all(c in string.ascii_lowercase for c in password)

    # Only uppercase
    passwords = password_service.generate_password(
        length=16,
        use_lowercase=False,
        use_uppercase=True,
        use_digits=False,
        use_special=False
    )
    password = passwords[0]
    assert all(c in string.ascii_uppercase for c in password)

    # Only digits
    passwords = password_service.generate_password(
        length=16,
        use_lowercase=False,
        use_uppercase=False,
        use_digits=True,
        use_special=False
    )
    password = passwords[0]
    assert all(c in string.digits for c in password)

    # Only special characters
    passwords = password_service.generate_password(
        length=16,
        use_lowercase=False,
        use_uppercase=False,
        use_digits=False,
        use_special=True
    )
    password = passwords[0]
    assert all(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)

def test_excluded_characters(password_service):
    """Test password generation with excluded characters"""
    excluded = "aeiou0123"
    passwords = password_service.generate_password(
        length=16,
        excluded_chars=excluded
    )
    password = passwords[0]
    assert not any(c in excluded for c in password)

def test_invalid_parameters(password_service):
    """Test password generation with invalid parameters"""
    # Test invalid length
    with pytest.raises(ValueError, match="Password length must be at least 8 characters"):
        password_service.generate_password(length=7)

    # Test invalid count
    with pytest.raises(ValueError, match="Number of passwords must be between 1 and 100"):
        password_service.generate_password(count=0)
    with pytest.raises(ValueError, match="Number of passwords must be between 1 and 100"):
        password_service.generate_password(count=101)

    # Test no character types selected
    with pytest.raises(ValueError, match="At least one character type must be selected"):
        password_service.generate_password(
            use_lowercase=False,
            use_uppercase=False,
            use_digits=False,
            use_special=False
        )

    # Test all characters excluded
    with pytest.raises(ValueError, match="No characters available after exclusions"):
        password_service.generate_password(
            use_lowercase=True,
            use_uppercase=False,
            use_digits=False,
            use_special=False,
            excluded_chars=string.ascii_lowercase
        )

def test_password_uniqueness(password_service):
    """Test that generated passwords are unique"""
    # Generate a large number of passwords
    passwords = password_service.generate_password(
        length=16,
        count=50
    )
    # Verify all passwords are unique
    assert len(passwords) == len(set(passwords))

    # Test with limited character set
    passwords = password_service.generate_password(
        length=16,
        count=10,
        use_lowercase=True,
        use_uppercase=False,
        use_digits=False,
        use_special=False
    )
    assert len(passwords) == len(set(passwords))
