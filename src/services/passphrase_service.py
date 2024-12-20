import string
import secrets
from typing import List, Optional

class PasswordService:
    def __init__(self):
        self.lowercase_chars = string.ascii_lowercase
        self.uppercase_chars = string.ascii_uppercase
        self.digit_chars = string.digits
        self.special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"

    def generate_password(
        self,
        length: int = 16,
        use_lowercase: bool = True,
        use_uppercase: bool = True,
        use_digits: bool = True,
        use_special: bool = True,
        excluded_chars: Optional[str] = None,
        count: int = 1
    ) -> List[str]:
        """
        Generate one or more passwords with the specified options
        Returns: List of generated passwords
        """
        if length < 8:
            raise ValueError("Password length must be at least 8 characters")
            
        if count < 1 or count > 100:
            raise ValueError("Number of passwords must be between 1 and 100")

        # Build character set based on options
        chars = ""
        if use_lowercase:
            chars += self.lowercase_chars
        if use_uppercase:
            chars += self.uppercase_chars
        if use_digits:
            chars += self.digit_chars
        if use_special:
            chars += self.special_chars

        if not chars:
            raise ValueError("At least one character type must be selected")

        # Remove excluded characters
        if excluded_chars:
            chars = "".join(c for c in chars if c not in excluded_chars)

        if not chars:
            raise ValueError("No characters available after exclusions")

        # Ensure we have enough unique characters
        if len(chars) < 4:
            raise ValueError("Not enough unique characters available")

        passwords = []
        max_attempts = count * 100  # Prevent infinite loop
        attempts = 0

        while len(passwords) < count and attempts < max_attempts:
            attempts += 1
            # Generate password
            password = ""
            
            # If using multiple character types, ensure at least one of each
            remaining_length = length
            if use_lowercase and any(c in chars for c in self.lowercase_chars):
                password += secrets.choice([c for c in self.lowercase_chars if c in chars])
                remaining_length -= 1
            if use_uppercase and any(c in chars for c in self.uppercase_chars):
                password += secrets.choice([c for c in self.uppercase_chars if c in chars])
                remaining_length -= 1
            if use_digits and any(c in chars for c in self.digit_chars):
                password += secrets.choice([c for c in self.digit_chars if c in chars])
                remaining_length -= 1
            if use_special and any(c in chars for c in self.special_chars):
                password += secrets.choice([c for c in self.special_chars if c in chars])
                remaining_length -= 1

            # Fill the rest with random characters
            password += "".join(secrets.choice(chars) for _ in range(remaining_length))
            
            # Shuffle the password
            password_list = list(password)
            secrets.SystemRandom().shuffle(password_list)
            password = "".join(password_list)

            if password not in passwords:  # Ensure uniqueness
                passwords.append(password)

        if len(passwords) < count:
            raise ValueError("Could not generate enough unique passwords with the given constraints")

        return passwords
