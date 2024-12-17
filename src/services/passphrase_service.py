import secrets
import string
from typing import List

class PasswordService:
    def __init__(self):
        self.uppercase_letters = string.ascii_uppercase
        self.lowercase_letters = string.ascii_lowercase
        self.digits = string.digits
        self.special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"

    def generate_password(self, 
                        length: int = 16,
                        use_uppercase: bool = True,
                        use_lowercase: bool = True,
                        use_digits: bool = True,
                        use_special: bool = True,
                        excluded_chars: str = "") -> str:
        """
        Generate a secure password with customizable options
        
        Args:
            length: Length of the password
            use_uppercase: Include uppercase letters
            use_lowercase: Include lowercase letters
            use_digits: Include numbers
            use_special: Include special characters
            excluded_chars: Characters to exclude from generation
        
        Returns:
            Generated password as string
        """
        # Create character pool based on selected options
        char_pool = ""
        if use_uppercase:
            char_pool += ''.join(c for c in self.uppercase_letters if c not in excluded_chars)
        if use_lowercase:
            char_pool += ''.join(c for c in self.lowercase_letters if c not in excluded_chars)
        if use_digits:
            char_pool += ''.join(c for c in self.digits if c not in excluded_chars)
        if use_special:
            char_pool += ''.join(c for c in self.special_chars if c not in excluded_chars)
            
        if not char_pool:
            # Default to lowercase if no options selected or all chars excluded
            char_pool = ''.join(c for c in self.lowercase_letters if c not in excluded_chars)
            
        if not char_pool:
            raise ValueError("No characters available for password generation after exclusions")
            
        # Generate password ensuring at least one character from each selected type
        password = []
        
        # Add one character from each selected type (if available after exclusions)
        if use_uppercase and any(c not in excluded_chars for c in self.uppercase_letters):
            available_chars = [c for c in self.uppercase_letters if c not in excluded_chars]
            password.append(secrets.choice(available_chars))
            
        if use_lowercase and any(c not in excluded_chars for c in self.lowercase_letters):
            available_chars = [c for c in self.lowercase_letters if c not in excluded_chars]
            password.append(secrets.choice(available_chars))
            
        if use_digits and any(c not in excluded_chars for c in self.digits):
            available_chars = [c for c in self.digits if c not in excluded_chars]
            password.append(secrets.choice(available_chars))
            
        if use_special and any(c not in excluded_chars for c in self.special_chars):
            available_chars = [c for c in self.special_chars if c not in excluded_chars]
            password.append(secrets.choice(available_chars))
            
        # Fill the rest with random characters from the pool
        while len(password) < length:
            password.append(secrets.choice(char_pool))
            
        # Shuffle the password
        secrets.SystemRandom().shuffle(password)
        
        return ''.join(password)
