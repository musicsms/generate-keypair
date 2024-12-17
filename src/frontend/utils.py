import streamlit as st
from typing import Union
import base64
import random
import string
import datetime

def generate_random_string(length: int = 8) -> str:
    """Generate a random string of fixed length"""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def get_key_filename(key_type: str, is_public: bool = False) -> str:
    """Generate a filename for a key with timestamp and random string"""
    timestamp = datetime.datetime.now().strftime("%Y%m%d")
    random_str = generate_random_string(6)
    
    if key_type.lower() == "ssh-rsa":
        base = f"id_rsa_{timestamp}_{random_str}"
    elif key_type.lower() == "ssh-ed25519":
        base = f"id_ed25519_{timestamp}_{random_str}"
    elif key_type.lower() == "pgp":
        base = f"pgp_key_{timestamp}_{random_str}"
    else:  # RSA
        base = f"rsa_key_{timestamp}_{random_str}"
    
    return f"{base}.pub" if is_public else base

def download_button(content: str, filename: str, button_text: str, mime_type: str = "text/plain") -> None:
    """
    Create a download button for text content
    """
    b64 = base64.b64encode(content.encode()).decode()
    href = f'<a href="data:{mime_type};base64,{b64}" download="{filename}">{button_text}</a>'
    st.markdown(href, unsafe_allow_html=True)
