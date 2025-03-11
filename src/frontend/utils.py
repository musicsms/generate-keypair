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
    """Generate a filename for a key with timestamp"""
    timestamp = datetime.datetime.now().strftime("%Y%m%d")
    
    if key_type.lower() == "ssh-rsa":
        base = f"ssh_rsa_{timestamp}"
    elif key_type.lower() == "ssh-ed25519":
        base = f"ssh_ed25519_{timestamp}"
    elif key_type.lower() == "pgp":
        base = f"pgp_keypair_{timestamp}"
    elif key_type.lower() == "csr":
        base = f"csr_{timestamp}"
    else:  # RSA
        base = f"rsa_keypair_{timestamp}"
    
    return f"{base}.pub" if is_public else f"{base}.key"

def download_button(content: Union[str, bytes], filename: str, button_text: str, mime_type: str = "text/plain") -> None:
    """
    Create a download button for text content or binary data
    
    Args:
        content: String or bytes content to download
        filename: Name of the file to download
        button_text: Text to display on the button
        mime_type: MIME type of the content
    """
    if isinstance(content, str):
        b64 = base64.b64encode(content.encode()).decode()
    else:
        # Content is already bytes
        b64 = base64.b64encode(content).decode()
        
    href = f'<a href="data:{mime_type};base64,{b64}" download="{filename}">{button_text}</a>'
    st.markdown(href, unsafe_allow_html=True)
