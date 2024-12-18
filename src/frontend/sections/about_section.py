import streamlit as st

def render_about_section():
    st.markdown("### ℹ️ About Secure Key Generator")
    st.markdown("""
    This application helps you generate various types of secure cryptographic keys and passwords.
    
    #### Features:
    * 🔑 **Password Generator**: Create strong, customizable passwords
    * 🔐 **RSA Keys**: Generate RSA key pairs for encryption and signing
    * 🔒 **SSH Keys**: Generate SSH key pairs for secure authentication
    * 🔏 **PGP Keys**: Create PGP keys for encryption and digital signatures
    * 📜 **CSR Generator**: Create Certificate Signing Requests for SSL/TLS certificates
    
    #### Security Notes:
    * All keys are generated using cryptographically secure methods
    * Private keys and passwords are never stored or transmitted
    * Always store your private keys and passwords securely
    * Use strong passphrases to protect your private keys
    
    #### Best Practices:
    * Keep private keys secret and never share them
    * Use different keys for different purposes
    * Regularly rotate your passwords and keys
    * Back up your keys securely
    * Never share your CSR private key with anyone
    * Verify certificate details before submitting CSR
    """)
