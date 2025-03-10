import streamlit as st
import sys
import os

# Add the parent directory to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sections import (
    render_password_section,
    render_rsa_section,
    render_ssh_section,
    render_pgp_section,
    render_csr_section,
    render_csr_sign_section,
    render_about_section
)
from styles import get_styles

def set_page_config():
    st.set_page_config(
        page_title="Secure Key Generator",
        page_icon="🔐",
        layout="wide",
        initial_sidebar_state="expanded"
    )

def main():
    set_page_config()
    
    st.title("🔐 Secure Key Generator")
    st.markdown(get_styles(), unsafe_allow_html=True)

    tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs([
        "🔑 Password Generator",
        "🔐 RSA Keys",
        "🔒 SSH Keys",
        "🔏 PGP Keys",
        "📜 CSR",
        "🔏 CSR Signing",
        "ℹ️ About"
    ])

    with tab1:
        render_password_section()
    with tab2:
        render_rsa_section()
    with tab3:
        render_ssh_section()
    with tab4:
        render_pgp_section()
    with tab5:
        render_csr_section()
    with tab6:
        render_csr_sign_section()
    with tab7:
        render_about_section()

if __name__ == "__main__":
    main()