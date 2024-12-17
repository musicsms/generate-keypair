import streamlit as st
from services.rsa_service import RSAService
from frontend.utils import download_button, get_key_filename

def render_rsa_section():
    st.markdown("### 🔑 RSA Key Generator")
    st.markdown("Generate RSA key pairs for general purpose cryptography.")
    
    with st.expander("RSA Key Options", expanded=True):
        col1, col2 = st.columns(2)
        
        with col1:
            key_size = st.select_slider(
                "Key Size (bits)",
                options=[2048, 3072, 4096],
                value=2048,
                help="Larger key sizes are more secure but slower",
                key="rsa_gen_key_size_select_slider"
            )
        
        with col2:
            password = st.text_input(
                "Password (Optional)",
                type="password",
                help="Optional password to encrypt the private key",
                key="rsa_gen_password_input"
            )
    
    if st.button("🔐 Generate RSA Key Pair", key="rsa_gen_create_button", use_container_width=True):
        try:
            service = RSAService()
            public_key, private_key = service.generate_keypair(
                key_size=key_size,
                password=password if password else None
            )
            
            # Generate filenames
            private_filename = get_key_filename("rsa")
            public_filename = get_key_filename("rsa", is_public=True)
            
            col1, col2 = st.columns(2)
            with col1:
                st.markdown("##### Private Key (Keep Secret!):")
                st.code(private_key, language="text")
                download_button(
                    private_key,
                    private_filename,
                    "⬇️ Download Private Key"
                )
            with col2:
                st.markdown("##### Public Key (Safe to Share):")
                st.code(public_key, language="text")
                download_button(
                    public_key,
                    public_filename,
                    "⬇️ Download Public Key"
                )
                
            st.warning("⚠️ Save your private key securely and never share it!")
        except Exception as e:
            st.error(f"⚠️ Error generating RSA keys: {str(e)}")
