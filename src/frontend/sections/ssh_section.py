import streamlit as st
from services.ssh_service import SSHService
from frontend.utils import download_button, get_key_filename

def render_ssh_section():
    st.markdown("### 🔒 SSH Key Generator")
    st.markdown("Generate secure SSH key pairs for authentication.")
    
    with st.expander("SSH Key Options", expanded=True):
        col1, col2 = st.columns(2)
        
        with col1:
            key_type = st.selectbox(
                "Key Type",
                options=["RSA", "Ed25519"],
                index=0,
                help="RSA is widely compatible, Ed25519 is newer and more secure",
                key="ssh_gen_key_type_select"
            )
            
            if key_type == "RSA":
                key_size = st.select_slider(
                    "Key Size (bits)",
                    options=[2048, 3072, 4096],
                    value=2048,
                    help="Larger key sizes are more secure but slower",
                    key="ssh_gen_key_size_select_slider"
                )
            else:
                key_size = 256  # Ed25519 has a fixed key size
        
        with col2:
            comment = st.text_input(
                "Key Comment",
                placeholder="e.g. username@hostname",
                help="Optional comment to identify this key",
                key="ssh_gen_comment_input"
            )
            password = st.text_input(
                "Password (Optional)",
                type="password",
                help="Optional password to encrypt the private key",
                key="ssh_gen_password_input"
            )
    
    if st.button("🔑 Generate SSH Key Pair", key="ssh_gen_create_button", use_container_width=True):
        service = SSHService()
        public_key, private_key = service.generate_keypair(
            key_type=key_type.lower(),
            key_size=key_size,
            comment=comment,
            password=password if password else None
        )
        
        # Generate filenames
        key_type_str = f"ssh-{key_type.lower()}"
        private_filename = get_key_filename(key_type_str)
        public_filename = get_key_filename(key_type_str, is_public=True)
        
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
