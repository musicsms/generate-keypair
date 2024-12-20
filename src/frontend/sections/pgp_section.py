import streamlit as st
from services.pgp_service import PGPService
from frontend.utils import download_button, get_key_filename

def render_pgp_section():
    st.markdown("### 🔏 PGP Key Generator")
    st.markdown("Generate PGP key pairs for encryption and signing.")
    
    with st.expander("PGP Key Options", expanded=True):
        col1, col2 = st.columns(2)
        
        with col1:
            name = st.text_input("Full Name", help="Your full name for the key", key="pgp_gen_name_input")
            email = st.text_input("Email Address", help="Your email address for the key", key="pgp_gen_email_input")
            comment = st.text_input(
                "Comment (Optional)",
                help="Optional comment to identify this key",
                key="pgp_gen_comment_input"
            )
        
        with col2:
            key_length = st.select_slider(
                "Key Length (bits)",
                options=[2048, 3072, 4096],
                value=2048,
                help="Larger keys are more secure but slower",
                key="pgp_gen_key_length_select_slider"
            )
            expiry_years = st.number_input(
                "Expiry (Years)",
                min_value=0,
                max_value=10,
                value=0,
                help="0 means no expiry, max 10 years",
                key="pgp_gen_expiry_input"
            )
            passphrase = st.text_input(
                "Passphrase (Required)",
                type="password",
                help="This passphrase will protect your private key",
                key="pgp_gen_passphrase_input"
            )
    
    if st.button("🔐 Generate PGP Key Pair", key="pgp_gen_create_button", use_container_width=True):
        if not name or not email:
            st.error("⚠️ Name and email are required!")
            return
            
        if not passphrase:
            st.error("⚠️ Passphrase is required for PGP key generation!")
            return

        try:
            # Convert years to days for expiry
            expiry_days = expiry_years * 365 if expiry_years > 0 else None
            
            # Generate the keys
            generator = PGPService()
            public_key, private_key = generator.generate_keypair(
                name=name,
                email=email,
                key_length=key_length,
                passphrase=passphrase,
                comment=comment if comment else None,
                expiry_days=expiry_days
            )

            # Generate filenames
            private_filename = get_key_filename("pgp")
            public_filename = get_key_filename("pgp", is_public=True)
            
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
                
            st.warning("⚠️ Save your private key and passphrase securely!")
        except Exception as e:
            st.error(f"⚠️ Error generating PGP keys: {str(e)}")
