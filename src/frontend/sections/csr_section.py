import streamlit as st
from services.csr_service import CSRService
from services.rsa_service import RSAService
from frontend.utils import download_button, get_key_filename
import tempfile
import os
from pathlib import Path

def render_csr_section():
    st.markdown("### 📜 Certificate Signing Request (CSR) Generator")
    st.markdown("Generate a CSR for obtaining SSL/TLS certificates.")
    
    # Create a temporary directory if it doesn't exist
    if 'temp_dir' not in st.session_state:
        st.session_state.temp_dir = tempfile.mkdtemp()
        st.session_state.key_file = Path(st.session_state.temp_dir) / "temp_key.pem"
        st.session_state.csr_key_password = None

    # Key Source Selection
    key_source = st.radio(
        "Private Key Source",
        options=["Generate New RSA Key", "Use Existing Key"],
        key="csr_gen_key_source_radio"
    )

    # Initialize session state for private key and password if not exists
    if 'csr_private_key' not in st.session_state:
        st.session_state.csr_private_key = None
    if 'csr_key_password' not in st.session_state:
        st.session_state.csr_key_password = None

    if key_source == "Generate New RSA Key":
        with st.expander("RSA Key Options", expanded=True):
            col1, col2 = st.columns(2)
            
            with col1:
                key_size = st.select_slider(
                    "Key Size (bits)",
                    options=[2048, 3072, 4096],
                    value=2048,
                    help="Larger key sizes are more secure but slower",
                    key="csr_gen_key_size_select_slider"
                )
            
            with col2:
                key_password = st.text_input(
                    "Key Password (Optional)",
                    type="password",
                    help="Optional password to encrypt the private key",
                    key="csr_gen_key_password_input"
                )

            if st.button("🔐 Generate RSA Key Pair", key="csr_gen_rsa_button"):
                try:
                    service = RSAService()
                    public_key, private_key = service.generate_keypair(
                        key_size=key_size,
                        password=key_password if key_password else None
                    )
                    # Store private key in temporary file
                    st.session_state.key_file.write_text(private_key)
                    st.session_state.csr_key_password = key_password
                    st.success("RSA key pair generated successfully!")

                    # Display and download options for keys
                    col1, col2 = st.columns(2)
                    with col1:
                        st.markdown("##### Private Key (Keep Secret!):")
                        st.code(private_key, language="text")
                        download_button(
                            private_key,
                            get_key_filename("rsa"),
                            "⬇️ Download Private Key"
                        )
                    with col2:
                        st.markdown("##### Public Key (Safe to Share):")
                        st.code(public_key, language="text")
                        download_button(
                            public_key,
                            get_key_filename("rsa", is_public=True),
                            "⬇️ Download Public Key"
                        )
                except Exception as e:
                    st.error(f"Error generating RSA key pair: {str(e)}")
                    if st.session_state.key_file.exists():
                        st.session_state.key_file.unlink()
                    st.session_state.csr_key_password = None

    else:  # Use Existing Key
        with st.expander("Private Key Input", expanded=True):
            input_private_key = st.text_area(
                "Private Key (PEM format)", 
                height=150,
                help="Paste your private key in PEM format",
                key="csr_gen_private_key_input"
            )
            if input_private_key:
                # Store input key in temporary file
                st.session_state.key_file.write_text(input_private_key)

            has_password = st.checkbox(
                "Private key is encrypted",
                key="csr_gen_has_password_check"
            )
            if has_password:
                input_key_password = st.text_input(
                    "Private key password", 
                    type="password",
                    key="csr_gen_password_input"
                )
                if input_key_password:
                    st.session_state.csr_key_password = input_key_password

    # CSR Information
    with st.expander("Certificate Information", expanded=True):
        col1, col2 = st.columns(2)
        
        with col1:
            common_name = st.text_input(
                "Common Name (CN)", 
                value="example.com",
                help="Domain name, server name, or IP address (e.g., example.com or 192.168.1.1)",
                key="csr_gen_cn_input"
            )
            country = st.text_input(
                "Country (C)", 
                value="US",
                max_chars=2,
                help="Two-letter country code (e.g., US)",
                key="csr_gen_country_input"
            )
            locality = st.text_input(
                "Locality/City (L)",
                value="San Francisco",
                help="City name",
                key="csr_gen_locality_input"
            )
            organization = st.text_input(
                "Organization (O)",
                value="Example Inc",
                help="Company or organization name",
                key="csr_gen_org_input"
            )

        with col2:
            state = st.text_input(
                "State/Province (ST)",
                value="California",
                help="Full state or province name",
                key="csr_gen_state_input"
            )
            email = st.text_input(
                "Email Address",
                value="admin@example.com",
                help="Contact email address",
                key="csr_gen_email_input"
            )
            org_unit = st.text_input(
                "Organizational Unit (OU)",
                value="IT Department",
                help="Department or division name",
                key="csr_gen_ou_input"
            )
            
        # Add Subject Alternative Names field
        st.markdown("##### Subject Alternative Names (SANs)")
        st.markdown("Add additional domain names or IP addresses to be secured by this certificate.")
        san_input = st.text_area(
            "Subject Alternative Names",
            placeholder="Enter one domain or IP per line (e.g., www.example.com, mail.example.com, 192.168.1.1)",
            help="Each line will be treated as a separate SAN entry. These can be domain names or IP addresses that will be secured by the certificate.",
            key="csr_gen_san_input"
        )
        
        # Process SAN input into a list
        subject_alternative_names = []
        if san_input:
            subject_alternative_names = [line.strip() for line in san_input.split('\n') if line.strip()]

    if st.button("📜 Generate CSR", key="csr_gen_create_button", use_container_width=True):
        if not st.session_state.key_file.exists():
            st.error("Please provide or generate a private key")
            return
        if not common_name:
            st.error("Common Name (CN) is required")
            return

        try:
            # Read private key from temporary file
            private_key_pem = st.session_state.key_file.read_text()
            
            csr = CSRService.generate_csr(
                private_key_pem=private_key_pem,
                common_name=common_name,
                country=country if country else None,
                state=state if state else None,
                locality=locality if locality else None,
                organization=organization if organization else None,
                organizational_unit=org_unit if org_unit else None,
                email=email if email else None,
                password=st.session_state.csr_key_password,
                subject_alternative_names=subject_alternative_names if subject_alternative_names else None
            )

            st.success("CSR generated successfully!")
            
            # Display both private key and CSR
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("##### Private Key (Keep Secret!):")
                st.code(private_key_pem, language="text")
                # Generate filename for private key
                private_key_filename = f"{common_name.replace('*', 'wildcard').replace('.', '_')}.key"
                download_button(
                    content=private_key_pem,
                    filename=private_key_filename,
                    button_text="⬇️ Download Private Key"
                )
                st.warning("⚠️ Keep your private key secure and never share it!")
            
            with col2:
                st.markdown("##### Certificate Signing Request (CSR):")
                st.code(csr, language="text")
                # Generate filename for CSR
                csr_filename = f"{common_name.replace('*', 'wildcard').replace('.', '_')}.csr"
                download_button(
                    content=csr,
                    filename=csr_filename,
                    button_text="⬇️ Download CSR"
                )
                st.info("ℹ️ Submit this CSR to your Certificate Authority")

        except Exception as e:
            st.error(f"Error generating CSR: {str(e)}")

    # Cleanup temporary files when the session ends
    def cleanup():
        if hasattr(st.session_state, 'temp_dir') and os.path.exists(st.session_state.temp_dir):
            try:
                if st.session_state.key_file.exists():
                    st.session_state.key_file.unlink()
                os.rmdir(st.session_state.temp_dir)
            except Exception:
                pass

    # Register cleanup function
    import atexit
    atexit.register(cleanup)
