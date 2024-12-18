import streamlit as st
from services.csr_service import CSRService
from services.rsa_service import RSAService
from frontend.utils import download_button, get_key_filename

def render_csr_section():
    st.markdown("### 📜 Certificate Signing Request (CSR) Generator")
    st.markdown("Generate a CSR for obtaining SSL/TLS certificates.")
    
    # Key Source Selection
    key_source = st.radio(
        "Private Key Source",
        options=["Generate New RSA Key", "Use Existing Key"],
        key="csr_gen_key_source_radio"
    )

    private_key = None
    public_key = None
    key_password = None

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
                    private_key = None
                    public_key = None

    else:  # Use Existing Key
        with st.expander("Private Key Input", expanded=True):
            private_key = st.text_area(
                "Private Key (PEM format)", 
                height=150,
                help="Paste your private key in PEM format",
                key="csr_gen_private_key_input"
            )

            has_password = st.checkbox(
                "Private key is encrypted",
                key="csr_gen_has_password_check"
            )
            if has_password:
                key_password = st.text_input(
                    "Private key password", 
                    type="password",
                    key="csr_gen_password_input"
                )

    # CSR Information
    with st.expander("Certificate Information", expanded=True):
        col1, col2 = st.columns(2)
        
        with col1:
            common_name = st.text_input(
                "Common Name (CN)", 
                help="Domain name or server name (e.g., example.com)",
                key="csr_gen_cn_input"
            )
            country = st.text_input(
                "Country (C)", 
                max_chars=2,
                help="Two-letter country code (e.g., US)",
                key="csr_gen_country_input"
            )
            locality = st.text_input(
                "Locality/City (L)",
                help="City name",
                key="csr_gen_locality_input"
            )
            organization = st.text_input(
                "Organization (O)",
                help="Company or organization name",
                key="csr_gen_org_input"
            )

        with col2:
            state = st.text_input(
                "State/Province (ST)",
                help="Full state or province name",
                key="csr_gen_state_input"
            )
            email = st.text_input(
                "Email Address",
                help="Contact email address",
                key="csr_gen_email_input"
            )
            org_unit = st.text_input(
                "Organizational Unit (OU)",
                help="Department or division name",
                key="csr_gen_ou_input"
            )

    if st.button("📜 Generate CSR", key="csr_gen_create_button", use_container_width=True):
        if not private_key:
            st.error("Please provide or generate a private key")
            return
        if not common_name:
            st.error("Common Name (CN) is required")
            return

        try:
            csr = CSRService.generate_csr(
                private_key_pem=private_key,
                common_name=common_name,
                country=country if country else None,
                state=state if state else None,
                locality=locality if locality else None,
                organization=organization if organization else None,
                organizational_unit=org_unit if org_unit else None,
                email=email if email else None,
                password=key_password
            )

            st.success("CSR generated successfully!")
            
            # Display CSR
            st.markdown("##### Certificate Signing Request (CSR):")
            st.code(csr, language="text")
            
            # Generate filename based on common name
            filename = f"{common_name.replace('*', 'wildcard').replace('.', '_')}.csr"
            
            # Download button
            download_button(
                content=csr,
                filename=filename,
                button_text="⬇️ Download CSR"
            )

        except Exception as e:
            st.error(f"Error generating CSR: {str(e)}")
