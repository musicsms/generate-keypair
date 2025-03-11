import streamlit as st
from services.vault_service import VaultService
from services.cert_sign_service import Certsrv, RequestDeniedException, CertificatePendingException, CouldNotRetrieveCertificateException
from services.csr_validation_service import CSRValidationService
import tempfile
from pathlib import Path
from frontend.utils import download_button
import base64

def render_csr_sign_section():
    st.markdown("### 🔏 Certificate Signing Request (CSR) Signing")
    st.markdown("Sign a CSR using Microsoft ADCS (Active Directory Certificate Services).")
    
    # Create a temporary directory if it doesn't exist
    if 'csr_sign_temp_dir' not in st.session_state:
        st.session_state.csr_sign_temp_dir = tempfile.mkdtemp()
        st.session_state.csr_file = Path(st.session_state.csr_sign_temp_dir) / "input_csr.pem"
        st.session_state.signed_cert_file = Path(st.session_state.csr_sign_temp_dir) / "signed_cert.pem"
        st.session_state.cert_chain_file = Path(st.session_state.csr_sign_temp_dir) / "cert_chain.p7b"
    
    # Initialize session state variables
    if 'csr_pem' not in st.session_state:
        st.session_state.csr_pem = None
    if 'csr_details' not in st.session_state:
        st.session_state.csr_details = None
    if 'signed_cert_pem' not in st.session_state:
        st.session_state.signed_cert_pem = None
    if 'cert_chain' not in st.session_state:
        st.session_state.cert_chain = None
    
    # CSR Input
    st.subheader("1. Provide Certificate Signing Request (CSR)")
    
    csr_input_method = st.radio(
        "CSR Input Method",
        options=["Paste CSR Content", "Upload CSR File"],
        key="csr_sign_input_method"
    )
    
    csr_content = None
    
    if csr_input_method == "Upload CSR File":
        csr_file = st.file_uploader("Upload CSR file (PEM format)", type=["pem", "csr", "txt"])
        if csr_file is not None:
            try:
                csr_content = csr_file.read().decode('utf-8')
                
                # Validate CSR format
                if CSRValidationService.validate_csr_format(csr_content):
                    st.session_state.csr_pem = csr_content
                    
                    with open(st.session_state.csr_file, 'w') as f:
                        f.write(csr_content)
                    
                    # Parse CSR for details
                    try:
                        csr_details = CSRValidationService.parse_csr(csr_content)
                        st.session_state.csr_details = csr_details
                        st.success("CSR file uploaded and validated successfully")
                    except ValueError as e:
                        st.warning(f"CSR format is valid but could not parse details: {str(e)}")
                else:
                    st.error("Invalid CSR format. Please ensure it's in PEM format.")
            except Exception as e:
                st.error(f"Error reading CSR file: {str(e)}")
    else:
        csr_text = st.text_area("Paste your CSR (PEM format)", height=200, 
                               help="Paste the content of your Certificate Signing Request in PEM format")
        
        if st.button("Validate CSR"):
            if csr_text:
                csr_content = csr_text
                # Validate CSR format
                if CSRValidationService.validate_csr_format(csr_text):
                    st.session_state.csr_pem = csr_text
                    
                    with open(st.session_state.csr_file, 'w') as f:
                        f.write(csr_text)
                    
                    # Parse CSR for details
                    try:
                        csr_details = CSRValidationService.parse_csr(csr_text)
                        st.session_state.csr_details = csr_details
                        st.success("CSR validated successfully")
                    except ValueError as e:
                        st.warning(f"CSR format is valid but could not parse details: {str(e)}")
                else:
                    st.error("Invalid CSR format. Please ensure it's in PEM format.")
            else:
                st.error("Please provide CSR content")
    
    # Display CSR details if available
    if st.session_state.csr_details:
        with st.expander("📋 CSR Details", expanded=True):
            csr_details = st.session_state.csr_details
            
            # Define column layout
            col1, col2 = st.columns(2)
            
            # Display subject information
            with col1:
                st.markdown("#### Subject Information")
                subject_info = csr_details.get("subject", {})
                
                if subject_info:
                    formatted_fields = CSRValidationService.get_formatted_subject_display(subject_info)
                    for label, value in formatted_fields:
                        st.markdown(f"**{label}:** {value}")
                else:
                    st.info("No subject information available")
            
            # Display public key and signature information
            with col2:
                # Public key information
                st.markdown("#### Key Information")
                key_info = csr_details.get("public_key", {})
                
                if key_info:
                    algorithm = key_info.get("algorithm", "Unknown")
                    key_size = key_info.get("key_size", "Unknown")
                    
                    st.markdown(f"**Algorithm:** {algorithm}")
                    st.markdown(f"**Key Size:** {key_size} bits")
                    
                    if algorithm == "RSA":
                        exponent = key_info.get("public_exponent", "Unknown")
                        st.markdown(f"**Public Exponent:** {exponent}")
                    elif algorithm == "ECC":
                        curve = key_info.get("curve", "Unknown")
                        st.markdown(f"**Curve:** {curve}")
                else:
                    st.info("No key information available")
                
                # Signature algorithm
                st.markdown("#### Signature Information")
                sig_alg = csr_details.get("signature_algorithm", "Unknown")
                st.markdown(f"**Signature Algorithm:** {sig_alg}")
                
                # CSR Validation status
                is_valid = csr_details.get("valid", False)
                if is_valid:
                    st.success("Signature is valid")
                else:
                    st.error("Signature is invalid")
            
            # Display fingerprints in a new section
            st.markdown("#### Fingerprints")
            fingerprints = csr_details.get("fingerprints", {})
            
            if fingerprints:
                for hash_name, fingerprint in fingerprints.items():
                    formatted_fingerprint = ":".join(fingerprint[i:i+2] for i in range(0, len(fingerprint), 2))
                    st.markdown(f"**{hash_name}:** `{formatted_fingerprint}`")
            else:
                st.info("No fingerprint information available")
            
            # Display extensions in a new section
            st.markdown("#### Extensions")
            extensions = csr_details.get("extensions", {})
            
            if extensions:
                # First display SANs if available
                sans = extensions.get("subject_alternative_name", [])
                if sans:
                    st.markdown("**Subject Alternative Names (SANs):**")
                    for san in sans:
                        san_type = san.get("type", "Unknown")
                        san_value = san.get("value", "Unknown")
                        st.markdown(f"- {san_type}: {san_value}")
                
                # Display other extensions
                for ext_name, ext_value in extensions.items():
                    if ext_name != "subject_alternative_name":
                        st.markdown(f"**{ext_name.replace('_', ' ').title()}:**")
                        if isinstance(ext_value, list):
                            for item in ext_value:
                                st.markdown(f"- {item}")
                        else:
                            st.markdown(f"{ext_value}")
            else:
                st.info("No extension information available")
    
    # HashiCorp Vault Configuration
    st.subheader("2. HashiCorp Vault Configuration")
    
    with st.expander("Vault Connection Settings", expanded=True):
        col1, col2 = st.columns(2)
        
        with col1:
            vault_url = st.text_input(
                "Vault URL",
                value="https://vault.example.com:8200",
                help="The URL of your HashiCorp Vault server"
            )
        
        with col2:
            vault_token = st.text_input(
                "Vault Token",
                type="password",
                help="Your authentication token for HashiCorp Vault"
            )
        
        vault_path = st.text_input(
            "Vault Secret Path",
            value="/kv2/cert",
            help="Path to the certificate signing credentials in Vault"
        )
    
    # ADCS Server Configuration
    st.subheader("3. ADCS Server Configuration")
    
    with st.expander("ADCS Server Settings", expanded=True):
        adcs_server = st.text_input(
            "ADCS Server",
            placeholder="certsrv.example.com",
            help="The FQDN of your Microsoft ADCS server"
        )
        
        auth_method = st.selectbox(
            "Authentication Method",
            options=["basic", "ntlm", "cert"],
            index=0,
            help="Authentication method for connecting to the ADCS server"
        )
    
    # Signing Template Selection
    st.subheader("4. Signing Template")
    
    # We'll get the templates dynamically when possible, but have a default list
    default_templates = [
        {"id": "WebServer", "name": "Web Server Certificate", "description": "Standard SSL/TLS server certificate"},
        {"id": "ClientAuth", "name": "Client Authentication", "description": "For client authentication purposes"},
        {"id": "CodeSigning", "name": "Code Signing Certificate", "description": "For signing executables and scripts"},
        {"id": "SmartcardLogon", "name": "Smartcard Logon", "description": "For smartcard authentication"}
    ]
    
    templates = default_templates
    template_options = {t["name"]: t["id"] for t in templates}
    
    selected_template_name = st.selectbox(
        "Certificate Template",
        options=list(template_options.keys()),
        help="Select the type of certificate to issue"
    )
    
    selected_template_id = template_options[selected_template_name]
    
    # Display template description
    for t in templates:
        if t["id"] == selected_template_id:
            st.info(t["description"])
            
            # Add note about validity
            st.write("**Note**: The validity period for this certificate is determined by the template on the server.")
    
    # Sign the CSR
    if st.button("Sign Certificate", disabled=not st.session_state.csr_pem or not vault_url or not vault_token or not adcs_server):
        if not st.session_state.csr_pem:
            st.error("Please provide a valid CSR first")
        elif not vault_url or not vault_token:
            st.error("Please provide Vault URL and token")
        elif not adcs_server:
            st.error("Please provide ADCS server address")
        else:
            try:
                with st.spinner("Retrieving credentials from Vault..."):
                    # Get credentials from Vault
                    vault_service = VaultService(vault_url, vault_token)
                    credentials = vault_service.get_credential(vault_path)
                    
                    if not credentials:
                        st.error(f"Failed to retrieve credentials from Vault path: {vault_path}")
                        st.stop()
                    
                    # Extract username and password from credentials
                    username = credentials.get("username")
                    password = credentials.get("password")
                    
                    if not username or not password:
                        st.error("Missing username or password in Vault credentials")
                        st.stop()
                    
                with st.spinner("Signing certificate..."):
                    # Initialize the cert signing service with credentials from Vault
                    cert_service = Certsrv(
                        server=adcs_server,
                        username=username,
                        password=password,
                        auth_method=auth_method,
                        cafile=None,
                    )
                    
                    # Sign the CSR
                    try:
                        # Get the signed certificate
                        signed_cert = cert_service.get_cert(
                            csr=st.session_state.csr_pem,
                            template=selected_template_id,
                            encoding="b64"
                        )
                        
                        # Ensure it's bytes
                        if not isinstance(signed_cert, bytes):
                            signed_cert = signed_cert.encode('utf-8')
                            
                        st.session_state.signed_cert_pem = signed_cert
                        
                        with open(st.session_state.signed_cert_file, 'wb') as f:
                            f.write(signed_cert)
                        
                        # Get the certificate chain
                        cert_chain = cert_service.get_chain(encoding="b64")
                        
                        # Ensure it's bytes
                        if not isinstance(cert_chain, bytes):
                            cert_chain = cert_chain.encode('utf-8')
                            
                        st.session_state.cert_chain = cert_chain
                        
                        with open(st.session_state.cert_chain_file, 'wb') as f:
                            f.write(cert_chain)
                        
                        st.success("Certificate and chain successfully retrieved!")
                        
                    except RequestDeniedException as e:
                        st.error(f"Request denied: {str(e)}")
                    except CertificatePendingException as e:
                        st.warning(f"Certificate is pending approval: {str(e)}")
                        st.info(f"Request ID: {e.req_id}")
                    except CouldNotRetrieveCertificateException as e:
                        st.error(f"Failed to retrieve certificate: {str(e)}")
                    
            except Exception as e:
                st.error(f"Error during certificate signing process: {str(e)}")
    
    # Download signed certificate and chain
    if st.session_state.signed_cert_pem:
        st.subheader("5. Download Certificate and Chain")
        
        col1, col2 = st.columns(2)
        
        with col1:
            download_button(
                st.session_state.signed_cert_pem,
                "signed_certificate.pem",
                "Download Signed Certificate",
                mime_type="application/x-pem-file"
            )
            
            with st.expander("View Certificate Content", expanded=False):
                if isinstance(st.session_state.signed_cert_pem, bytes):
                    # Try to decode as text for display
                    try:
                        cert_text = st.session_state.signed_cert_pem.decode('utf-8')
                        st.code(cert_text)
                    except UnicodeDecodeError:
                        st.code("Binary certificate data (cannot display as text)")
                else:
                    st.code(st.session_state.signed_cert_pem)
        
        if st.session_state.cert_chain:
            with col2:
                download_button(
                    st.session_state.cert_chain,
                    "certificate_chain.p7b",
                    "Download Certificate Chain",
                    mime_type="application/pkcs7-mime"
                )
                
                st.info("The certificate chain is in PKCS#7 format (.p7b)")
                st.markdown("""
                **Note:** To use the certificate chain in your application:
                1. Import the signed certificate
                2. Import the certificate chain separately
                """)
                
                if isinstance(st.session_state.cert_chain, bytes):
                    try:
                        # Display first few bytes as hex for debugging
                        hex_preview = st.session_state.cert_chain[:30].hex()
                        st.write(f"Chain file preview (hex): {hex_preview}...")
                    except:
                        pass