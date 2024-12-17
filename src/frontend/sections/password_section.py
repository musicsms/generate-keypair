import streamlit as st
from services.passphrase_service import PasswordService

def render_password_section():
    st.markdown("### 🔑 Password Generator")
    st.markdown("Generate secure, customizable passwords with various options.")
    
    with st.expander("Password Options", expanded=True):
        col1, col2 = st.columns(2)
        
        with col1:
            length = st.select_slider(
                "Password Length",
                options=[8, 12, 16, 20, 24, 32, 48, 64],
                value=16,
                key="pwd_gen_length_select_slider"
            )
            
            st.markdown("##### Character Types")
            use_uppercase = st.checkbox("🔠 Uppercase Letters (A-Z)", value=True, key="pwd_gen_uppercase_check")
            use_lowercase = st.checkbox("🔡 Lowercase Letters (a-z)", value=True, key="pwd_gen_lowercase_check")
        
        with col2:
            use_digits = st.checkbox("🔢 Numbers (0-9)", value=True, key="pwd_gen_digits_check")
            use_special = st.checkbox("💫 Special Characters (!@#$...)", value=True, key="pwd_gen_special_check")
            excluded_chars = st.text_input(
                "🚫 Exclude Characters",
                key="pwd_gen_excluded_input",
                help="Enter any characters you want to exclude from the password",
                placeholder="e.g. 0O1lI"
            )
    
    if st.button("🎲 Generate Password", key="pwd_gen_create_button", use_container_width=True):
        try:
            service = PasswordService()
            password = service.generate_password(
                length=length,
                use_uppercase=use_uppercase,
                use_lowercase=use_lowercase,
                use_digits=use_digits,
                use_special=use_special,
                excluded_chars=excluded_chars
            )
            st.markdown("##### Generated Password:")
            st.code(password, language=None)
            st.info("🔒 Copy this password and store it securely!")
        except ValueError as e:
            st.error(f"⚠️ {str(e)}")
