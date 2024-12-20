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
            use_lowercase = st.checkbox("🔡 Lowercase Letters (a-z)", value=True, key="pwd_gen_lowercase_check")
            use_uppercase = st.checkbox("🔠 Uppercase Letters (A-Z)", value=True, key="pwd_gen_uppercase_check")
            use_digits = st.checkbox("🔢 Numbers (0-9)", value=True, key="pwd_gen_digits_check")
            use_special = st.checkbox("💫 Special Characters (!@#$...)", value=True, key="pwd_gen_special_check")
        
        with col2:
            st.markdown("##### Additional Options")
            password_count = st.number_input(
                "Number of Passwords",
                min_value=1,
                max_value=100,
                value=1,
                help="Generate multiple unique passwords at once",
                key="pwd_gen_count_input"
            )
            excluded_chars = st.text_input(
                "🚫 Exclude Characters",
                key="pwd_gen_excluded_input",
                help="Enter any characters you want to exclude from the password (e.g. similar-looking characters)",
                placeholder="e.g. 0O1lI"
            )
    
    if st.button("🎲 Generate Password", key="pwd_gen_create_button", use_container_width=True):
        if not any([use_lowercase, use_uppercase, use_digits, use_special]):
            st.error("⚠️ Please select at least one character type!")
            return

        try:
            service = PasswordService()
            passwords = service.generate_password(
                length=length,
                use_uppercase=use_uppercase,
                use_lowercase=use_lowercase,
                use_digits=use_digits,
                use_special=use_special,
                excluded_chars=excluded_chars,
                count=password_count
            )
            
            st.markdown(f"##### Generated Password{'s' if password_count > 1 else ''}:")
            for i, password in enumerate(passwords, 1):
                if password_count > 1:
                    st.markdown(f"**Password {i}:**")
                st.code(password, language=None)
            
            if password_count > 1:
                st.info("🔒 Copy these passwords and store them securely!")
            else:
                st.info("🔒 Copy this password and store it securely!")
        except ValueError as e:
            st.error(f"⚠️ {str(e)}")
