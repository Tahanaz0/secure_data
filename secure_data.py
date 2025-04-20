import hashlib
import base64
from cryptography.fernet import Fernet, InvalidToken
import streamlit as st

# 🔐 Password to encryption key
def generate_key(password):
    """Generate Fernet-compatible key from password"""
    if not password:
        raise ValueError("Password cannot be empty")
    hashed = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(hashed)

# 🔒 Encryption function
def encrypt_text(text, password):
    """Encrypt text using password-derived key"""
    if not text:
        raise ValueError("Text cannot be empty")
    key = generate_key(password)
    fernet = Fernet(key)
    encrypted = fernet.encrypt(text.encode())
    return encrypted.decode()

# 🔓 Decryption function
def decrypt_text(encrypted_text, password):
    """Decrypt text using password-derived key"""
    if not encrypted_text:
        raise ValueError("Encrypted text cannot be empty")
    key = generate_key(password)
    fernet = Fernet(key)
    try:
        decrypted = fernet.decrypt(encrypted_text.encode())
        return decrypted.decode()
    except InvalidToken:
        return "❌ Decryption failed - wrong password or corrupted data"
    except Exception as e:
        return f"❌ Error: {str(e)}"

# 🎛️ Streamlit UI
st.title("🔐 Secure Data Encryption App")
st.warning("Important: Remember your password! Without it, data cannot be recovered.")

# Input sections
col1, col2 = st.columns(2)
with col1:
    text = st.text_area("Message:", height=150)
with col2:
    password = st.text_input("Password:", type="password")
    confirm_pass = st.text_input("Confirm Password:", type="password") if st.toggle("Show confirm field") else None

mode = st.radio("Action:", ["Encrypt", "Decrypt"], horizontal=True)

if st.button("Process"):
    if not text or not password:
        st.error("Please enter both message and password")
    elif confirm_pass and (password != confirm_pass):
        st.error("Passwords don't match!")
    else:
        try:
            if mode == "Encrypt":
                result = encrypt_text(text, password)
                st.success("✅ Encrypted Message:")
                st.code(result)
                st.download_button("Download Encrypted Message", result, "encrypted.txt")
            else:
                result = decrypt_text(text, password)
                if result.startswith("❌"):
                    st.error(result)
                else:
                    st.success("🔓 Decrypted Message:")
                    st.code(result)
        except Exception as e:
            st.error(f"Error: {str(e)}")