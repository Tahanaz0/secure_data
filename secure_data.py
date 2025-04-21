import hashlib
import base64
from cryptography.fernet import Fernet, InvalidToken
import streamlit as st

# 🔐 Convert password to Fernet-compatible key
def generate_key(password):
    """Generate a Fernet key from a password."""
    if not password:
        raise ValueError("Password cannot be empty")
    hashed = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(hashed)

# 🔒 Encrypt the input text
def encrypt_text(text, password):
    """Encrypt text using a password-derived key."""
    if not text:
        raise ValueError("Text cannot be empty")
    key = generate_key(password)
    fernet = Fernet(key)
    encrypted = fernet.encrypt(text.encode())
    return encrypted.decode()

# 🔓 Decrypt the encrypted text
def decrypt_text(encrypted_text, password):
    """Decrypt text using a password-derived key."""
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
st.set_page_config(page_title="Secure Encryption App", layout="centered")
st.title("🔐 Secure Data Encryption App")
st.info("Remember: If you forget the password, your encrypted data can't be recovered.")

# Input layout
col1, col2 = st.columns(2)
with col1:
    text = st.text_area("Enter your message:", height=150)
with col2:
    password = st.text_input("Password:", type="password")
    mode = st.radio("Action:", ["Encrypt", "Decrypt"], horizontal=True)
    show_confirm = st.toggle("Confirm password (for encryption)")
    confirm_pass = st.text_input("Confirm Password:", type="password") if show_confirm and mode == "Encrypt" else None

# Process button
if st.button("🔄 Process"):
    if not text or not password:
        st.error("Please provide both the message and password.")
    elif mode == "Encrypt" and confirm_pass and password != confirm_pass:
        st.error("❗ Passwords do not match.")
    else:
        try:
            if mode == "Encrypt":
                result = encrypt_text(text, password)
                st.success("✅ Message Encrypted:")
                st.code(result)
                st.download_button("📥 Download Encrypted Message", result, file_name="encrypted.txt")
            else:
                result = decrypt_text(text, password)
                if result.startswith("❌"):
                    st.error(result)
                else:
                    st.success("🔓 Message Decrypted:")
                    st.code(result)
        except Exception as e:
            st.error(f"❌ Unexpected Error: {str(e)}")
