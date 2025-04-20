# Importing necessary libraries
import hashlib
import base64
from cryptography.fernet import Fernet
import streamlit as st

# 🔐 Step 1: Password se encryption key banana
def generate_key(password):
    # Password ko sha256 hash mein convert karte hain (256-bit)
    hashed = hashlib.sha256(password.encode()).digest()
    # Base64 encode karte hain taake Fernet-compatible key ban jaye
    return base64.urlsafe_b64encode(hashed)

# 🔒 Step 2: Encrypt karna (message ko password se encrypt karna)
def encrypt_text(text, password):
    key = generate_key(password)  # Password se key generate karna
    fernet = Fernet(key)          # Fernet object create karna
    encrypted = fernet.encrypt(text.encode())  # Encrypt karna
    return encrypted.decode()  # Encrypted text ko string ke form mein return karna

# 🔓 Step 3: Decrypt karna (encrypted text ko password se decrypt karna)
def decrypt_text(encrypted_text, password):
    key = generate_key(password)  # Same key generate karna
    fernet = Fernet(key)          # Fernet object create karna
    try:
        decrypted = fernet.decrypt(encrypted_text.encode())  # Decrypt karna
        return decrypted.decode()  # Decrypted text ko string mein return karna
    except:
        return "❌ Decryption failed. Wrong password or data."

# 🔧 Step 4: Streamlit interface setup
st.title("🔐 Secure Data Encryption App")

# User se message input lene ke liye
text = st.text_area("Enter your message:")

# User se password input lene ke liye (password field ke liye)
password = st.text_input("Enter a password:", type="password")

# User ko action choose karne ke liye (Encrypt ya Decrypt)
mode = st.radio("Select action:", ["Encrypt", "Decrypt"])

# Action perform karna jab button press ho
if st.button("Run"):
    if not text or not password:
        st.warning("Please enter both text and password.")
    else:
        if mode == "Encrypt":
            encrypted = encrypt_text(text, password)  # Encrypt karna
            st.success("✅ Encrypted Message:")
            st.code(encrypted)  # Encrypted message show karna
        else:
            decrypted = decrypt_text(text, password)  # Decrypt karna
            if decrypted.startswith("❌"):
                st.error(decrypted)  # Agar decryption fail ho toh error dikhana
            else:
                st.success("🔓 Decrypted Message:")
                st.code(decrypted)  # Decrypted message show karna
