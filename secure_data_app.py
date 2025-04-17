import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# --- Initialization ---
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# Session states
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}  # {"encrypted_text": {"encrypted_text": "...", "passkey": "..."}}

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "is_logged_in" not in st.session_state:
    st.session_state.is_logged_in = True  # Starts as authorized


# --- Utility Functions ---

def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)

    if encrypted_text in st.session_state.stored_data:
        stored_entry = st.session_state.stored_data[encrypted_text]
        if stored_entry["passkey"] == hashed_passkey:
            st.session_state.failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()

    st.session_state.failed_attempts += 1
    return None


# --- Streamlit App UI ---

st.title("🔒 Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.radio("Navigation", menu)


# --- Home Page ---
if choice == "Home":
    st.subheader("🏠 Welcome!")
    st.markdown("""
    Use this app to **securely store and retrieve data** using a unique passkey.  
    - 🔐 Your data is encrypted with Fernet  
    - 🔑 Passkey is hashed using SHA-256  
    - 🚫 After 3 failed attempts, you must log in again
    """)

# --- Store Data Page ---
elif choice == "Store Data":
    st.subheader("📂 Store Data")

    user_data = st.text_area("Enter the data you want to store securely:")
    passkey = st.text_input("Enter a passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            encrypted_text = encrypt_data(user_data)
            hashed_pass = hash_passkey(passkey)

            st.session_state.stored_data[encrypted_text] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_pass
            }

            st.success("✅ Your data has been securely encrypted and stored!")
            st.text_area("🔐 Copy your encrypted data below:", encrypted_text, height=100)
        else:
            st.error("⚠️ Please fill in both fields.")

# --- Retrieve Data Page ---
elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Data")

    if not st.session_state.is_logged_in:
        st.warning("🔐 Too many failed attempts. Please reauthorize via Login Page.")
        st.stop()

    encrypted_text = st.text_area("Paste your encrypted data:")
    passkey = st.text_input("Enter your passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            decrypted = decrypt_data(encrypted_text, passkey)

            if decrypted:
                st.success("✅ Decryption Successful!")
                st.text_area("📄 Your Decrypted Data:", decrypted, height=100)
            else:
                attempts_left = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey! Attempts remaining: {attempts_left}")

                if st.session_state.failed_attempts >= 3:
                    st.session_state.is_logged_in = False
                    st.warning("🚫 Too many failed attempts. Please login to try again.")
        else:
            st.error("⚠️ Please provide both fields.")

# --- Login Page ---
elif choice == "Login":
    st.subheader("🔑 Login to Reauthorize")
    login_pass = st.text_input("Enter master password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":  # Demo-only password
            st.session_state.failed_attempts = 0
            st.session_state.is_logged_in = True
            st.success("✅ Reauthorization successful. You can now retrieve data again.")
        else:
            st.error("❌ Incorrect master password.")
