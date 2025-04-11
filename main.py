# Project 05 Assignment Python
# Python Assignment: Secure Data Encryption System Using Streamlit


# Date : 10 April 2025

# Author : Areeba Tanveer Awan

# Objective
# Develop a Streamlit-based secure data storage and retrieval system where:

# Users store data with a unique passkey.
# Users decrypt data by providing the correct passkey.
# Multiple failed attempts result in a forced reauthorization (login page).
# The system operates entirely in memory without external databases.

import streamlit as st

import hashlib 

import json
import os 
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode 
from hashlib import pbkdf2_hmac

# ===== Data Information Of User =====

DATA_FILE = "secure_data.json"
SALT = b"secure_salt_value"
LOCKOUT_DURATION = 60


# ===== Login Section Details =====

if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0


# ===== Function to Hash Password =====

def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

def generate_key(passkey):
    try:
        # Generate a 32-byte key using PBKDF2
        key = pbkdf2_hmac('sha256', passkey.encode(), SALT, 100000)
        # Convert to base64 for Fernet
        key = urlsafe_b64encode(key)
        return key
    except Exception as e:
        st.error(f"Key generation error: {str(e)}")
        return None

def hash_password(password):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), SALT, 100000).hex()


# ===== CRYPTOGRAPHY.FERNET USED =====

def encrypt_text(text, passkey):
    try:
        if not text or not passkey:
            return None
        # Generate Fernet key
        key = generate_key(passkey)
        if not key:
            return None
        # Create cipher
        cipher = Fernet(key)
        # Encrypt
        encrypted_data = cipher.encrypt(text.encode())
        return encrypted_data.decode('utf-8')
    except Exception as e:
        st.error(f"Encryption error: {str(e)}")
        return None

def decrypt_text(encrypted_text, passkey):
    try:
        if not encrypted_text or not passkey:
            return None
        # Generate Fernet key
        key = generate_key(passkey)
        if not key:
            return None
        # Create cipher
        cipher = Fernet(key)
        # Decrypt
        decrypted_data = cipher.decrypt(encrypted_text.encode('utf-8'))
        return decrypted_data.decode('utf-8')
    except Exception as e:
        st.error(f"Decryption error: {str(e)}")
        return None
    
stored_data = load_data()

# ===== Navigation bar  =====

st.title("🛡️ Secure Data Encryption System")
menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data"]
choice = st.sidebar.selectbox("Navigation", menu)


if choice == "Home":
    st.subheader(f"\n✨ Welcome to the 🔐 Secure Data Encryption System!")
    st.markdown(f"\n Develop a Streamlit-based secure data storage and retrieval system where: Users store data with a unique passkey. ")
    st.markdown("Users decrypt data by providing the correct passkey. Multiple Failed attempts result in a reauthorization (login page). The system operates entirely in memory without external databases.")
   
# ===== User Registeration Section =====
elif choice == "Register" : 
    st.subheader("✍ Register New User 🧑")
    username = st.text_input ("Choose Username")
    password = st.text_input ("Choose Password", type="password")

    if st.button("Register"):
        if username and password:
            if username in stored_data:
                st.error("⚠️ Username already exists!")
            else:
                stored_data[username] = {
                    "password": hash_password(password),
                    "encrypted_data": []  # Changed from "data" to "encrypted_data" for clarity
                }
                save_data(stored_data)
                st.success("✅ User registered successfully!")
        else:
            st.error("⚠️ Please fill in all fields!")
                     
elif choice == "Login":
        st.subheader("🔑 User Login")

        if time.time() < st.session_state.lockout_time:
            remaining = int(st.session_state.lockout_time - time.time())
            st.error(f"🕰️ Too many failed attempts! Please wait {remaining} seconds.")

        username = st.text_input("Username")
        password = st.text_input("Password", type="password")

        if st.button("Login"):
            if username in stored_data and stored_data[username]["password"] == hash_password(password):
                st.session_state.authenticated_user = username
                st.session_state.failed_attempts = 0
                st.success(f"✅ Welcome {username}!")
            else:
                st.session_state.failed_attempts += 1
                remaining = 3 - st.session_state.failed_attempts
                st.error(f"❌ Invalid credentials! Attempts left: {remaining}") 

                if st.session_state.failed_attempts >= 3:
                    st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                    st.error("🔴 Too many failed attempts! You are locked out for 60 seconds.")
                    st.stop()

# ===== Store Data Section =====
elif choice == "Store Data":
    if not st.session_state.authenticated_user:
        st.warning("💾 Please Login First.")
    else:
        st.subheader("🛠️ Store Encrypted Data") 
        data = st.text_area("Enter data to encrypt and store:")
        passkey = st.text_input("Encryption key (passphrase)", type="password")   

        if st.button("Encrypt And Save"):
            if data and passkey:
                encrypted = encrypt_text(data, passkey)
                if "encrypted_data" not in stored_data[st.session_state.authenticated_user]:
                    stored_data[st.session_state.authenticated_user]["encrypted_data"] = []
                
                stored_data[st.session_state.authenticated_user]["encrypted_data"].append(encrypted)
                save_data(stored_data)
                st.success("✅ Data encrypted and stored successfully!")
            
            else:
                st.error("⚠️ Please fill in all fields!")

# === data retrieve section ===
elif choice == "Retrieve Data":
    if not st.session_state.authenticated_user:
        st.warning("💾 Please Login First.")
    else:
        st.subheader("🔍 Retrieve Encrypted Data")
        user_data = stored_data.get(st.session_state.authenticated_user, {})

        if not user_data or not user_data.get("encrypted_data"):
            st.info("No Data Found!")
        else:
            st.write("Encrypted Data Entries:")
            for i, encrypted_item in enumerate(user_data["encrypted_data"]):
                st.code(f"Entry {i+1}: {encrypted_item}", language="text")
                if st.button(f"Copy Entry {i+1}"):
                    st.code(encrypted_item, language="text")
                    st.success("Copied to clipboard!")

            st.subheader("Decrypt Data")
            encrypted_input = st.text_area("Enter Encrypted Text:")
            passkey = st.text_input("Enter Decryption key", type="password")
            
            if st.button("Decrypt"):
                if not encrypted_input or not passkey:
                    st.error("⚠️ Please enter both encrypted text and passkey!")
                else:
                    # Debug information
                    st.write("Debug Info:")
                    st.write(f"Encrypted text length: {len(encrypted_input)}")
                    st.write(f"Passkey length: {len(passkey)}")
                    
                    result = decrypt_text(encrypted_input, passkey)
                    if result:
                        st.success("✅ Decryption successful!")
                        st.text_area("Decrypted Data:", value=result, height=100)
                    else:
                        st.error("❌ Invalid passkey or corrupted data!")
                        st.info("Make sure to:")
                        st.write("1. Use the exact same passkey used for encryption")
                        st.write("2. Copy the entire encrypted text without any modifications")
                        st.write("3. Don't add any extra spaces or characters")
                        st.write("4. The passkey is case-sensitive")


# =================== END OF THE CODE ===================