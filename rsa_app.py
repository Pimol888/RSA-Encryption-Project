import streamlit as st
import time
from sympy import randprime, mod_inverse

st.title("RSA Encryption Demo")

# -------------------------------
# RSA Functions
# -------------------------------
def encrypt(message, e, n):
    return [pow(ord(char), e, n) for char in message]

def decrypt(cipher, d, n):
    return ''.join([chr(pow(char, d, n)) for char in cipher])


# -------------------------------
# Session state initialization
# -------------------------------
if "keys_generated" not in st.session_state:
    st.session_state.keys_generated = False

# -------------------------------
# Key Generation
# -------------------------------
if st.button("Generate RSA Keys"):
    p = randprime(100, 300)
    q = randprime(100, 300)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = mod_inverse(e, phi)

    st.session_state.n = n
    st.session_state.e = e
    st.session_state.d = d
    st.session_state.keys_generated = True

# -------------------------------
# Encryption & Decryption UI
# -------------------------------
if st.session_state.keys_generated:
    st.write(f"**Public Key (e, n):** ({st.session_state.e}, {st.session_state.n})")
    st.write(f"**Private Key (d, n):** ({st.session_state.d}, {st.session_state.n})")

    # -------- Encryption --------
    message = st.text_input("Enter message to encrypt:")

    if st.button("Encrypt"):
        start_time = time.time()
        encrypted = encrypt(
            message,
            st.session_state.e,
            st.session_state.n
        )
        end_time = time.time()

        st.session_state.cipher = encrypted
        encryption_time = end_time - start_time

        st.write("**Encrypted Message:**", encrypted)
        st.write(f"**Encryption Time:** {encryption_time:.6f} seconds")

    # -------- Decryption --------
    if "cipher" in st.session_state:
        if st.button("Decrypt"):
            start_time = time.time()
            decrypted = decrypt(
                st.session_state.cipher,
                st.session_state.d,
                st.session_state.n
            )
            end_time = time.time()

            decryption_time = end_time - start_time

            st.write("**Decrypted Message:**", decrypted)
            st.write(f"**Decryption Time:** {decryption_time:.6f} seconds")
