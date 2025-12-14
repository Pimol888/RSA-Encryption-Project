import streamlit as st
import time
from sympy import randprime, mod_inverse

st.title("RSA Encryption Demo (Key Size Comparison)")

# -------------------------------
# RSA Functions
# -------------------------------
def generate_keys(bits):
    start = time.time()

    half = bits // 2
    p = randprime(2**(half-1), 2**half)
    q = randprime(2**(half-1), 2**half)

    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = mod_inverse(e, phi)

    end = time.time()
    return n, e, d, end - start


def encrypt(message, e, n):
    start = time.time()
    cipher = [pow(ord(c), e, n) for c in message]
    end = time.time()
    return cipher, end - start


def decrypt(cipher, d, n):
    start = time.time()
    message = ''.join(chr(pow(c, d, n)) for c in cipher)
    end = time.time()
    return message, end - start


# -------------------------------
# UI: Key size selection
# -------------------------------
key_size = st.selectbox(
    "Select RSA Key Size (bits)",
    [256, 512, 1024, 2048, 4096]
)

# -------------------------------
# Session state
# -------------------------------
if "keys_generated" not in st.session_state:
    st.session_state.keys_generated = False

# -------------------------------
# Generate Keys
# -------------------------------
if st.button("Generate RSA Keys"):
    with st.spinner("Generating keys..."):
        n, e, d, keygen_time = generate_keys(key_size)

    st.session_state.n = n
    st.session_state.e = e
    st.session_state.d = d
    st.session_state.keygen_time = keygen_time
    st.session_state.keys_generated = True

# -------------------------------
# Display Keys & Times
# -------------------------------
if st.session_state.keys_generated:
    st.success("Keys generated successfully!")

    st.write(f"**Key Size:** {key_size} bits")
    st.write(f"**Key Generation Time:** {st.session_state.keygen_time:.4f} seconds")

    st.write(f"**Public Key (e, n):** ({st.session_state.e}, n)")
    st.write(f"**Private Key (d, n):** (hidden)")

    # -------- Encryption --------
    message = st.text_input("Enter message to encrypt:")

    if st.button("Encrypt"):
        cipher, enc_time = encrypt(
            message,
            st.session_state.e,
            st.session_state.n
        )
        st.session_state.cipher = cipher
        st.session_state.enc_time = enc_time

        st.write("**Encrypted Message:**", cipher)
        st.write(f"**Encryption Time:** {enc_time:.6f} seconds")

    # -------- Decryption --------
    if "cipher" in st.session_state:
        if st.button("Decrypt"):
            decrypted, dec_time = decrypt(
                st.session_state.cipher,
                st.session_state.d,
                st.session_state.n
            )
            st.session_state.dec_time = dec_time

            st.write("**Decrypted Message:**", decrypted)
            st.write(f"**Decryption Time:** {dec_time:.6f} seconds")
