from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64

def aes_decrypt(ciphertext_b64, key, iv):
    """
    Decrypt AES-encrypted text (CBC mode) encoded in Base64.
    """
    # Convert inputs from strings to bytes
    ciphertext = base64.b64decode(ciphertext_b64)
    key_bytes = key.encode()
    iv_bytes = iv.encode()

    # Create AES cipher for decryption
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)

    # Decrypt and unpad
    decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted.decode('utf-8')


# ---------------- USER INPUT SECTION ----------------

# 🔑 Insert your AES secret key (must be 16, 24, or 32 bytes for AES-128/192/256)
secret_key = "A1B2C3D4E5F6G7H8"

# 🔐 Insert your AES IV (must be 16 bytes)
iv = "1a2b3c4d5e6f7g8h"

# 🔒 Insert your encrypted Base64 text
encrypted_text = "biQaUaXCQoYjUFO4zsSzPi7ul6YISlvKK/AQ1yrsO6M="

# ----------------------------------------------------

# Run decryption
try:
    decrypted_text = aes_decrypt(encrypted_text, secret_key, iv)
    print("Decrypted text:", decrypted_text)
except Exception as e:
    print("Error during decryption:", e)
