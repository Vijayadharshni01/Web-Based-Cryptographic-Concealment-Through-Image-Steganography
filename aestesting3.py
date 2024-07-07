from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64
import os

def generate_AES_key(key_length):
    return os.urandom(key_length // 8)

def encrypt_message(message, key):
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return encrypted_data

def decrypt_message(encrypted_message, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_message) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    return unpadded_data.decode()

if __name__ == "__main__":
    key = generate_AES_key(128)
    print("Generated AES Key:", key.hex())
    message = "Hello, World!"
    encrypted_message = encrypt_message(message, key)
    print("Encrypted message:", base64.b64encode(encrypted_message).decode())

    decrypted_message = decrypt_message(encrypted_message, key)
    print("Decrypted message:", decrypted_message)
