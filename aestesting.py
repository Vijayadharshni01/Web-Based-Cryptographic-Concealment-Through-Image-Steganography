from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from PIL import Image
import numpy as np
import os
import datetime
from werkzeug.utils import secure_filename
import sys

def encrypt_data(data, key):
    iv = get_random_bytes(AES.block_size)  # Generate a random initialization vector (IV)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(data.encode('utf-8'), AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return iv + encrypted_data  # Return IV + ciphertext

def encode(image_path, data):
    image = Image.open(image_path)
    arr = np.array(image)

    red = arr[..., 0]
    green = arr[..., 1]
    blue = arr[..., 2]

    height, width = blue.shape
    incompBlue = True
    incompGreen = True
    incompRed = True

    key = b'\x90\xb2\xf0\xa8%\xd9\xbai\xa8a^\xf78\xd6*c'
    print(f"Key: {key}")
    encrypted_data = encrypt_data(data, key)

    data_index = 0
    for i in range(height):
        for j in range(width):
            if data_index < len(encrypted_data):
                if incompBlue:
                    blue[i][j] = blue[i][j] & 0b11111110 | ((encrypted_data[data_index] >> 7) & 1)
                elif incompGreen:
                    green[i][j] = green[i][j] & 0b11111110 | ((encrypted_data[data_index] >> 7) & 1)
                elif incompRed:
                    red[i][j] = red[i][j] & 0b11111110 | ((encrypted_data[data_index] >> 7) & 1)
                data_index += 1
            else:
                incompBlue = False
                incompGreen = False
                incompRed = False
                break

    test = np.zeros((height, width, 3), dtype=np.uint8)
    test[..., 0] = red
    test[..., 1] = green
    test[..., 2] = blue

    output_dir = './output/'
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    ct = datetime.datetime.now()
    filename = secure_filename('Encoded_data.jpg')
    img = Image.fromarray(test, 'RGB')
    img.save(os.path.join(output_dir, filename))

    return img, filename

image_path =  "C:\\Users\\vijayadharshni\\Documents\\crypto_project\\stegopic.jpeg"
data = 'i lub papa'

encoded_image, filename = encode(image_path, data)
print(f"Image with encoded data saved as: {filename}")

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from PIL import Image
import numpy as np

def decrypt_data(encrypted_data, key):
    iv = encrypted_data[:AES.block_size]  # Extract IV from the beginning of the encrypted data
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(encrypted_data)  # Exclude IV from decryption
    return unpad(decrypted_data, AES.block_size).decode('utf-8')

def decode(image_path):
    image = Image.open(image_path)
    arr = np.array(image)
    red = arr[..., 0]  # All Red values
    green = arr[..., 1]  # All Green values
    blue = arr[..., 2]  # All Blue values

    height, width = blue.shape
    total_size = height * width
    data = []
    bit_size = 0
    data_byte = ''

    for i in range(height):
        for j in range(width):
            if bit_size < 8:
                data_byte = data_byte + str((blue[i][j] & 1))
                bit_size += 1
            else:
                data.append(data_byte)
                bit_size = 0
                data_byte = ''

                data_byte = data_byte + str((blue[i][j] & 1))
                bit_size += 1

    encrypted_data = bytes([int(byte, 2) for byte in data])
    key = b'\x90\xb2\xf0\xa8%\xd9\xbai\xa8a^\xf78\xd6*c'
    decrypted_data = decrypt_data(encrypted_data, key)

    return decrypted_data

# Path to the encrypted image
encrypted_image_path = 'C:\\Users\\vijayadharshni\\Documents\\crypto_project\\output\\Encoded_data.jpg'

decoded_data = decode(encrypted_image_path)
print("Decoded data:", decoded_data)


