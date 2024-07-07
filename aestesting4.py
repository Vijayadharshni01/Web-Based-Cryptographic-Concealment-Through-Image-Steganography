from PIL import Image
import numpy as np
import datetime
from werkzeug.utils import secure_filename
import sys
import codecs
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64
import os
import cv2
import math

count = 0 

from Crypto.Cipher import AES
from secrets import token_bytes

key = token_bytes(16)

def encrypt(message):
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return encrypted_data

def decrypt(encrypted_message,key):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_message) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    return unpadded_data.decode()


#Binary to UTF
def bin_to_utf(data):
    
    Unicode_data = ''
    for d in data:
        binary_int = int(d,2)
        byte_number = binary_int.bit_length() + 7 # 8
        binary_array = binary_int.to_bytes(byte_number, "big")
        ascii_text = binary_array.decode("utf-8", 'ignore')       
        
        Unicode_data = Unicode_data + ascii_text        

    return Unicode_data


# Decode the image
def decode(image):    
    arr = np.array(image)
    red = arr[..., 0]  # All Red values
    green = arr[..., 1]  # All Green values
    blue = arr[..., 2]  # All Blue values
    print(arr,"arr-decode")

    height,width = blue.shape
    total_size = height*width
    data = []
    bit_size = 0
    data_byte = ''

    if count < total_size:
        new_count = 0
        for i in range(height):
            for j in range(width):
                if new_count <= count:                    
                    if bit_size < 8:
                        data_byte = data_byte + str((blue[i][j] & 1))
                        bit_size+=1
                    else:
                        data.append(data_byte)                        
                        bit_size = 0
                        data_byte = '' 

                        data_byte = data_byte + str((blue[i][j] & 1))
                        bit_size+=1
                        
                    new_count+=1
                else:
                    break

    elif count > total_size and count < 2*total_size:
        new_count = 0
        for i in range(height):
            for j in range(width):                                    
                if bit_size < 8:
                    data_byte = data_byte + str((blue[i][j] & 1))
                    bit_size+=1
                else:
                    data.append(data_byte)                        
                    bit_size = 0
                    data_byte = '' 

                    data_byte = data_byte + str((blue[i][j] & 1))
                    bit_size+=1
        bit_size = 0
        data_byte = ''                                                        
                
        for i in range(height):
            for j in range(width):
                if new_count <= count:                    
                    if bit_size < 8:
                        data_byte = data_byte + str((green[i][j] & 1))
                        bit_size+=1
                    else:
                        data.append(data_byte)                        
                        bit_size = 0
                        data_byte = '' 

                        data_byte = data_byte + str((green[i][j] & 1))
                        bit_size+=1
                        
                    new_count+=1
                else:
                    break
    else: 
        new_count = 0
        for i in range(height):
            for j in range(width):                                    
                if bit_size < 8:
                    data_byte = data_byte + str((blue[i][j] & 1))
                    bit_size+=1
                else:
                    data.append(data_byte)                        
                    bit_size = 0
                    data_byte = '' 

                    data_byte = data_byte + str((blue[i][j] & 1))
                    bit_size+=1
        bit_size = 0
        data_byte = ''

        for i in range(height):
            for j in range(width):                                    
                if bit_size < 8:
                    data_byte = data_byte + str((green[i][j] & 1))
                    bit_size+=1
                else:
                    data.append(data_byte)                        
                    bit_size = 0
                    data_byte = '' 

                    data_byte = data_byte + str((green[i][j] & 1))
                    bit_size+=1
        bit_size = 0
        data_byte = ''                                                        
                
        for i in range(height):
            for j in range(width):
                if new_count <= count:                    
                    if bit_size < 8:
                        data_byte = data_byte + str((red[i][j] & 1))
                        bit_size+=1
                    else:
                        data.append(data_byte)                        
                        bit_size = 0
                        data_byte = '' 

                        data_byte = data_byte + str((red[i][j] & 1))
                        bit_size+=1
                        
                    new_count+=1
                else:
                    break    
    return data

def encode(image,data):

   
    arr = np.array(image)
    print(arr.shape)
    print(arr)
    
    
    red = arr[..., 0]  
    green = arr[..., 1]  
    blue = arr[..., 2]  
       
    
    height,width = blue.shape
    incompBlue = True
    incompGreen = True
    incompRed = True

    blue[0][0] = 193
    blue[0][2] = 882
    i = 0
    j = -1
    global count
    c = 0
    for char in data:
        for bit in char:  
            count += 1
            if incompBlue == True:
                if i < height:
                    if j < width:                       
                        j+=1     
                    if j >= width:
                        i+=1
                        j=0
                    
                    #print(i,j)
                    if i < height:
                        if bit=='1':
                            blue[i][j] = blue[i][j] | 1  #set the last bit to 1
                        elif bit=='0':
                            blue[i][j] = blue[i][j] & (blue[i][j] -1)   #set the last bit to 0
                        c += 1  
                    else:
                        incompBlue = False
                        i = 0
                        j = -1
                      
                    
                  
       
                else:
                    incompBlue = False  
                    i = 0
                    j = -1                                                              
                
            if incompBlue == False and incompGreen == True:
                if i < height:
                    if j < width:                        
                        j+=1
                    if j >= width:
                        i+=1
                        j=0   

                    if i < height:
                        if bit=='1':
                            green[i][j] = green[i][j] | 1  
                        elif bit=='0':
                            green[i][j] = green[i][j] & (green[i][j] -1)   
                        c += 1
                    else:
                        incompGreen = False
                        i = 0
                        j = -1                    
                    
    
                else:
                    incompGreen = False  
                    i = 0
                    j = -1
            if incompBlue == False and incompGreen == False:
                if i < height:
                    if j < width:                        
                        j+=1
                    if j >= width:
                        i+=1
                        j=0   
                    if i < height:
                        if bit=='1':
                            red[i][j] = red[i][j] | 1  
                        elif bit=='0':
                            red[i][j] = red[i][j] & (red[i][j] -1)   
                        c += 1
                    else:
                        incompRed = False  
                        sys.exit("Choose a higher quality image")                     

                    # print("{0:b}".format(red[i][j]))
                    # print('\n')    
                else:
                    incompRed = False  
                    i = 0
                    j = -1
                    break
                  
    if incompRed == False:
        sys.exit("Choose a higher quality image")        

    w, h = image.size
    test = np.zeros((h, w, 3), dtype=np.uint8)
    
    test[:,:,0] = red
    test[:,:,1] = green
    test[:,:,2] = blue

    output_dir = './output/'
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    print(test)
    # Saving image
    ct = datetime.datetime.now()
    filename = secure_filename('encoded'+'.jpg')
    img = Image.fromarray(test, 'RGB')
    img.save(os.path.join(output_dir, filename))

    return img, filename


def generate_binary(data):
    # converted data
    new_data = []

    for i in data:
        # converting every character of user input to its binary
        new_data.append(format(ord(i), '08b'))

    
    return new_data


def PSNR(original, compressed): 
    mse = np.mean((original - compressed) ** 2) 
    if(mse == 0): # MSE is zero means no noise is present in the signal . 
                    # Therefore PSNR have no importance. 
        return 100
    max_pixel = 255.0
    psnr = 20 * math.log10(max_pixel / math.sqrt(mse)) 
    return psnr
# Load image
def load_img():
    resource_name = "C:\\Users\\vijayadharshni\\Documents\\crypto_project\\stegopic.jpeg"

    image = Image.open(resource_name,'r')
    return image

# Main function
def main():
    content = 'Lorem ipsu'
    #content = input("Enter the content you want to hide:\n")
    data = generate_binary(content)
    image = load_img()
    eny = encrypt(data)
    encoded_img,fname = encode(image,eny)
    decoded_data = decode(encoded_img)
    dec = decrypt(decoded_data,key)
    result_data = bin_to_utf(dec)
    tmp = result_data.replace('\0','')    

    print("Encoded image is present in output folder with name",fname,"\n")
    print("Decoded message from image is present in output folder with name decode.txt")

    original = cv2.imread(r"C:\Users\vijayadharshni\Documents\crypto_project\stegoimg2.jpg")
    compressed = cv2.imread(r"C:\Users\vijayadharshni\Documents\crypto_project\output\encoded.jpg", 1) 
    value = PSNR(original, compressed) 
    print(f"PSNR value is {value} dB")

    # Read the two images

    # Convert the images to grayscale
    image1 = cv2.cvtColor(original, cv2.COLOR_BGR2GRAY)
    image2 = cv2.cvtColor(compressed, cv2.COLOR_BGR2GRAY)

    # Calculate the MSE between the two images
    mse = np.mean((image1 - image2) ** 2)

    # Print the MSE value
    print(f"MSE value is {mse}") 

        
    file = codecs.open('./output/decoded.txt', 'w')
    file.write(tmp)
    file.close()
  

    

if __name__ == '__main__':
    main()