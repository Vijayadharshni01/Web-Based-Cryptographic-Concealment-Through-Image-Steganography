from PIL import Image
import numpy as np
import datetime
from werkzeug.utils import secure_filename
import sys
import codecs
import os

count = 0 

from Crypto.Cipher import AES
from secrets import token_bytes

key = token_bytes(16)

def encrypt(msg):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(msg.encode('ascii'))
    return nonce, ciphertext, tag

def decrypt(nonce, ciphertext, tag):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
        return plaintext.decode('ascii')
    except:
        return False

nonce, ciphertext, tag = encrypt(input('Enter a message: '))
plaintext = decrypt(nonce, ciphertext, tag)
print(f'Cipher text: {ciphertext}')
if not plaintext:
    print('Message is corrupted')
else:
    print(f'Plain text: {plaintext}')



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
    print(test.shape)
    print(test)
    test[:,:,0] = red
    test[:,:,1] = green
    test[:,:,2] = blue

    output_dir = './output/'
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Saving image
    ct = datetime.datetime.now()
    filename = secure_filename('Amaterasu ' + str(ct) + '.jpg')
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

# Load image
def load_img():
    resource_name = "C:\\Users\\vijayadharshni\\Documents\\crypto_project\\stegopic.jpeg"

    image = Image.open(resource_name,'r')
    return image

# Main function
def main():
    content = 'fluffy'
    #content = input("Enter the content you want to hide:\n")
    data = generate_binary(content)
    image = load_img()
    encoded_img,fname = encode(image,data)
    decoded_data = decode(encoded_img)
    result_data = bin_to_utf(decoded_data)
    tmp = result_data.replace('\0','')    

    print("Encoded image is present in output folder with name",fname,"\n")
    print("Decoded message from image is present in output folder with name decode.txt")
    
    file = codecs.open('./output/decoded.txt', 'w')
    file.write(tmp)
    file.close()
    

if __name__ == '__main__':
    main()