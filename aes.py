#!/usr/bin/python3
import sys
import base64
from Crypto.Cipher import AES
from Crypto import Random
import hashlib

block_size = 16
pad_len = 0

def sha256(key):
    sha = hashlib.sha256()
    sha.update(key.encode('utf-8'))
    return sha.digest()

def pad(plain, block):
    pad_len = block - len(plain) % block
    return plain + ' ' * pad_len

def unpad(plain, block):
    return plain.rstrip()

def encrypt(plain, key):
    plain = pad(plain, block_size)
    iv = Random.new().read(block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    final_cipher = cipher.encrypt(plain.encode('utf-8'))
    return base64.b64encode(iv + final_cipher).decode('utf-8')

def decrypt(ciphertext, key):
    ciphertext = base64.b64decode(ciphertext.encode('utf-8'))
    iv = ciphertext[:block_size].rjust(block_size, b'\0')
    actual_ciphertext = ciphertext[block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(actual_ciphertext).decode('utf-8')
    decoded_bytes = base64.b64decode(plaintext)
    decoded_string = decoded_bytes.decode('utf-8')
    return decoded_string


def main():
    if len(sys.argv) not in (3, 4):
        print("Usage: {} <input_file> <output_file> [-d/--decrypt] [-r/--read]".format(sys.argv[0]))
        sys.exit(1)

    file = sys.argv[1]
    output_file = sys.argv[2]

    key = input('Enter a key ')
    key = sha256(key)

    read_mode = "-r" in sys.argv or "--read" in sys.argv
    decrypt_mode = "-d" in sys.argv or "--decrypt" in sys.argv

    if read_mode:
        with open(file, 'r') as fp:
            file_content = fp.read()
    else:
        with open(file, 'rb') as fp:
            file_content = base64.b64encode(fp.read()).decode('utf-8')

    if decrypt_mode:
        decrypted_data = decrypt(file_content, key)
        with open(output_file, 'w') as fp2:
            fp2.write(decrypted_data)
        print(f"Decryption completed. Decrypted file: {output_file}")
    else:
        encrypted_data = encrypt(file_content, key)
        with open(output_file, 'w' if read_mode else 'wb') as fp1:
            if read_mode:
                fp1.write(encrypted_data)
            else:
                fp1.write(base64.b64decode(encrypted_data.encode('utf-8')))
        print(f"Encryption completed. {'Decrypted' if read_mode else 'Encrypted'} file: {output_file}")

if __name__ == "__main__":
    main()
