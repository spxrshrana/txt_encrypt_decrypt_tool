import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox
import sys
import base64
from Crypto.Cipher import AES
from Crypto import Random
import hashlib

block_size = 16

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

def process_file(input_file, output_file, key, is_decrypt, is_read):
    try:
        if is_read:
            with open(input_file, 'r') as fp:
                file_content = fp.read()
        else:
            with open(input_file, 'rb') as fp:
                file_content = base64.b64encode(fp.read()).decode('utf-8')

        key = sha256(key)

        if is_decrypt:
            decrypted_data = decrypt(file_content, key)
            with open(output_file, 'w') as fp2:
                fp2.write(decrypted_data)
            messagebox.showinfo("Decryption Completed", f"Decrypted file: {output_file}")
        else:
            encrypted_data = encrypt(file_content, key)
            with open(output_file, 'w' if is_read else 'wb') as fp1:
                if is_read:
                    fp1.write(encrypted_data)
                else:
                    fp1.write(base64.b64decode(encrypted_data.encode('utf-8')))
            messagebox.showinfo("Encryption Completed", f"{'Decrypted' if is_read else 'Encrypted'} file: {output_file}")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {str(e)}")

class App:
    def __init__(self, master):
        self.master = master
        master.title("File Encryptor/Decryptor")

        self.label_key = tk.Label(master, text="Enter Key:")
        self.label_key.pack()

        self.entry_key = tk.Entry(master, show="*")
        self.entry_key.pack()

        self.encrypt_decrypt_var = tk.StringVar()
        self.encrypt_decrypt_var.set("Encrypt")

        self.radio_encrypt = tk.Radiobutton(master, text="Encrypt", variable=self.encrypt_decrypt_var, value="Encrypt")
        self.radio_encrypt.pack()

        self.radio_decrypt = tk.Radiobutton(master, text="Decrypt", variable=self.encrypt_decrypt_var, value="Decrypt")
        self.radio_decrypt.pack()

        self.browse_button = tk.Button(master, text="Browse Input File", command=self.browse_input_file)
        self.browse_button.pack()

        self.browse_output_button = tk.Button(master, text="Browse Output File", command=self.browse_output_file)
        self.browse_output_button.pack()

        self.process_button = tk.Button(master, text="Process", command=self.process_file)
        self.process_button.pack()

    def browse_input_file(self):
        self.input_file = filedialog.askopenfilename()

    def browse_output_file(self):
        self.output_file = filedialog.asksaveasfilename()

    def process_file(self):
        key = self.entry_key.get()
        action = self.encrypt_decrypt_var.get()
        is_decrypt = (action == "Decrypt")
        process_file(self.input_file, self.output_file, key, is_decrypt, False)

root = tk.Tk()
app = App(root)
root.mainloop()

