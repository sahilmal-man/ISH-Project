from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import tkinter as tk
from tkinter import filedialog, messagebox
import os

# Function to generate a key from the password
def generate_key(password):
    hasher = SHA256.new(password.encode('utf-8'))  # Hash the password to create a 256-bit key
    return hasher.digest()

# Function to encrypt the file
def encrypt_file(file_name, password):
    key = generate_key(password)  # Generate key from password
    cipher = AES.new(key, AES.MODE_EAX)  # Create a new AES cipher

    with open(file_name, 'rb') as file:
        file_data = file.read()  # Read the file's data

    ciphertext, tag = cipher.encrypt_and_digest(file_data)  # Encrypt the file data

    # Save the encrypted file with a ".enc" extension
    with open(file_name + ".enc", 'wb') as encrypted_file:
        for x in (cipher.nonce, tag, ciphertext):  # Write nonce, tag, and ciphertext
            encrypted_file.write(x)

    messagebox.showinfo("Success", f"File '{file_name}' encrypted successfully!")

# Function to decrypt the file
def decrypt_file(file_name, password):
    key = generate_key(password)  # Generate key from password

    with open(file_name, 'rb') as encrypted_file:
        nonce, tag, ciphertext = [encrypted_file.read(x) for x in (16, 16, -1)]  # Extract nonce, tag, and ciphertext

    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)  # Create a new cipher using the extracted nonce

    try:
        file_data = cipher.decrypt_and_verify(ciphertext, tag)  # Decrypt and verify the data
        with open(file_name[:-4], 'wb') as decrypted_file:  # Remove '.enc' from filename
            decrypted_file.write(file_data)
        messagebox.showinfo("Success", f"File '{file_name}' decrypted successfully!")
    except ValueError:
        messagebox.showerror("Error", "Incorrect password or corrupted file!")

# Function to open a file selection dialog and run encryption/decryption
def select_file(action):
    root = tk.Tk()
    root.withdraw()  # Hide the root window
    file_path = filedialog.askopenfilename()  # Open the file dialog
    
    if file_path:  # If a file is selected
        password = input("Enter the password: ")
        if action == 'E':
            encrypt_file(file_path, password)
        elif action == 'D':
            decrypt_file(file_path, password)
    else:
        messagebox.showwarning("Warning", "No file selected.")

# Main program for encrypting and decrypting
if _name_ == "_main_":
    root = tk.Tk()
    root.withdraw()  # Hide the root window

    choice = input("Do you want to (E)ncrypt or (D)ecrypt a file? ").upper()

    if choice == 'E':
        select_file('E')
    elif choice == 'D':
        select_file('D')
    else:
        print("Invalid choice! Please choose (E) for encrypt or (D) for decrypt.")