# https://github.com/u6488067/ITCS461-TeamProj.git

import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox
from cryptography.fernet import Fernet
import hashlib
import os
import base64

# Function to generate a key from password using PBKDF2
def generate_key_from_password(password, salt):
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return key

# Function to encrypt text
def encrypt_text(password, text):
    # Generate a random salt
    salt = os.urandom(16)
    # Derive key from password
    key = generate_key_from_password(password, salt)
    # Hash the derived key using SHA-256
    hashed_key = hashlib.sha256(key).digest()
    # Use the hashed key for encryption
    cipher = Fernet(base64.urlsafe_b64encode(hashed_key))
    encrypted_text = cipher.encrypt(text.encode())
    return salt, encrypted_text

# Function to decrypt text
def decrypt_text(password, salt, encrypted_text):
    # Derive key from password and salt
    key = generate_key_from_password(password, salt)
    # Hash the derived key using SHA-256
    hashed_key = hashlib.sha256(key).digest()
    # Use the hashed key for decryption
    cipher = Fernet(base64.urlsafe_b64encode(hashed_key))
    decrypted_text = cipher.decrypt(encrypted_text).decode()
    return decrypted_text

# Function to prompt user for password
def prompt_password(prompt):
    password = simpledialog.askstring("Password", prompt, show='*')
    return password

# Global variables to store current file path and encryption key
current_file_path = None
current_password = None

def open_file():
    global current_file_path, current_password
    file_path = filedialog.askopenfilename()
    if file_path:
        password = prompt_password("Enter decryption password:")
        if password:
            try:
                with open(file_path, 'rb') as file:
                    salt, encrypted_text = file.read().split(b'\n')
                    decrypted_text = decrypt_text(password, salt, encrypted_text)
                    text.delete('1.0', tk.END)
                    text.insert(tk.END, decrypted_text)
                    # Update current file path and password
                    current_file_path = file_path
                    current_password = password
                    # Update window title with file name
                    root.title(f"Secure Text Editor - {os.path.basename(file_path)}")
            except Exception as e:
                print("Error:", e)
                messagebox.showerror("Error", "Failed to decrypt the file. Please check the decryption password.")

def save_file():
    global current_file_path, current_password
    if current_file_path and current_password:
        try:
            text_content = text.get('1.0', tk.END)
            salt, encrypted_text = encrypt_text(current_password, text_content)
            with open(current_file_path, 'wb') as file:
                file.write(salt + b'\n' + encrypted_text)
        except Exception as e:
            print("Error:", e)
            messagebox.showerror("Error", "Failed to save the file.")

def save_file_as():
    global current_file_path, current_password
    password = prompt_password("Enter encryption password:")
    if password:
        file_path = filedialog.asksaveasfilename(defaultextension='.txt')
        if file_path:
            try:
                text_content = text.get('1.0', tk.END)
                salt, encrypted_text = encrypt_text(password, text_content)
                with open(file_path, 'wb') as file:
                    file.write(salt + b'\n' + encrypted_text)
                # Update current file path and password
                current_file_path = file_path
                current_password = password
                # Update window title with file name
                root.title(f"Secure Text Editor - {os.path.basename(file_path)}")
            except Exception as e:
                print("Error:", e)
                messagebox.showerror("Error", "Failed to save the file.")

def open_new_file():
    global current_file_path, current_password
    text.delete('1.0', tk.END)
    # Reset window title
    root.title("Secure Text Editor")
    current_file_path = None
    current_password = None

def copy_text():
    text.clipboard_clear()
    text.clipboard_append(text.selection_get())

def cut_text():
    copy_text()
    text.delete("sel.first", "sel.last")

def paste_text():
    text.insert(tk.INSERT, text.clipboard_get())

def select_all():
    text.tag_add(tk.SEL, "1.0", tk.END)
    
def delete_text():
    start_index = text.index(tk.SEL_FIRST)
    end_index = text.index(tk.SEL_LAST)
    text.delete(start_index, end_index)

def find_text():
    find_text = simpledialog.askstring("Find", "Enter text to find:")
    if find_text:
        start_pos = "1.0"
        while True:
            start_pos = text.search(find_text, start_pos, stopindex=tk.END)
            if not start_pos:
                break
            end_pos = f"{start_pos}+{len(find_text)}c"
            text.tag_add(tk.SEL, start_pos, end_pos)
            start_pos = end_pos
        text.tag_config("sel", background="yellow")

def replace_text():
    find_text = simpledialog.askstring("Replace", "Enter text to replace:")
    replace_text = simpledialog.askstring("Replace", "Enter replacement text:")
    if find_text and replace_text:
        start_pos = "1.0"
        while True:
            start_pos = text.search(find_text, start_pos, stopindex=tk.END)
            if not start_pos:
                break
            end_pos = f"{start_pos}+{len(find_text)}c"
            text.delete(start_pos, end_pos)
            text.insert(start_pos, replace_text)
            start_pos = end_pos

def update_status_bar(event=None):
    cursor_position = text.index(tk.INSERT)
    line, column = cursor_position.split('.')
    line_num = int(line)
    col_num = int(column)
    char_count = len(text.get('1.0', 'end-1c').replace('\n', ''))
    word_count = len(text.get('1.0', 'end-1c').split())
    status_text = f"Ln {line_num}, Col {col_num} | {char_count} characters, {word_count} words"
    status_label.config(text=status_text)
    
# Create the main window
root = tk.Tk()
root.title("Secure Text Editor")

# Create a text widget
text = tk.Text(root, wrap="word")
text.pack(expand=True, fill="both")

# Create a menu
menu = tk.Menu(root)
root.config(menu=menu)
file_menu = tk.Menu(menu)
menu.add_cascade(label="File", menu=file_menu)
file_menu.add_command(label="New", command=open_new_file)
file_menu.add_separator()
file_menu.add_command(label="Open", command=open_file)
file_menu.add_command(label="Save", command=save_file)
file_menu.add_command(label="Save As", command=save_file_as)
file_menu.add_separator()
file_menu.add_command(label="Exit", command=root.destroy)

edit_menu = tk.Menu(menu)
menu.add_cascade(label="Edit", menu=edit_menu)
edit_menu.add_command(label="Copy", command=copy_text)
edit_menu.add_command(label="Cut", command=cut_text)
edit_menu.add_command(label="Paste", command=paste_text)
edit_menu.add_command(label="Delete", command=delete_text)
edit_menu.add_separator()
edit_menu.add_command(label="Find", command=find_text)
edit_menu.add_command(label="Replace", command=replace_text)
edit_menu.add_separator()
edit_menu.add_command(label="Select All", command=select_all)

# Create a status bar
status_label = tk.Label(root, text="", bd=1, relief=tk.SUNKEN, anchor=tk.W)
status_label.pack(side=tk.BOTTOM, fill=tk.X)

# Bind cursor movement events to update the status bar
text.bind('<KeyRelease>', update_status_bar)
text.bind('<ButtonRelease>', update_status_bar)

# Update the status bar initially
update_status_bar()

# Run the application
root.mainloop()
