import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, simpledialog
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64, os, bcrypt

def check_password_strength(password):
    score = 0
    if len(password) >= 8: score += 1
    if any(c.isdigit() for c in password): score += 1
    if any(c.islower() for c in password): score += 1
    if any(c.isupper() for c in password): score += 1
    if any(c in '!@#$%^&*()-_+=' for c in password): score += 1
    return score

def hash_password_bcrypt(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt)

def simulate_password_crack(hashed_pw, dictionary):
    for word in dictionary:
        if bcrypt.checkpw(word.encode(), hashed_pw):
            return word
    return None

backend = default_backend()

def generate_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=backend)
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_message_rsa(message, public_key):
    return public_key.encrypt(
        message.encode(),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def decrypt_message_rsa(ciphertext, private_key):
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    ).decode()

class ChatClient:
    def __init__(self, host, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))

        self.private_key, self.public_key = generate_keys()
        self.partner_key = None

        self.root = tk.Tk()
        self.root.title("Secure Chat")
        self.chat_log = scrolledtext.ScrolledText(self.root, state='disabled')
        self.chat_log.pack(padx=10, pady=10)
        self.entry = tk.Entry(self.root)
        self.entry.pack(padx=10, pady=10, fill='x')
        self.entry.bind('<Return>', self.send_message)

        self.send_key()
        threading.Thread(target=self.receive_messages).start()
        self.root.mainloop()

    def send_key(self):
        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.sock.send(pem)

    def receive_messages(self):
        if self.partner_key is None:
            partner_pem = self.sock.recv(1024)
            self.partner_key = serialization.load_pem_public_key(partner_pem, backend=backend)

        while True:
            try:
                encrypted = self.sock.recv(4096)
                message = decrypt_message_rsa(encrypted, self.private_key)
                self.display_message(f"Partner: {message}")
            except Exception as e:
                self.display_message("Error decrypting message.")
                break

    def send_message(self, event=None):
        message = self.entry.get()
        self.entry.delete(0, tk.END)
        encrypted = encrypt_message_rsa(message, self.partner_key)
        self.sock.send(encrypted)
        self.display_message(f"You: {message}")

    def display_message(self, message):
        self.chat_log.configure(state='normal')
        self.chat_log.insert(tk.END, message + '\n')
        self.chat_log.configure(state='disabled')
        self.chat_log.yview(tk.END)

if __name__ == "__main__":
    pw = "MySecureP@ssw0rd!"
    score = check_password_strength(pw)
    print(f"Password strength score: {score}/5")

    hashed = hash_password_bcrypt(pw)
    print(f"Hashed Password (bcrypt): {hashed}")

    common_words = ["password", "123456", "letmein", "MySecureP@ssw0rd!"]
    result = simulate_password_crack(hashed, common_words)
    print(f"Cracked password: {result if result else 'Not found'}")
