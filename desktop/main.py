import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.fernet import Fernet
import base64
import os


class SecureFilesApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SecureFiles - File Encryption App")
        self.root.geometry("600x500")
        self.file_path = None
        self.processed_data = None
        self.action = None

        navbar = tk.Frame(root, bg="#333", height=50)
        navbar.pack(fill="x")
        tk.Label(navbar, text="SecureFiles", bg="#333", fg="white", font=("Arial", 16)).pack(side="left", padx=10)
        tk.Button(navbar, text="Home", command=self.show_home, bg="#444", fg="white").pack(side="right", padx=10)
        tk.Button(navbar, text="GitHub", command=self.open_github, bg="#444", fg="white").pack(side="right")

        self.container = tk.Frame(root, bg="#f9f9f9", pady=20)
        self.container.pack(fill="both", expand=True)

        tk.Label(self.container, text="Encrypt and Decrypt Files Securely", font=("Arial", 20), bg="#f9f9f9").pack(pady=10)
        tk.Label(self.container, text="SecureFiles allows you to encrypt or decrypt files securely.", bg="#f9f9f9", font=("Arial", 12)).pack(pady=5)

        tk.Label(self.container, text="Upload a File:", bg="#f9f9f9").pack(pady=5)
        self.file_label = tk.Label(self.container, text="No file selected", bg="#f9f9f9", fg="gray")
        self.file_label.pack(pady=5)
        tk.Button(self.container, text="Choose File", command=self.select_file, bg="#444", fg="white").pack(pady=5)

        tk.Label(self.container, text="Enter a Password:", bg="#f9f9f9").pack(pady=5)
        self.password_entry = tk.Entry(self.container, show="*", width=40)
        self.password_entry.pack(pady=5)
        self.password_entry.bind("<KeyRelease>", self.update_password_strength)

        self.strength_label = tk.Label(self.container, text="Password Strength: ", bg="#f9f9f9", font=("Arial", 12))
        self.strength_label.pack(pady=5)

        self.strength_bar = tk.Canvas(self.container, width=200, height=10, bg="#ddd", bd=0, highlightthickness=0)
        self.strength_bar.pack(pady=5)

        self.button_frame = tk.Frame(self.container, bg="#f9f9f9")
        self.button_frame.pack(pady=20)
        tk.Button(self.button_frame, text="Encrypt", command=self.encrypt_file, bg="#28a745", fg="white", width=12).grid(row=0, column=0, padx=10)
        tk.Button(self.button_frame, text="Decrypt", command=self.decrypt_file, bg="#dc3545", fg="white", width=12).grid(row=0, column=1, padx=10)

        self.download_btn = tk.Button(self.container, text="Save Processed File", command=self.download_file, bg="#0069d9", fg="white", state="disabled")
        self.download_btn.pack(pady=10)

    def show_home(self):
        messagebox.showinfo("Home", "Welcome to SecureFiles! Use the app to encrypt or decrypt files.")

    def open_github(self):
        import webbrowser
        webbrowser.open("https://github.com/ferid333")

    def select_file(self):
        file_path = filedialog.askopenfilename(title="Select a file")
        if file_path:
            self.file_path = file_path
            self.file_label.config(text=f"Selected File: {os.path.basename(file_path)}")

    def derive_key(self, password):
        salt = b"securefiles_salt"
        kdf = PBKDF2HMAC(
            algorithm=SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    def process_file(self, data, action, key):
        fernet = Fernet(key)
        return fernet.encrypt(data) if action == "encrypt" else fernet.decrypt(data)

    def encrypt_file(self):
        self.process_and_enable_save("encrypt")

    def decrypt_file(self):
        self.process_and_enable_save("decrypt")

    def process_and_enable_save(self, action):
        if not self.file_path:
            messagebox.showerror("Error", "No file selected!")
            return

        password = self.password_entry.get()
        if not password:
            messagebox.showerror("Error", "Password is missing!")
            return

        try:
            key = self.derive_key(password)
            with open(self.file_path, 'rb') as file:
                data = file.read()

            self.processed_data = self.process_file(data, action, key)
            self.action = action
            self.download_btn.config(state="normal")
            messagebox.showinfo("Success", f"File {action}ed successfully!\nClick 'Save Processed File' to download.")
        except Exception as e:
            messagebox.showerror("Error", f"{action.capitalize()}ion failed: {e}")

    def download_file(self):
        if self.processed_data is None or self.action is None:
            messagebox.showerror("Error", "No processed data to save!")
            return

        if self.action == "encrypt":
            output_file = self.file_path + ".enc"
        elif self.action == "decrypt" and self.file_path.endswith(".enc"):
            output_file = self.file_path[:-4]
        else:
            output_file = self.file_path + "_decrypted"

        try:
            with open(output_file, 'wb') as file:
                file.write(self.processed_data)
            messagebox.showinfo("Success", f"Processed file saved as:\n{output_file}")
            self.download_btn.config(state="disabled")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save file: {e}")

    def update_password_strength(self, event):
        password = self.password_entry.get()
        strength, color = self.evaluate_password_strength(password)
        self.strength_label.config(text=f"Password Strength: {strength}", fg=color)
        self.update_strength_bar(strength)

    def evaluate_password_strength(self, password):
        length = len(password) >= 8
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*()-_=+[]{}|;:',.<>?/" for c in password)

        score = sum([length, has_upper, has_lower, has_digit, has_special])

        if score == 5:
            return "Strong", "green"
        elif score >= 3:
            return "Medium", "orange"
        else:
            return "Weak", "red"

    def update_strength_bar(self, strength):
        colors = {"Weak": "red", "Medium": "orange", "Strong": "green"}
        widths = {"Weak": 50, "Medium": 100, "Strong": 200}

        self.strength_bar.delete("all")
        self.strength_bar.create_rectangle(0, 0, widths[strength], 10, fill=colors[strength], outline="")


if __name__ == "__main__":
    root = tk.Tk()
    app = SecureFilesApp(root)
    root.mainloop()