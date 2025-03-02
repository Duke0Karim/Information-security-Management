import itertools
import string
import os
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext

# Default dictionary file path
DICTIONARY_PATH = r"password.list"

class PasswordCrackerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Cracker")
        self.root.geometry("600x450")

        # Title Label
        tk.Label(root, text="Password Cracker", font=("Arial", 16, "bold")).pack(pady=10)

        # Password Entry
        tk.Label(root, text="Enter Correct Password:").pack()
        self.password_entry = tk.Entry(root, show="*", width=30)
        self.password_entry.pack(pady=5)

        # Output Text Area
        self.output_text = scrolledtext.ScrolledText(root, width=70, height=15)
        self.output_text.pack(padx=10, pady=10)

        # Buttons
        self.btn_dictionary_attack = tk.Button(root, text="Start Dictionary Attack", command=self.dictionary_attack)
        self.btn_dictionary_attack.pack(pady=5)

        self.btn_brute_force_attack = tk.Button(root, text="Start Brute Force Attack", command=self.brute_force_attack)
        self.btn_brute_force_attack.pack(pady=5)

    def log_message(self, message):
        """Logs messages to the GUI text area."""
        self.output_text.insert(tk.END, message + "\n")
        self.output_text.see(tk.END)
        self.root.update()

    def get_correct_password(self):
        """Retrieves the correct password from the entry field."""
        return self.password_entry.get().strip()

    def load_dictionary(self):
        """Loads the dictionary file into a list."""
        if not os.path.exists(DICTIONARY_PATH):
            messagebox.showerror("Error", f"Dictionary file not found at:\n{DICTIONARY_PATH}")
            return []
        
        with open(DICTIONARY_PATH, "r", encoding="utf-8") as file:
            return [line.strip() for line in file.readlines()]

    def dictionary_attack(self):
        """Attempts to crack the password using a dictionary attack."""
        correct_password = self.get_correct_password()
        if not correct_password:
            messagebox.showwarning("Warning", "Please enter the correct password before starting.")
            return

        self.log_message("🔍 Starting dictionary attack...")
        dictionary = self.load_dictionary()

        for word in dictionary:
            self.log_message(f"Trying: {word}")
            if word == correct_password:
                self.log_message(f"✅ Password found using dictionary attack: {word}")
                messagebox.showinfo("Success", f"Password found: {word}")
                return True

        self.log_message("❌ Dictionary attack failed.")
        return False

    def brute_force_attack(self):
        """Attempts to crack the password using brute force (all possible 5-letter combinations)."""
        correct_password = self.get_correct_password()
        if not correct_password:
            messagebox.showwarning("Warning", "Please enter the correct password before starting.")
            return

        self.log_message("🚀 Starting brute force attack...")

        characters = string.ascii_letters  # A-Z, a-z
        for attempt in itertools.product(characters, repeat=5):
            guess = "".join(attempt)
            self.log_message(f"Trying: {guess}")
            if guess == correct_password:
                self.log_message(f"✅ Password found using brute force: {guess}")
                messagebox.showinfo("Success", f"Password found: {guess}")
                return True
        
        self.log_message("❌ Brute force attack failed.")
        return False

# Run the GUI
if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordCrackerGUI(root)
    root.mainloop()
