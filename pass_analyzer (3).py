import tkinter as tk
from tkinter import messagebox
import re
import hashlib

# Function to analyze password strength
def analyze_password():
    password = entry.get()
    
    # Regex pattern checks
    length_ok = len(password) >= 8
    lowercase_ok = re.search(r'[a-z]', password) is not None
    uppercase_ok = re.search(r'[A-Z]', password) is not None
    digit_ok = re.search(r'\d', password) is not None
    special_char_ok = re.search(r'[\W_]', password) is not None

    # Calculate strength level
    passed_criteria = sum([length_ok, lowercase_ok, uppercase_ok, digit_ok, special_char_ok])
    strength_levels = ["Very Weak", "Weak", "Moderate", "Strong", "Very Strong"]
    strength = strength_levels[passed_criteria - 1] if passed_criteria > 0 else "Very Weak"

    # Hash the password
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    
    # Display results
    result_label.config(text=f"Password Strength: {strength}")
    hash_label.config(text=f"SHA-256 Hash:\n{hashed_password}")

# GUI Setup
root = tk.Tk()
root.title("Password Analyzer")

tk.Label(root, text="Enter Password:").pack()
entry = tk.Entry(root, show="*", width=30)
entry.pack()

analyze_btn = tk.Button(root, text="Analyze", command=analyze_password)
analyze_btn.pack()

result_label = tk.Label(root, text="")
result_label.pack()

hash_label = tk.Label(root, text="", wraplength=300)
hash_label.pack()

root.mainloop()