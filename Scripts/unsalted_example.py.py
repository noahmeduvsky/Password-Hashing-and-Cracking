# --------------- IMPORTS ---------------
import random
import string
import hashlib
import sqlite3
import tkinter as tk
from tkinter import messagebox

# --------------- DATABASE FUNCTIONS ---------------
def create_password_table():
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS passwords (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        plain_text TEXT,
        hashed_password TEXT
    )
    ''')
    conn.commit()
    conn.close()

def create_master_password_table():
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS master_password (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        hashed_password TEXT
    )
    ''')
    conn.commit()
    conn.close()

def initialize_master_password_table():
    create_master_password_table()

def set_master_password(master_password):
    hashed_master_password = hash_password(master_password)
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM master_password')
    existing_master = cursor.fetchone()
    if not existing_master:
        cursor.execute('''INSERT INTO master_password (hashed_password) VALUES (?)''', (hashed_master_password,))
    conn.commit()
    conn.close()

def verify_master_password(input_password):
    hashed_input_password = hash_password(input_password)
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM master_password')
    stored_password = cursor.fetchone()
    conn.close()
    return stored_password and stored_password[1] == hashed_input_password

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def insert_password(plain_text_password):
    hashed_password = hash_password(plain_text_password)
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute('''INSERT INTO passwords (plain_text, hashed_password) VALUES (?, ?)''', (plain_text_password, hashed_password))
    conn.commit()
    conn.close()

def retrieve_passwords():
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM passwords')
    rows = cursor.fetchall()
    conn.close()
    return rows

def delete_all_passwords():
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM passwords")
    conn.commit()
    conn.close()
    messagebox.showinfo("Success", "All passwords have been deleted from the database.")

# --------------- PASSWORD GENERATION AND EVALUATION FUNCTIONS ---------------
def generate_password(length=12, use_uppercase=True, use_numbers=True, use_special_chars=True):
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase if use_uppercase else ''
    numbers = string.digits if use_numbers else ''
    special_chars = string.punctuation if use_special_chars else ''
    all_chars = lowercase + uppercase + numbers + special_chars
    if not all_chars:
        raise ValueError("No character sets selected for password generation")
    return ''.join(random.choice(all_chars) for _ in range(length))

def evaluate_password_strength(password):
    length = len(password)
    score = sum([
        length >= 8,
        any(char.isdigit() for char in password),
        any(char.islower() for char in password),
        any(char.isupper() for char in password),
        any(char in string.punctuation for char in password)
    ])
    return ["Very Weak", "Weak", "Moderate", "Strong", "Very Strong"][min(score, 5) - 1]

# Add all remaining functions logically grouped here

import random
import string
import hashlib
import sqlite3
import tkinter as tk
from tkinter import messagebox
import os
import sys

# --------------- DATABASE FUNCTIONS ---------------
def create_password_table():
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS passwords (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        plain_text TEXT,
        hashed_password TEXT
    )
    ''')
    
    conn.commit()
    conn.close()

def create_master_password_table():
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS master_password (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        hashed_password TEXT
    )
    ''')
    
    conn.commit()
    conn.close()

# Ensure the master password table exists
def initialize_master_password_table():
    create_master_password_table()  # Ensure the master password table is created

def set_master_password(master_password):
    hashed_master_password = hash_password(master_password)
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM master_password')
    existing_master = cursor.fetchone()
    
    if not existing_master:
        cursor.execute('''
        INSERT INTO master_password (hashed_password)
        VALUES (?)
        ''', (hashed_master_password,))
    
    conn.commit()
    conn.close()

def verify_master_password(input_password):
    hashed_input_password = hash_password(input_password)
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM master_password')
    stored_password = cursor.fetchone()
    
    conn.close()
    
    if stored_password and stored_password[1] == hashed_input_password:
        return True
    else:
        return False

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def insert_password(plain_text_password):
    hashed_password = hash_password(plain_text_password)
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute('''INSERT INTO passwords (plain_text, hashed_password) VALUES (?, ?)''', 
                   (plain_text_password, hashed_password))
    conn.commit()
    conn.close()

def retrieve_passwords():
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM passwords')
    rows = cursor.fetchall()
    conn.close()
    return rows

# --------------- MASTER PASSWORD SETTING DIALOG ---------------
def prompt_for_master_password():
    # Create a new top-level window for setting the master password
    master_password_window = tk.Toplevel(root)
    master_password_window.title("Set Master Password")
    
    tk.Label(master_password_window, text="Please set a master password:", font=("Helvetica", 14)).pack(pady=20)
    
    password_entry = tk.Entry(master_password_window, show="*", font=("Helvetica", 12))
    password_entry.pack(pady=10)
    
    tk.Label(master_password_window, text="Re-enter the password:", font=("Helvetica", 14)).pack(pady=10)
    password_confirm_entry = tk.Entry(master_password_window, show="*", font=("Helvetica", 12))
    password_confirm_entry.pack(pady=10)

    def save_master_password():
        master_password = password_entry.get()
        confirm_password = password_confirm_entry.get()

        # Ensure the passwords match
        if master_password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match. Please try again.")
            return
        
        # Set the master password in the database
        set_master_password(master_password)
        master_password_window.destroy()  # Close the password setting window
        open_start_menu()  # Open the main start menu after setting the master password

    # Button to confirm the master password
    set_button = tk.Button(master_password_window, text="Set Master Password", font=("Helvetica", 14), command=save_master_password)
    set_button.pack(pady=20)

    master_password_window.geometry("400x300")  # Set window size
    master_password_window.mainloop()

# --------------- PASSWORD GENERATION AND EVALUATION FUNCTION ---------------
def generate_password(length=12, use_uppercase=True, use_numbers=True, use_special_chars=True):
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase if use_uppercase else ''
    numbers = string.digits if use_numbers else ''
    special_chars = string.punctuation if use_special_chars else ''
    all_chars = lowercase + uppercase + numbers + special_chars

    if not all_chars:
        raise ValueError("No character sets selected for password generation")

    password = ''.join(random.choice(all_chars) for _ in range(length))
    return password

# --------------- PASSWORD GENERATION AND EVALUATION FUNCTION ---------------
def generate_and_evaluate_password():
    # Get input values from the GUI
    length = int(entry_length.get())
    use_uppercase = var_uppercase.get()
    use_numbers = var_numbers.get()
    use_special = var_special.get()

    # Generate the password
    password = generate_password(length, use_uppercase, use_numbers, use_special)

    # Store the password and hash it in the database
    insert_password(password)  # Save the password to the database

    # Display the password in the textbox
    text_password.delete(1.0, tk.END)  # Clear existing text
    text_password.insert(tk.END, password)

    # Hash the password for cracking attempts
    hashed_password = hash_password(password)
    text_hashed.delete(1.0, tk.END)  # Display the hashed password
    text_hashed.insert(tk.END, hashed_password)

    # Evaluate the password strength and display it
    strength = evaluate_password_strength(password)
    label_strength.config(text=f"Strength: {strength}")  # Update label with strength

    # Add a button to save the password to the database
    save_button = tk.Button(game_frame, text="Save Password to Database", font=("Helvetica", 14), command=lambda: insert_password(password))
    save_button.pack(pady=10)

def save_manual_password():
    user_password = text_user_password.get("1.0", tk.END).strip()  # Get the manually entered password
    if user_password:  # Check if the input field is not empty
        insert_password(user_password)  # Save it to the database
        messagebox.showinfo("Success", "Password saved to the database.")
    else:
        messagebox.showerror("Error", "Please enter a password.")

def delete_all_passwords():
    # Connect to the database
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()

    # Execute the DELETE command to remove all rows from the passwords table
    cursor.execute("DELETE FROM passwords")
    
    # Commit the changes and close the connection
    conn.commit()
    conn.close()
    
    # Inform the user that the passwords have been deleted
    messagebox.showinfo("Success", "All passwords have been deleted from the database.")

# --------------- HASH PASSWORD FUNCTION ---------------
def hash_user_password():
    user_password = text_user_password.get("1.0", tk.END).strip()  # Get the password from the input field
    hashed_user_password = hash_password(user_password)  # Hash the entered password

    # Display the hashed password in the text box
    text_hashed.delete(1.0, tk.END)  # Clear any previous data
    text_hashed.insert(tk.END, hashed_user_password)  # Insert the hashed password into the text box

    # Evaluate the strength of the entered password
    strength = evaluate_password_strength(user_password)  # Call the password strength evaluation function
    label_strength.config(text=f"Strength: {strength}")  # Display the strength of the entered password

# --------------- PASSWORD STRENGTH EVALUATION FUNCTION ---------------
def evaluate_password_strength(password):
    length = len(password)
    score = 0

    if length >= 8:
        score += 1
    if any(char.isdigit() for char in password):
        score += 1
    if any(char.islower() for char in password):
        score += 1
    if any(char.isupper() for char in password):
        score += 1
    if any(char in string.punctuation for char in password):
        score += 1

    if score == 5:
        return "Very Strong"
    elif score == 4:
        return "Strong"
    elif score == 3:
        return "Moderate"
    elif score == 2:
        return "Weak"
    else:
        return "Very Weak"

def crack_master_password():
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM master_password')
    master_password_data = cursor.fetchone()
    conn.close()

    if not master_password_data:
        messagebox.showerror("Error", "Master password is not set!")
        return

    hashed_master_password = master_password_data[1]
    print(f"Hashed Master Password: {hashed_master_password}")  # Debugging line

    # Brute force
    password, attempts = brute_force_crack(hashed_master_password, string.ascii_letters + string.digits + string.punctuation, max_attempts=1000000)
    if password:
        messagebox.showinfo("Success", f"Master Password Cracked: {password} in {attempts} attempts.")
        display_passwords()
        return

    # Dictionary attack
    common_passwords = ["123456", "password", "letmein", "qwerty", "1234"]
    password, attempts = dictionary_attack(hashed_master_password, common_passwords)
    if password:
        messagebox.showinfo("Success", f"Master Password Cracked: {password} in {attempts} attempts.")
        display_passwords()
        return

    # Rainbow table
    rainbow_table = generate_rainbow_table(string.ascii_letters + string.digits, max_length=6)
    cracked_password = rainbow_table_attack(hashed_master_password, rainbow_table)
    if cracked_password:
        messagebox.showinfo("Success", f"Master Password Cracked: {cracked_password}")
        display_passwords()
    else:
        messagebox.showerror("Failure", "Master password could not be cracked.")

# --------------- DISPLAY PASSWORDS FUNCTION ---------------
def display_passwords():
    rows = retrieve_passwords()  # This should return a list of tuples, each containing (id, plain_text, hashed_password)
    if not rows:
        messagebox.showinfo("No Data", "No stored passwords found.")
        return

    # Create a new window to display the passwords
    password_window = tk.Toplevel(root)
    password_window.title("Stored Passwords")
    
    # Create a textbox to display the passwords in a formatted way
    text_box = tk.Text(password_window, width=60, height=15, wrap="word", font=("Helvetica", 12))
    text_box.pack(pady=10)

    # Format each row for displaying
    for row in rows:
        id, plain_text, hashed_password = row
        text_box.insert(tk.END, f"ID: {id}, Hashed: {hashed_password}\n")

    # Add a button to close the window
    close_button = tk.Button(password_window, text="Close", command=password_window.destroy)
    close_button.pack(pady=10)

    password_window.geometry("500x400")

# --------------- DICTIONARY ATTACK FUNCTION ---------------
def dictionary_attack(hashed_password, wordlist):
    attempts = 0
    for password in wordlist:
        attempts += 1
        if hash_password(password) == hashed_password:
            return password, attempts
    return None, attempts

# --------------- BRUTE FORCE ATTACK FUNCTION ---------------
def brute_force_crack(hashed_password, character_set, max_length=12, max_attempts=1000000):
    attempts = 0
    for length in range(1, max_length + 1):
        for password in generate_passwords_of_length(length, character_set):
            attempts += 1
            if attempts >= max_attempts:
                return None, attempts
            if hash_password(password) == hashed_password:
                return password, attempts
    return None, attempts

def generate_passwords_of_length(length, character_set):
    if length == 1:
        for char in character_set:
            yield char
    else:
        for prefix in generate_passwords_of_length(length - 1, character_set):
            for char in character_set:
                yield prefix + char

# --------------- RAINBOW TABLE ATTACK FUNCTION ---------------
def generate_rainbow_table(character_set, max_length=4):
    rainbow_table = {}
    for length in range(1, max_length + 1):
        for password in generate_passwords_of_length(length, character_set):
            hashed = hash_password(password)
            rainbow_table[hashed] = password
    return rainbow_table

def rainbow_table_attack(target_hash, rainbow_table):
    if target_hash in rainbow_table:
        return rainbow_table[target_hash]
    else:
        return None

def crack_password():
    hashed_password = text_hashed.get("1.0", tk.END).strip()
    max_attempts = int(entry_max_attempts.get())

    if attack_method.get() == "Brute Force":
        char_set = string.ascii_lowercase + string.ascii_uppercase + string.digits + string.punctuation
        password, attempts = brute_force_crack(hashed_password, char_set, max_attempts=max_attempts)

        if password is None and attempts >= max_attempts:
            messagebox.showerror("Failure", f"Password could not be cracked after {attempts} attempts.")
        elif password:
            messagebox.showinfo("Success", f"Password cracked: {password} in {attempts} attempts.")
        else:
            messagebox.showerror("Failure", f"Password could not be cracked in {attempts} attempts.")
    
    elif attack_method.get() == "Dictionary Attack":
        common_passwords = [
            "123456", "password", "123456789", "qwerty", "abc123", "letmein",
            "welcome", "admin", "password1", "sunshine", "iloveyou"
        ]
        password, attempts = dictionary_attack(hashed_password, common_passwords)

        if password:
            messagebox.showinfo("Success", f"Password cracked: {password} in {attempts} attempts.")
        else:
            messagebox.showerror("Failure", f"Password could not be cracked in {attempts} attempts.")
    
    elif attack_method.get() == "Rainbow Table Attack":
        char_set = string.ascii_lowercase + string.digits
        rainbow_table = generate_rainbow_table(char_set, max_length=4)
        cracked_password = rainbow_table_attack(hashed_password, rainbow_table)

        if cracked_password:
            messagebox.showinfo("Success", f"Password cracked: {cracked_password}")
        else:
            messagebox.showerror("Failure", "Password could not be cracked using the rainbow table.")

# --------------- CHANGE MASTER PASSWORD DIALOG ---------------
def change_master_password():
    # Prompt the user to input the current master password
    change_window = tk.Toplevel(root)
    change_window.title("Change Master Password")

    tk.Label(change_window, text="Enter current master password:", font=("Helvetica", 12)).pack(pady=10)
    current_password_entry = tk.Entry(change_window, show="*", font=("Helvetica", 12))
    current_password_entry.pack(pady=10)

    def update_master_password():
        current_password = current_password_entry.get()
        if verify_master_password(current_password):  # Check if the current password is correct
            prompt_for_new_master_password(change_window)  # Proceed to set a new master password
            change_window.destroy()  # Close the window
        else:
            messagebox.showerror("Error", "Incorrect master password. Please try again.")

    # Button to confirm
    confirm_button = tk.Button(change_window, text="Confirm", font=("Helvetica", 14), command=update_master_password)
    confirm_button.pack(pady=20)

    change_window.geometry("400x300")
    change_window.mainloop()

def prompt_for_new_master_password(parent_window):
    new_master_password_window = tk.Toplevel(root)
    new_master_password_window.title("Set New Master Password")
    
    tk.Label(new_master_password_window, text="Enter the new master password:", font=("Helvetica", 14)).pack(pady=20)
    
    password_entry = tk.Entry(new_master_password_window, show="*", font=("Helvetica", 12))
    password_entry.pack(pady=10)
    
    tk.Label(new_master_password_window, text="Re-enter the new password:", font=("Helvetica", 14)).pack(pady=10)
    password_confirm_entry = tk.Entry(new_master_password_window, show="*", font=("Helvetica", 12))
    password_confirm_entry.pack(pady=10)

    def save_new_master_password():
        new_master_password = password_entry.get()
        confirm_password = password_confirm_entry.get()

        if new_master_password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match. Please try again.")
            return
        
        # Update the master password in the database
        hashed_new_password = hash_password(new_master_password)
        conn = sqlite3.connect('passwords.db')
        cursor = conn.cursor()

        cursor.execute("UPDATE master_password SET hashed_password = ? WHERE id = 1", (hashed_new_password,))
        conn.commit()
        conn.close()

        messagebox.showinfo("Success", "Master password updated successfully.")
        new_master_password_window.destroy()
        open_start_menu()

    set_button = tk.Button(new_master_password_window, text="Save New Password", font=("Helvetica", 14), command=save_new_master_password)
    set_button.pack(pady=20)

    new_master_password_window.geometry("400x300")
    new_master_password_window.mainloop()

# Function to initialize the start menu GUI
def initialize_start_menu():
    """Set up the start menu GUI."""
    tk.Label(start_menu_frame, text="Password Management System", font=("Helvetica", 16)).pack(pady=10)

    # Start Game button
    start_game_button = tk.Button(start_menu_frame, text="Start Game", font=("Helvetica", 16), command=lambda: switch_to_frame(game_frame))
    start_game_button.pack(pady=20)

    # Learn about strong passwords button
    learn_button = tk.Button(start_menu_frame, text="Learn About Strong Passwords", font=("Helvetica", 16), command=open_password_info)
    learn_button.pack(pady=20)

    # Change Master Password button
    change_master_button = tk.Button(start_menu_frame, text="Change Master Password", font=("Helvetica", 16), command=change_master_password)
    change_master_button.pack(pady=20)

    # Crack Master Password button
    crack_master_button = tk.Button(start_menu_frame, text="Crack Master Password", font=("Helvetica", 16), command=crack_master_password)
    crack_master_button.pack(pady=20)

    # Quit button
    quit_button = tk.Button(start_menu_frame, text="Quit", font=("Helvetica", 16), command=quit_game)
    quit_button.pack(pady=20)

# Function to switch frames
def switch_to_frame(target_frame):
    """Hide all frames and show the target frame."""
    start_menu_frame.pack_forget()
    game_frame.pack_forget()
    target_frame.pack()

# Function to set up the Start Menu frame
def setup_start_menu():
    """Initialize the Start Menu frame and its components."""
    tk.Label(start_menu_frame, text="Password Hashing and Cracking", font=("Helvetica", 16)).pack(pady=10)

    # Start Game button
    start_game_button = tk.Button(start_menu_frame, text="Start Game", font=("Helvetica", 16),
                                  command=lambda: switch_to_frame(game_frame))
    start_game_button.pack(pady=20)

    # Learn about strong passwords button
    learn_button = tk.Button(start_menu_frame, text="Learn About Strong Passwords", font=("Helvetica", 16),
                              command=open_password_info)
    learn_button.pack(pady=20)

    # Change Master Password button
    change_master_button = tk.Button(start_menu_frame, text="Change Master Password", font=("Helvetica", 16),
                                      command=change_master_password)
    change_master_button.pack(pady=20)

    # Crack Master Password button
    crack_master_button = tk.Button(start_menu_frame, text="Crack Master Password", font=("Helvetica", 16),
                                     command=crack_master_password)
    crack_master_button.pack(pady=20)

    # Quit button
    quit_button = tk.Button(start_menu_frame, text="Quit", font=("Helvetica", 16), command=quit_game)
    quit_button.pack(pady=20)

def setup_game_frame():
    global text_user_password, text_hashed, entry_length, attack_method, entry_max_attempts

    # Password Length input
    tk.Label(game_frame, text="Password Length:").pack()
    entry_length = tk.Entry(game_frame)
    entry_length.insert(tk.END, "12")  # Default length
    entry_length.pack()

    var_uppercase = tk.BooleanVar(value=True)
    tk.Checkbutton(game_frame, text="Include Uppercase", variable=var_uppercase).pack()

    var_numbers = tk.BooleanVar(value=True)
    tk.Checkbutton(game_frame, text="Include Numbers", variable=var_numbers).pack()

    var_special = tk.BooleanVar(value=True)
    tk.Checkbutton(game_frame, text="Include Special Characters", variable=var_special).pack()

    button_generate = tk.Button(game_frame, text="Generate Password", command=generate_and_evaluate_password)
    button_generate.pack()

    # Display the generated password
    tk.Label(game_frame, text="Generated Password:").pack()
    text_password = tk.Text(game_frame, height=2, width=40)
    text_password.pack()

    # Display the hashed password
    tk.Label(game_frame, text="Hashed Password (for Cracking):").pack()
    text_hashed = tk.Text(game_frame, height=2, width=40)
    text_hashed.pack()

    # Input field for user-entered password
    tk.Label(game_frame, text="Enter Your Own Password (for Cracking):").pack()
    text_user_password = tk.Text(game_frame, height=2, width=40)
    text_user_password.pack()

    # Button to save manually entered password to the database
    button_save_manual = tk.Button(game_frame, text="Save Password to Database", font=("Helvetica", 14),
                                    command=save_manual_password)
    button_save_manual.pack(pady=10)

    button_hash = tk.Button(game_frame, text="Hash Password", command=hash_user_password)
    button_hash.pack()

    # Display the password strength
    label_strength = tk.Label(game_frame, text="Strength: ")
    label_strength.pack()

    # Attack method selection
    attack_method = tk.StringVar(value="Brute Force")
    tk.Radiobutton(game_frame, text="Brute Force", variable=attack_method, value="Brute Force").pack()
    tk.Radiobutton(game_frame, text="Dictionary Attack", variable=attack_method, value="Dictionary Attack").pack()
    tk.Radiobutton(game_frame, text="Rainbow Table Attack", variable=attack_method, value="Rainbow Table Attack").pack()

    # Max Brute Force Attempts input
    tk.Label(game_frame, text="Max Brute Force Attempts:").pack()
    entry_max_attempts = tk.Entry(game_frame)
    entry_max_attempts.insert(tk.END, "1000000")  # Default value is 1 million
    entry_max_attempts.pack()

    # Button to crack the password
    button_crack = tk.Button(game_frame, text="Crack Password", command=crack_password)
    button_crack.pack()

    # End Game button (returns to start menu)
    end_game_button = tk.Button(game_frame, text="End Game", font=("Helvetica", 16),
                                 command=lambda: switch_to_frame(start_menu_frame))
    end_game_button.pack(pady=20)

    # Button to delete all passwords
    delete_button = tk.Button(game_frame, text="Delete All Passwords", font=("Helvetica", 14),
                               command=delete_all_passwords)
    delete_button.pack(pady=10)

# --------------- GAME WINDOW FUNCTION ---------------
def open_start_menu():
    game_frame.pack_forget()  # Hide the game frame
    start_menu_frame.pack()  # Show the start menu frame

def open_password_info():
    info_window = tk.Toplevel(root)
    info_window.title("How to Create Strong Passwords")
    
    # Introduction Section
    tk.Label(info_window, text="Why Strong Passwords Are Important:", font=("Helvetica", 16, "bold")).pack(pady=10)
    tk.Label(info_window, text="Passwords are the first line of defense against unauthorized access to your accounts and personal information. A weak password can easily be guessed or cracked by attackers, putting your sensitive data at risk.", font=("Helvetica", 12), wraplength=480).pack(pady=10)

    info_window.geometry("1000x1000")  # Adjust window size

def end_game():
    game_frame.pack_forget()  # Hide the game window
    start_menu_frame.pack()  # Show the start menu

def quit_game():
    root.quit()

# --------------- CREATE THE MAIN WINDOW AND GUI ELEMENTS ---------------
# Main GUI setup
root = tk.Tk()
root.title("Password Management System")
root.geometry("600x400")

# Global frames
start_menu_frame = tk.Frame(root)
game_frame = tk.Frame(root)

# Initialize frames
setup_start_menu()
setup_game_frame()

# Initialize database
initialize_master_password_table()
create_password_table()

# Check if master password is set
conn = sqlite3.connect('passwords.db')
cursor = conn.cursor()
cursor.execute('SELECT * FROM master_password')
master_password_row = cursor.fetchone()
conn.close()

if not master_password_row:  # Prompt for master password if not set
    prompt_for_master_password()
else:  # Open Start Menu
    open_start_menu()

# Start the application
root.mainloop()