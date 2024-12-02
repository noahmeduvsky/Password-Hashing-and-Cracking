import random
import string
import hashlib
import tkinter as tk
from tkinter import messagebox

# --------------- PASSWORD GENERATION FUNCTION ---------------
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

# --------------- PASSWORD STRENGTH EVALUATION FUNCTION ---------------
def evaluate_password_strength(password):
    length = len(password)
    score = 0

    # Criteria for strong password
    if length >= 8:
        score += 1  # Adds 1 point for length
    if any(char.isdigit() for char in password):
        score += 1  # Adds 1 point for having numbers
    if any(char.islower() for char in password):
        score += 1  # Adds 1 point for having lowercase letters
    if any(char.isupper() for char in password):
        score += 1  # Adds 1 point for having uppercase letters
    if any(char in string.punctuation for char in password):
        score += 1  # Adds 1 point for having special characters

    # Determine password strength based on score
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

# --------------- PASSWORD HASHING FUNCTION ---------------
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# --------------- BRUTE FORCE ATTACK FUNCTION ---------------
def brute_force_crack(hashed_password, character_set, max_length=8, max_attempts=1000000):
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

# --------------- DICTIONARY ATTACK FUNCTION ---------------
def dictionary_attack(hashed_password, wordlist):
    attempts = 0
    for password in wordlist:
        attempts += 1
        if hash_password(password) == hashed_password:
            return password, attempts
    return None, attempts

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

# --------------- CRACK PASSWORD FUNCTION ---------------
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

# --------------- PASSWORD GENERATION AND EVALUATION GUI FUNCTION ---------------
def generate_and_evaluate_password():
    # Get input values from the GUI
    length = int(entry_length.get())
    use_uppercase = var_uppercase.get()
    use_numbers = var_numbers.get()
    use_special = var_special.get()

    # Generate the password
    password = generate_password(length, use_uppercase, use_numbers, use_special)

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

# --------------- HASH PASSWORD FUNCTION ---------------
def hash_user_password():
    # Get the user-entered password and hash it
    user_password = text_user_password.get("1.0", tk.END).strip()
    hashed_user_password = hash_password(user_password)

    # Display the hashed password in the text box
    text_hashed.delete(1.0, tk.END)
    text_hashed.insert(tk.END, hashed_user_password)

    # Evaluate the strength of the password
    strength = evaluate_password_strength(user_password)
    label_strength.config(text=f"Strength: {strength}")  # Update label with strength

# --------------- GAME WINDOW FUNCTION ---------------
def open_start_menu():
    start_menu_frame.pack_forget()  # Hide the start menu
    game_frame.pack()  # Show the game window

def open_password_info():
    # Create a new window with detailed information on creating strong passwords
    info_window = tk.Toplevel(root)
    info_window.title("How to Create Strong Passwords")
    
    # Introduction Section
    tk.Label(info_window, text="Why Strong Passwords Are Important:", font=("Helvetica", 16, "bold")).pack(pady=10)
    tk.Label(info_window, text="Passwords are the first line of defense against unauthorized access to your accounts and personal information. A weak password can easily be guessed or cracked by attackers, putting your sensitive data at risk.", font=("Helvetica", 12), wraplength=480).pack(pady=10)
    
    tk.Label(info_window, text="The consequences of a weak password include:", font=("Helvetica", 14, "italic")).pack(pady=10)
    tk.Label(info_window, text="- Identity theft, where attackers steal your personal information.", font=("Helvetica", 12), wraplength=480).pack(pady=5)
    tk.Label(info_window, text="- Financial loss, from unauthorized access to bank accounts or credit cards.", font=("Helvetica", 12), wraplength=480).pack(pady=5)
    tk.Label(info_window, text="- Loss of privacy, with hackers gaining access to sensitive or personal data.", font=("Helvetica", 12), wraplength=480).pack(pady=5)
    
    tk.Label(info_window, text="To protect yourself, it's essential to create strong, unique passwords for every account you have. Below are tips on how to create strong passwords:", font=("Helvetica", 16, "bold")).pack(pady=15)

    # Creating Strong Passwords Section
    tk.Label(info_window, text="1. Use a minimum of 12 characters.", font=("Helvetica", 14)).pack(pady=5)
    tk.Label(info_window, text="Longer passwords are more difficult for attackers to guess. Aim for at least 12 characters to increase security.", font=("Helvetica", 12), wraplength=480).pack(pady=5)
    
    tk.Label(info_window, text="2. Use a mix of uppercase and lowercase letters.", font=("Helvetica", 14)).pack(pady=5)
    tk.Label(info_window, text="Using both uppercase and lowercase letters increases the complexity of your password.", font=("Helvetica", 12), wraplength=480).pack(pady=5)
    
    tk.Label(info_window, text="3. Include numbers and special characters.", font=("Helvetica", 14)).pack(pady=5)
    tk.Label(info_window, text="Incorporating numbers and special characters (e.g., !, @, #, $, %, ^) adds further complexity and reduces the likelihood of a successful brute-force attack.", font=("Helvetica", 12), wraplength=480).pack(pady=5)
    
    tk.Label(info_window, text="4. Avoid using common words, personal information, or predictable patterns.", font=("Helvetica", 14)).pack(pady=5)
    tk.Label(info_window, text="Common words or personal information (like your name, birthdate, or simple sequences like '1234') can easily be guessed by attackers. Avoid using such easy-to-predict combinations.", font=("Helvetica", 12), wraplength=480).pack(pady=5)

    tk.Label(info_window, text="5. Use a unique password for each account.", font=("Helvetica", 14)).pack(pady=5)
    tk.Label(info_window, text="Never reuse the same password across multiple sites. If one site gets compromised, all your accounts will be vulnerable.", font=("Helvetica", 12), wraplength=480).pack(pady=5)
    
    tk.Label(info_window, text="6. Consider using a password manager.", font=("Helvetica", 14)).pack(pady=5)
    tk.Label(info_window, text="A password manager can help you store and manage unique, complex passwords for each of your accounts without needing to remember all of them.", font=("Helvetica", 12), wraplength=480).pack(pady=5)

    tk.Label(info_window, text="7. Enable two-factor authentication (2FA) where possible.", font=("Helvetica", 14)).pack(pady=5)
    tk.Label(info_window, text="In addition to a strong password, two-factor authentication (2FA) adds an extra layer of security by requiring a second form of identification (e.g., a code sent to your phone).", font=("Helvetica", 12), wraplength=480).pack(pady=5)

    # Footer Section
    tk.Label(info_window, text="By following these tips, you can greatly improve the security of your online accounts and protect your personal data.", font=("Helvetica", 14, "italic")).pack(pady=20)
    
    info_window.geometry("1000x1000")  # Set window size to fit the content

def end_game():
    # Hide the game frame and show the start menu
    game_frame.pack_forget()
    start_menu_frame.pack()

def quit_game():
    # Terminate the application
    root.quit()

# --------------- CREATE THE MAIN WINDOW AND GUI ELEMENTS ---------------
root = tk.Tk()
root.title("Password Generation and Hacking")

# --------------- Set the image path based on the environment ---------------
if getattr(sys, 'frozen', False):  # If running as a bundled executable
    image_path = os.path.join(sys._MEIPASS, "image.png")
else:  # If running as a Python script
    image_path = "image.png"  # Same folder as app.py

# Load the background image
background_image = tk.PhotoImage(file=image_path)
background_label = tk.Label(root, image=background_image)
background_label.place(relwidth=1, relheight=1)

# --------------- START MENU GUI ---------------
start_menu_frame = tk.Frame(root)
start_menu_frame.pack()

# Start Game button
start_game_button = tk.Button(start_menu_frame, text="Start Game", font=("Helvetica", 16), command=open_start_menu)
start_game_button.pack(pady=20)

# Learn about strong passwords button
learn_button = tk.Button(start_menu_frame, text="Learn About Strong Passwords", font=("Helvetica", 16), command=open_password_info)
learn_button.pack(pady=20)

# Quit button
quit_button = tk.Button(start_menu_frame, text="Quit", font=("Helvetica", 16), command=quit_game)
quit_button.pack(pady=20)

# --------------- GAME WINDOW GUI ---------------
game_frame = tk.Frame(root)
game_frame.pack_forget()  # Hide the game frame initially

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
end_game_button = tk.Button(game_frame, text="End Game", font=("Helvetica", 16), command=end_game)
end_game_button.pack(pady=20)

root.geometry("600x400")  # Set window size
root.mainloop()
