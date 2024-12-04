Password Generation and Cracking Tool

Description

This is a password generation, evaluation, and cracking application that demonstrates how to generate random passwords, evaluate their strength, and perform common password cracking techniques, such as brute force, dictionary attacks, and rainbow table attacks. The app also allows the user to set a master password, store it in a database, and simulate cracking the master password using the aforementioned methods.

Features
- Generate random passwords with customizable criteria (length, uppercase, numbers, special characters).
- Evaluate password strength.
- Save and hash passwords.
- Crack hashed passwords using brute force, dictionary, and rainbow table attacks.
- Change or crack the master password stored in the database.

Requirements

Before running the application, ensure the following libraries are installed:

Required Libraries

1. cffi==1.17.1
2. cryptography==44.0.0
3. passlib==1.7.4
4. pycparser==2.22
5. pyperclip==1.9.0
6. PyQt5==5.15.11
7. PyQt5-Qt5==5.15.2
8. PyQt5_sip==12.15.0

These libraries can be installed using `pip`. To install all dependencies, you can use the provided `requirements.txt` file.

Setup and Installation

Step 1: Clone the repository or download the source files.
If you don't already have the repository, you can clone it using Git:

git clone <repository_url>
https://github.com/noahmeduvsky/Password-Hashing-and-Cracking.git

Step 2: Install the dependencies.
You can install the required libraries by running:

pip install -r requirements.txt

Ensure that you are using the correct Python environment. It is recommended to use a virtual environment to manage dependencies.

sqlite was used for the database in the project. Make sure to install it and add the PATH so that the application can run with the database. 

Step 3: Run the application.
Once the dependencies are installed, you can run the application using the following command:

python master.py

This will start the application, and the graphical user interface (GUI) will be displayed.

Step 4: Create a Master Password.
When you run the application for the first time, it will prompt you to set a master password. This master password will be used for accessing certain features of the application, like cracking the password database.

Step 5: Use the application.
You can:
- Generate random passwords.
- Crack a password using different attack methods.
- Save passwords to the database.
- Change the master password.

Troubleshooting
- If you encounter an error stating that a library is missing, make sure that all dependencies listed in the `requirements.txt` file are properly installed.
- If the application does not start, ensure that you're running it with the correct version of Python (preferably Python 3.x).
- If you have any other issues, feel free to open an issue in the repository's issue tracker.
