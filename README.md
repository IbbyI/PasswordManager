# Password Manager

## Overview

This Password Manager is a Python-based application that helps you securely store and manage account credentials. It provides an easy-to-use graphical interface, strong password generation, and encrypts all sensitive data to ensure the security of your accounts. Built with `Tkinter` and enhanced with `ttkbootstrap` for a modern theme, this tool offers a comprehensive solution for password management and data security.

## Features

### 1. **Master Login Page**
   - **Secure Authentication**: The application starts with a master login page that ensures only authorized users can access the stored credentials.
   - **SHA-256 Hashing with Salt**: The master password is securely stored using SHA-256 hashing with a random 32-bit salt. This ensures that the password is hashed before storage, and the hash is verified during login, preventing plain-text password storage and enhancing security.

### 2. **Account Management**
   - **Store Credentials**: Securely store account information including email, username, password, and application name.
   - **Add, Edit, and Delete Options**: Easily manage account data through an intuitive interface with options to add, edit, or delete entries.
   - **Treeview Display**: Navigate through saved accounts with a treeview structure for quick access and overview of accounts.

### 3. **Password Generation**
   - **Strong Password Creation**: Generate secure, random passwords with customizable options.
   - **Customization Options**:
     - Include special characters, uppercase letters, and numbers.
     - Select password length (8-24 characters).
   - **Clipboard Copy**: Automatically copies the generated password to your clipboard for easy use.

### 4. **Data Security**
   - **Encryption with Fernet**: All passwords and sensitive data are encrypted using **Fernet encryption** from the `cryptography` library, ensuring that data remains secure.
   - **Secure Key Management**: The encryption key is securely managed to ensure that only authorized users can decrypt the information.

### 5. **Email Notifications**
   - **Optional Email Alerts**: Send notifications via email when new accounts are added or edited (optional).
   - **Email Validation**: Validates email formatting before allowing data to be saved, ensuring accuracy.

### 6. **SQLite Database**
   - **Local Storage**: Credentials are stored in an **SQLite database** on the local machine.
   - **Decryption on Retrieval**: Data is decrypted only when needed for display, ensuring stored information remains secure.

### 7. **Modern User Interface**
   - **ttkbootstrap Theme**: The application uses the `ttkbootstrap` library to provide a sleek and modern look.
   - **Dark Mode**: The **Cyborg** theme is used for a dark mode experience.
   - **Interactive Elements**: Includes interactive buttons, entry fields, checkboxes, and a context menu (right-click) for editing or deleting accounts.

## Installation

### Prerequisites
Ensure that you have the following dependencies installed:

- **Python 3.x**
- **Required Python packages**: Install these packages using `pip`:

  ```bash
  pip install -r requirements.txt

### Clone the Repository
```bash
git clone https://github.com/IbbyI/PasswordManager.git
cd PasswordManager
```

### Usage
## Run the Application

```bash
python3 main.py
```

###  Enable Email Notifications
## Create an Apps Password
- Head over to the [Google Apps Password Settings](https://myaccount.google.com/apppasswords).
- Login to your account.
- Create a new app-specific password and name it Password Manager.
- Insert your email into an environment variable named **email**.
- Insert your apps password into an environment variable named **appsPassword**.

## Adding Accounts
- Click the **Add Account** button.
- Enter your credentials and optionally choose to opt-in for newsletters.
- Submit the form, and your data will be securely saved.

## Viewing or Hiding Data
- Click **Show Data** to reveal saved credentials (decrypted on display).
- Click **Hide Data** to conceal stored information from view.

## Editing or Deleting Accounts
- Right-click any account in the table to either **Edit** or **Delete** it.

## Generating a Password
- Click the **Password Generator** button.
- Customize password settings (length, special characters, etc.).
- Generate and copy the password directly to your clipboard.

## Contributing
Feel free to fork this project, submit issues, or contribute improvements via pull requests.

## License
This project is open-source and available under the [MIT License](LICENSE).

## Author
This project was created by [Ibby](https://github.com/IbbyI).

