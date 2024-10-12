# Password Manager

## Overview

This Password Manager is a Python-based application that helps you securely store and manage account credentials. It provides an easy-to-use graphical interface, strong password generation, and encrypts all sensitive data to ensure the security of your accounts. Built with `Tkinter` and enhanced with `ttkbootstrap` for a modern theme, this tool offers a comprehensive solution for password management and data security.

## Features

### 1. **Account Management**
   - Store credentials (email, username, password, application name) securely.
   - Add, edit, and delete account information using an intuitive interface.
   - **Treeview Display**: Easily navigate through saved accounts with a treeview structure.

### 2. **Password Generation**
   - Generate strong, secure passwords with customizable options:
     - Include special characters, uppercase letters, and numbers.
     - Choose password length (8-24 characters).
   - Automatically copy the generated password to your clipboard.

### 3. **Data Security**
   - All passwords and sensitive information are encrypted using **Fernet encryption** from the `cryptography` library.
   - Secure key management with a Fernet encryption key.

### 4. **Email Notifications**
   - Integration with email services to send notifications when new accounts are added or edited (optional feature).
   - Email validation to ensure correct email formatting before saving.

### 5. **SQLite Database**
   - Credentials are stored locally in an **SQLite database**.
   - Easy data retrieval with built-in decryption for safe display of stored information.

### 6. **Modern User Interface**
   - The application uses the `ttkbootstrap` library to provide a sleek and modern look, with the **Cyborg** theme for dark mode.
   - Interactive buttons, entry fields, checkboxes, and a context menu (right-click) for editing or deleting accounts.

## Installation

### Prerequisites
Ensure that you have the following dependencies installed:

- **Python 3.x**
- **Required Python packages**: Install these packages using `pip`:

```bash
pip install -r requirements.txt
```

### Clone the Repository
```bash
git clone https://github.com/Valorrr/PasswordManager.git
cd PasswordManager
```

### Usage
## Run the Application

```bash
python3 main.py
```

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

## Future Improvements
I am working on integrating Amazon Simple Email Service (Amazon SES) to enhance the functionality of this application. This will allow users to receive updates directly via email, making it easier to keep track of any changes to their saved credentials. By utilizing Amazon SES, the application will be able to send reliable, scalable, and cost-effective emails with enhanced deliverability. Future updates will also include options to customize email content, such as adding user-defined email subjects and message templates.

## License
This project is open-source and available under the [MIT License](LICENSE).

## Author
This project was created by [Valor](https://github.com/Valorrr)

