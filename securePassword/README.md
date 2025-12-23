# Secure Authentication System

## Description
This project implements a **Secure Authentication System** with **multi-factor authentication (MFA)**, **password hashing**, **JWT tokens**, and **TOTP (Time-based One-Time Password)** for secure user login and session management. The application supports **user registration**, **login with MFA**, **password reset**, and **account recovery**.

## Features
- **User Registration**: Register a user with a username, email, and password (hashed using bcrypt).
- **Login with MFA**: Login using a username, password, and TOTP code.
- **Password Reset**: Reset the user's password via a secure JWT token.
- **Account Recovery**: Recover the account using a recovery token sent to the user’s email.
- **Session Management**: Secure user session management with Flask-Session.

## Installation

1. **Clone the repository:**
    ```bash
    git clone https://github.com/yourusername/secure-authentication-system.git
    cd secure-authentication-system
    ```

2. **Create a virtual environment (optional but recommended):**
    ```bash
    python -m venv venv
    source venv/bin/activate  # For Windows use 'venv\Scripts\activate'
    ```

3. **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4. **Run the app:**
    ```bash
    python app.py
    ```

5. **Access the application in your browser:**
    Navigate to `http://127.0.0.1:5000/` for registration, login, and password reset.

## Technologies Used
- **Flask**: Web framework for Python.
- **bcrypt**: Password hashing for secure storage.
- **pyotp**: Time-based One-Time Password (TOTP) for MFA.
- **jwt**: JSON Web Tokens for secure session management.
- **Flask-Session**: Session management in Flask.

## Folder Structure

- `app.py`: Contains the main application logic for registration, login, password reset, and session management.
- `templates/`: Contains HTML files for the web pages:
    - `login.html`: Page for users to login.
    - `register.html`: Page for users to register.
    - `reset_password.html`: Page for users to request a password reset.
    - `reset_password_confirm.html`: Page to confirm password reset after entering a reset token.

## Security Considerations
- **Password Hashing**: Passwords are hashed using **bcrypt** to ensure secure storage.
- **TOTP**: Multi-factor authentication is implemented using **TOTP** with **pyotp** for extra security.
- **JWT**: Used for secure user sessions and token-based authentication.

## Testing
Unit tests are not yet implemented. To improve the project, consider adding tests to verify each component, such as:
- **User Registration**
- **Login**
- **Password Reset**
- **Account Recovery**
- **Session Management**

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
