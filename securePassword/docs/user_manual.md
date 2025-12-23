3. User Manual (User Manual)

3.1. Introduction

This application is designed to authenticate users with the ability to register, log in with two-factor authentication (TOTP), as well as reset the password via email.

3.2. User registration

Go to the registration page.

Enter your password and click "Register".

After that, you will receive a hashed password, which is stored in the system.

3.3. Login

Go to the login page.

Enter your registered password and TOTP code (you can get it in the application, for example, Google Authenticator).

If the data is correct, you will receive a JWT token that allows you to stay authorized.

3.4. Password reset

Go to the password reset request page.

Enter your email and click "Send password reset link".

Check your email and click on the password reset link.

Enter a new password and confirm the reset.

3.5. Profile

After a successful login, you can access the profile page, which is available only to authorized users.

3.6. Frequently Asked Questions (FAQ)

What should I do if I forgot my password?

Go to the password reset page and follow the instructions.