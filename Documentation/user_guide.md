User Guide — CryptoVault

1. Registration

Go to /register.
Enter your desired username and strong password.
After registration, a TOTP secret is generated for two-factor authentication (TOTP).
Scan the displayed QR code with an authenticator app (Google Authenticator or similar).

2. Login

Go to /login.
Enter your username, password, and the 6-digit code from your authenticator app.
Upon successful login, you will be redirected to the dashboard, and an audit event will be logged to the blockchain.

3. File Encryption

Go to /encrypt-file.
Upload a file and enter a password to encrypt it.
The file is encrypted using AES-GCM, and the encrypted file hash is logged to the blockchain.
The encrypted file is stored, and you can later decrypt it by entering the correct password.

4. Ledger

Go to /ledger to view the blockchain.
You will see all events (login, file encryption) recorded in the blockchain as blocks.
You can mine a block by clicking the "Mine Block" button, which will add pending events to the blockchain.