System Architecture — CryptoVault

Overview
CryptoVault is composed of four main modules that work together to ensure the security and integrity of user actions. 
These modules are:
Authentication Module (Module 1)
File Encryption Module (Module 3)
Messaging Module (Module 2)
Blockchain Audit Ledger (Module 4)

Each module is responsible for a specific part of the system, and events are logged in the blockchain to ensure immutability.
Modules Interaction

Authentication:
User registers with a username and password.
A TOTP secret is generated, and the user can log in with their password and the TOTP code.
Login events are logged to the blockchain.

File Encryption:
Users can upload files and encrypt them with a password.
Encrypted files are stored, and the hashes are logged to the blockchain.
Events are also logged to the blockchain.

Blockchain Audit Ledger:
Each important action (login, file encryption) is recorded as a transaction in the blockchain.
Merkle Trees and Proof of Work (PoW) are used to ensure data integrity.

Mining:
A block is mined when enough transactions accumulate. This involves solving a Proof of Work problem, which is a nonce that results in a hash with a certain number of leading zeros.

System Design
The modules are integrated into a Flask application, where each action (like login or file encryption) triggers an event that is logged in the blockchain. The blockchain provides an immutable record of all actions.
Flask app serves the frontend and interacts with each module.
Blockchain stores a record of all important events.
File Encryption module handles AES encryption and decryption, ensuring file confidentiality.
Authentication handles user login, registration, and multi-factor authentication.