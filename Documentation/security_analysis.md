Security Analysis — CryptoVault

1. Assets (What We Are Protecting)

User Credentials: Password hashes and TOTP secrets
Files: File encryption keys and encrypted files
Audit Logs: The blockchain audit trail, ensuring event immutability
Session Tokens: Used for user authentication

2. Threats (Potential Attackers)

External Attackers: Hackers attempting to brute-force passwords or intercept communication
Malicious Insiders: Employees who have access to sensitive data
Compromised Clients: If a user's device is compromised, the attacker can potentially access plaintext data

3. Threat Model

3.1 Assets Identification

We need to protect the following assets:
User credentials: Hashes of passwords and the TOTP secret used for multi-factor authentication.
Encrypted files: The encryption keys and the actual encrypted files.
Audit logs: The blockchain that tracks login, file encryption events, and other significant actions.
Session tokens: These are used for authenticated user sessions, and their security is crucial to maintaining the integrity of the application.

3.2 Threat Actors

The potential threat actors that could compromise the security of this system include:
External Attackers: Individuals or groups with malicious intent trying to hack the system. This could include attackers attempting to crack passwords or intercept communications between the client and the server.
Malicious Insiders: Employees or contractors who have authorized access to the system, but misuse this access for malicious purposes.
Compromised Clients: Users' devices being compromised. If an attacker gains control of a user's device, they could access encrypted files or even potentially steal session tokens.

3.3 Attack Vectors

The potential attack vectors (ways in which attackers could exploit the system) include:
Brute-Force Attacks: Attackers trying to guess user passwords through a brute-force method.
Man-in-the-Middle (MITM) Attacks: Interception of communication between the client and the server, potentially allowing attackers to steal session tokens, passwords, or files.
Replay Attacks: Intercepted messages or file operations that are replayed to perform malicious actions, like re-encrypting files or gaining unauthorized access.
File Tampering: Modification or corruption of encrypted files, which could lead to data loss or unauthorized access to sensitive information.

4. Mitigations (How We Defend)

4.1 Password Brute-Force Protection

To mitigate brute-force attacks on user passwords, we use the following measures:
bcrypt for password hashing, which includes salting the hashes to protect against rainbow table attacks.
Rate limiting on login attempts to prevent repeated login attempts in a short period of time.


4.2 Man-in-the-Middle (MITM) Attack Mitigation

To defend against MITM attacks:
Use of ECDH (Elliptic Curve Diffie-Hellman) for key exchange, ensuring that even if an attacker intercepts the communication, they cannot decrypt it.
AES-GCM (Authenticated Encryption with Associated Data) is used for encrypting messages, ensuring data integrity and confidentiality.


4.3 File Tampering Prevention

To protect against file tampering:
HMAC (Hash-based Message Authentication Code) is used to verify the integrity of files before decryption, ensuring that files have not been altered.
SHA-256 is used to generate a hash of the original file, which is stored alongside the encrypted file. When the file is decrypted, the hash is verified to ensure that no tampering has occurred.


4.4 Replay Attack Mitigation

To prevent replay attacks:
Nonces (numbers used once) are included in the file encryption process and the blockchain mining process. These nonces ensure that every request and operation is unique and cannot be repeated.


5. Known Limitations

While we have implemented several security measures, there are still some known limitations:
No Hardware Security Module (HSM): The key management is done in software, which is less secure than using a hardware security module (HSM).
Single Machine Deployment: Currently, the prototype runs on a single machine. A distributed blockchain would be more secure but was not implemented in this project.
Simplified Proof of Work (PoW): The PoW algorithm used here is basic and would require more computational power in a real-world system to prevent malicious actors from easily mining blocks.
