1. System architecture document (Architecture Document)

This document describes the general architecture of the system, its components, the connections between them and the main technologies that are used.

1.1. Introduction

Brief description of the system.

Goals and objectives of the application.

1.2. Application architecture

Description of application components: frontend, backend, databases, external services.

Architecture scheme:

Frontend (HTML, CSS, JavaScript).

Backend (Flask, Python).

Database (if used).

External services (e.g. Google Authenticator for TOTP).

1.3. System components

Frontend: HTML pages, data entry forms, UI processing.

Backend: Flask server, request processing, authentication management, JWT processing.

Security: Using bcrypt to hash passwords, pyotp for TOTP, JWT for authentication.

1.4. Database schema (if used)

Tables, their fields, links between tables.

1.5. Data streams

How data passes through the system (for example, from user input to creating a JWT token).