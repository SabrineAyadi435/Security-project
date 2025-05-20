# Medicryptis – Secure Image Encryption Web Application

## Overview
**Medicryptis** is a web-based platform developed for secure communication between medical laboratories and patients. It focuses on encrypting and transmitting sensitive medical images (such as MRI or X-ray scans) using modern cryptographic algorithms. The application provides a secure messaging interface where encrypted images are shared and decrypted based on user roles.

## Purpose
The goal of Medicryptis is to ensure the confidentiality and integrity of medical images during transmission. It combines strong encryption (AES + RSA or ChaCha20) with visual obfuscation (pixelation) to protect patient data from unauthorized access.

##  User Registration and Roles

### Lab Staff Registration
When registering, include the keyword `lab_` in your username (e.g., `lab_alice`). This grants access to the lab dashboard where you can encrypt, decrypt, and send images.

### Patient Registration
Register with any other username (e.g., `john_doe`). Patients have access to a Gmail-style inbox where they receive encrypted images and can decrypt them with one click.

## Features
-  **AES + RSA hybrid encryption**
-  **ChaCha20 stream cipher encryption**
- **Pixelation of encrypted images for visual obfuscation**
-  **User authentication system** (staff and patients)
- **Encrypted image messaging system**
- **Role-based dashboards**
  - Lab staff: Encrypt, decrypt, and send images to patients.
  - Patients: View received encrypted images and decrypt them securely.

## Technologies Used
- **Frontend**: HTML, CSS , Jinja2 templates
- **Backend**: Python (Flask)
- **Cryptography**: PyCryptodome
- **Database**: SQLite
- **User Security**: Password hashing, strength checking (zxcvbn)
## Advanced Decryption Feature
This project includes an enhanced security feature for decrypting images. When a user attempts to decrypt an image, they are sent a random one-time code via email . The user must enter this code to proceed with decryption, adding an additional layer of protection for sensitive data.
A video demo showcasing this advanced feature is included in this repository to demonstrate the user experience and security workflow.
[▶️ Watch demo video](video/Medicryptis_advanced_version.mp4)
## Installation & Setup

Follow these steps to install and run the Medicryptis web application on your local machine.

---

### Step 1: Clone the Repository

```bash
git clone https://github.com/SabrineAyadi435/Security-project.git
cd Security-project
```
### Step 2: Create a Virtual Environment (Recommended)
Create a Python virtual environment to isolate dependencies.
#### On Windows:
```bash
python -m venv venv
venv\Scripts\activate
```
#### On macOS/Linux:
```bash
python -m venv venv
source venv/bin/activate
```
### Step 3: Install Required Packages
Make sure you have a requirements.txt file in the project root with the following content:
```ini
Flask==2.3.2
PyCryptodome==3.20.0
zxcvbn==4.4.28
Pillow==10.2.0
```
Then run:
```bash
pip install -r requirements.txt
```
### Step 4: Run the Flask Application
Start the app with:
```bash
python app.py
```
### Step 5: Access the Application
Open your web browser and navigate to:
```arduino
http://localhost:5000
```
## Inspecting Database Schema

To view the tables and their columns (schema) in the database, use the `inspect_database.py` script.

### How to Run

1. Activate your virtual environment and install dependencies if needed.
2. Run this command in the project directory:

```bash
python inspect_database.py
