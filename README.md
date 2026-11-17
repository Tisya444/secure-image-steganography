# Secure Image Steganography Using AES-256-GCM and LSB

A college mini project web application built with Python and Flask. It encrypts a text message with AES-256-GCM, then hides the encrypted bytes inside RGB pixel least-significant bits of a PNG image.

## Features
- Hide a text message inside a PNG image.
- Password-based key derivation with scrypt.
- Authenticated AES-256-GCM encryption.
- Extract and decrypt the message using the correct password.
- Basic image quality measurement using PSNR.
- No database required; uploaded images are processed in memory.

## Requirements
- Python 3.10 or later
- pip

## Run locally

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000 in your browser.

## How to test
1. Choose a reasonably large PNG image (e.g. 800 x 600).
2. Enter a short message and a password of at least 8 characters.
3. Submit **Encrypt & Hide Message**. Save `stego_image.png`.
4. In the extraction panel, upload that downloaded PNG and enter the same password.
5. Confirm that the original message is recovered.
6. Try a wrong password; authenticated decryption should fail.

## Algorithm details
- The message is encrypted using AES-256-GCM.
- The 256-bit AES key is derived from the password with scrypt and a random 16-byte salt.
- A random 12-byte nonce is used for every encryption.
- Payload layout: `STG1 | salt (16 bytes) | nonce (12 bytes) | ciphertext + GCM tag`.
- The payload is preceded by a 4-byte big-endian length field.
- Payload bits are stored in the LSB of each flattened RGB channel value.

## Important limitations
- Use PNG only. JPEG is lossy and will normally corrupt the embedded bits.
- Resizing, cropping, recompressing, or editing the stego-image can destroy the message.
- LSB embedding is not resistant to steganalysis; it is a teaching implementation.
- Capacity is limited to approximately one bit per RGB channel (three bits per pixel), less the payload header.
- Use a larger image or shorter message if the capacity warning appears.
- The app limits uploads to 12 MB and messages to 10,000 UTF-8 bytes.

## Suggested viva topics
1. Difference between cryptography and steganography.
2. Why encrypt before hiding?
3. What is the least significant bit?
4. Why is PNG preferred over JPEG?
5. What do salt and nonce do?
6. Why does AES-GCM detect a wrong password or modified ciphertext?
7. What is PSNR and what does it tell us?
8. What are the limitations of LSB steganography?

## Academic extension ideas
- Add user accounts and access control.
- Compare LSB with adaptive or edge-based embedding.
- Add histogram analysis and a steganalysis warning.
- Plot PSNR against message size for different cover images.
