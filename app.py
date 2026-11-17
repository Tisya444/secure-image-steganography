import io
import os
import struct
import secrets
import hashlib
import numpy as np
from flask import Flask, render_template, request, send_file, flash, redirect, url_for
from PIL import Image, UnidentifiedImageError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))
app.config["MAX_CONTENT_LENGTH"] = 12 * 1024 * 1024  # 12 MB upload limit

MAGIC = b"STG1"
SALT_LEN = 16
NONCE_LEN = 12
HEADER_LEN = 4  # unsigned 32-bit payload length


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from the user's password using scrypt."""
    if not password:
        raise ValueError("Password cannot be empty.")
    return hashlib.scrypt(
        password.encode("utf-8"), salt=salt,
        n=2**14, r=8, p=1, dklen=32
    )


def encrypt_message(message: str, password: str) -> bytes:
    salt = secrets.token_bytes(SALT_LEN)
    nonce = secrets.token_bytes(NONCE_LEN)
    key = derive_key(password, salt)
    ciphertext = AESGCM(key).encrypt(nonce, message.encode("utf-8"), None)
    return MAGIC + salt + nonce + ciphertext


def decrypt_message(payload: bytes, password: str) -> str:
    minimum = len(MAGIC) + SALT_LEN + NONCE_LEN + 16
    if len(payload) < minimum or payload[:4] != MAGIC:
        raise ValueError("No valid project message was found in this image.")
    offset = 4
    salt = payload[offset:offset + SALT_LEN]
    offset += SALT_LEN
    nonce = payload[offset:offset + NONCE_LEN]
    offset += NONCE_LEN
    ciphertext = payload[offset:]
    key = derive_key(password, salt)
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
        return plaintext.decode("utf-8")
    except Exception as exc:
        raise ValueError("Decryption failed. Check the password or image.") from exc


def bytes_to_bits(data: bytes) -> np.ndarray:
    return np.unpackbits(np.frombuffer(data, dtype=np.uint8))


def bits_to_bytes(bits: np.ndarray) -> bytes:
    return np.packbits(bits).tobytes()


def encode_image(image: Image.Image, payload: bytes) -> Image.Image:
    """Embed [4-byte payload length][payload] into RGB channel LSBs."""
    rgb = image.convert("RGB")
    pixels = np.array(rgb, dtype=np.uint8)
    flat = pixels.reshape(-1)

    if len(payload) > 0xFFFFFFFF:
        raise ValueError("Message is too large.")

    packet = struct.pack(">I", len(payload)) + payload
    bits = bytes_to_bits(packet)

    if bits.size > flat.size:
        max_bytes = max(0, (flat.size // 8) - HEADER_LEN)
        raise ValueError(
            f"Image capacity exceeded. Approximate maximum encrypted payload: "
            f"{max_bytes} bytes. Please use a larger PNG image or shorter message."
        )

    flat[:bits.size] = (flat[:bits.size] & 0xFE) | bits
    return Image.fromarray(pixels, mode="RGB")


def decode_payload(image: Image.Image) -> bytes:
    rgb = image.convert("RGB")
    flat = np.array(rgb, dtype=np.uint8).reshape(-1)

    if flat.size < HEADER_LEN * 8:
        raise ValueError("Image is too small to contain a message.")

    length_bits = flat[:HEADER_LEN * 8] & 1
    payload_length = struct.unpack(">I", bits_to_bytes(length_bits))[0]
    total_bits = (HEADER_LEN + payload_length) * 8

    if payload_length == 0 or total_bits > flat.size:
        raise ValueError("No valid hidden message was detected.")

    payload_bits = flat[HEADER_LEN * 8:total_bits] & 1
    return bits_to_bytes(payload_bits)


def calculate_psnr(original: Image.Image, modified: Image.Image) -> float:
    a = np.asarray(original.convert("RGB"), dtype=np.float64)
    b = np.asarray(modified.convert("RGB"), dtype=np.float64)
    mse = np.mean((a - b) ** 2)
    if mse == 0:
        return float("inf")
    return 20 * np.log10(255.0 / np.sqrt(mse))


def read_uploaded_image(file_storage) -> Image.Image:
    if not file_storage or not file_storage.filename:
        raise ValueError("Please choose an image.")
    try:
        image = Image.open(file_storage.stream)
        if image.format != "PNG":
            raise ValueError("Please upload a PNG image. PNG avoids lossy compression.")
        image.load()
        return image.convert("RGB")
    except UnidentifiedImageError as exc:
        raise ValueError("The uploaded file is not a valid image.") from exc


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/encode")
def encode():
    try:
        image = read_uploaded_image(request.files.get("image"))
        message = request.form.get("message", "")
        password = request.form.get("password", "")
        if not message.strip():
            raise ValueError("Please enter a message.")
        if len(message.encode("utf-8")) > 10000:
            raise ValueError("Message is too long. Limit: 10,000 UTF-8 bytes.")
        if len(password) < 8:
            raise ValueError("Use a password with at least 8 characters.")

        payload = encrypt_message(message, password)
        stego = encode_image(image, payload)
        psnr = calculate_psnr(image, stego)

        output = io.BytesIO()
        stego.save(output, format="PNG")
        output.seek(0)

        flash(f"Message hidden successfully. Image PSNR: {psnr:.2f} dB.", "success")
        return send_file(
            output, mimetype="image/png", as_attachment=True,
            download_name="stego_image.png"
        )
    except ValueError as exc:
        flash(str(exc), "error")
    except Exception:
        app.logger.exception("Unexpected encoding error")
        flash("Something went wrong while encoding the image.", "error")
    return redirect(url_for("index"))


@app.post("/decode")
def decode():
    try:
        image = read_uploaded_image(request.files.get("image"))
        password = request.form.get("password", "")
        if not password:
            raise ValueError("Please enter the password.")

        payload = decode_payload(image)
        message = decrypt_message(payload, password)
        return render_template("index.html", decoded_message=message)
    except ValueError as exc:
        flash(str(exc), "error")
    except Exception:
        app.logger.exception("Unexpected decoding error")
        flash("Something went wrong while decoding the image.", "error")
    return redirect(url_for("index"))


@app.errorhandler(413)
def too_large(_error):
    flash("Upload too large. Maximum file size is 12 MB.", "error")
    return redirect(url_for("index"))


if __name__ == "__main__":
    # For local development only. Use a production WSGI server for deployment.
    app.run(host="127.0.0.1", port=5000, debug=False)
