"""
Client side — UDP Multi-Client Chat Application — Secure Edition
COMP 3500 Final Project  (Homework 1 hardened with five security controls)

Extends the Homework 1 client with encryption, a login step, and client-side
input validation — while keeping the original threaded receiver, the
print_lock prompt handling, and the 'bye' exit behavior.
"""

import socket
import base64
import getpass
import threading

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ── Configuration ──────────────────────────────────────────────
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 12345
BUFFER_SIZE = 4096
MAX_MESSAGE_LENGTH = 500

# Must match the server so the two derive the same channel key.
GROUP_SECRET = "comp3500-secure-channel"
_KDF_SALT = b"comp3500-static-salt"

# Prevent print() and input() from stepping on each other
print_lock = threading.Lock()


# ── Encryption (matches the server so they interoperate) ────────
def _make_key(secret):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                     salt=_KDF_SALT, iterations=200_000)
    return base64.urlsafe_b64encode(kdf.derive(secret.encode()))


fernet = Fernet(_make_key(GROUP_SECRET))


def encrypt(text):
    """Encrypt a plaintext string into a datagram-ready blob."""
    return fernet.encrypt(text.encode())


def decrypt(blob):
    """Decrypt a blob back to text. Raises on tamper / wrong key."""
    return fernet.decrypt(blob).decode()


# ── Input validation (client-side too — defense in depth) ───────
def sanitize(text):
    text = text[:MAX_MESSAGE_LENGTH]
    return "".join(ch for ch in text if ch == "\t" or (ch >= " " and ch != "\x7f"))


def receive_messages(client_socket):
    """
    Background thread that listens for incoming broadcast messages from the
    server, decrypts them, and prints them.
    """
    while True:
        try:
            blob, _ = client_socket.recvfrom(BUFFER_SIZE)

            # Ignore any packet we can't decrypt (corrupted / forged)
            try:
                message = decrypt(blob).strip()
            except (InvalidToken, ValueError):
                continue

            with print_lock:
                # Move to a new line, print the message, reprint the prompt
                print(f"\r{message}")
                print("You: ", end="", flush=True)

        except OSError:
            # Socket was closed (user typed 'bye')
            break
        except Exception as e:
            print(f"\n[ERROR] Receiving message: {e}")
            break


def start_client():
    """Create the UDP socket, log in, and enter the send loop."""

    # Creates a client side UDP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = (SERVER_HOST, SERVER_PORT)

    print("Secure UDP Chat")
    print(f"Server: {SERVER_HOST}:{SERVER_PORT}")

    # ── Authentication: collect credentials and send a login request ──
    username = input("Username: ").strip()
    try:
        password = getpass.getpass("Password: ")
    except Exception:
        password = input("Password: ")

    print("Type your message below. Type 'bye' to exit.\n")

    # Start receive thread
    recv_thread = threading.Thread(
        target=receive_messages,
        args=(client_socket,),
        daemon=True
    )
    recv_thread.start()

    # Send the login signal (encrypted) instead of the old __JOIN__ signal
    client_socket.sendto(encrypt(f"__LOGIN__|{username}|{password}"), server_address)

    # Send loop
    try:
        while True:
            with print_lock:
                print("You: ", end="", flush=True)

            # Read input WITHOUT printing "You: "
            message = input()

            if not message.strip():
                continue

            # Graceful exit
            if message.strip().lower() == "bye":
                client_socket.sendto(encrypt("bye"), server_address)
                print("Disconnected from chat. Goodbye!")
                break

            # Send the (validated, encrypted) message to the server
            client_socket.sendto(encrypt(sanitize(message)), server_address)

    except KeyboardInterrupt:
        try:
            client_socket.sendto(encrypt("bye"), server_address)
        except Exception:
            pass
        print("\nDisconnected.")

    finally:
        client_socket.close()


if __name__ == "__main__":
    start_client()
