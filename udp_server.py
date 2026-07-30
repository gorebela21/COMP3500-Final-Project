"""
UDP Multi-Client Chat Application — COMP 3500 Final Project  (Homework 1 hardened with five security controls)

This is the Homework 1 UDP multi-client chat server, extended with:
    1. Encryption       — every datagram is encrypted (Fernet: AES + HMAC)
    2. Authentication   — clients must log in before they can chat
    3. Rate limiting    — caps messages/sec per client to resist flooding
    4. Input validation — length cap + control-character stripping
    5. Logging          — security events timestamped to server.log

The original structure (function-based, a `clients` collection, broadcast(),
get_timestamp(), the __JOIN__/bye control signals) is preserved.
"""

import os
import socket
import base64
import hashlib
import logging
import datetime
from collections import deque

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ── Configuration ──────────────────────────────────────────────
HOST = "127.0.0.1"
PORT = 12345
BUFFER_SIZE = 4096
MAX_MESSAGE_LENGTH = 500          # input-validation cap (characters)

# Shared channel secret — the client must use the same value. Both sides
# derive the same Fernet key from it; a fixed salt lets them agree with no
# handshake (in a real production system would use a real key exchange instead).
GROUP_SECRET = "comp3500-secure-channel"
_KDF_SALT = b"comp3500-static-salt"

# Rate-limit policy: at most RATE_MAX messages per RATE_WINDOW seconds/client
RATE_MAX = 5
RATE_WINDOW = 3.0


# Encryption  (Security feature: CONFIDENTIALITY + INTEGRITY) ─
def _make_key(secret):
    """Derive a 32-byte Fernet key from a passphrase using PBKDF2."""

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


# Authentication  (Security feature: AUTHENTICATION)

def hash_password(password, salt=None):
    """Return a salted PBKDF2-SHA256 hash string:  salt_hex$hash_hex."""
    if salt is None:
        salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
    return f"{salt.hex()}${digest.hex()}"


def verify_password(password, stored):
    """Check a candidate password against a stored salted hash."""

    try:
        salt_hex, _ = stored.split("$")

    except ValueError:
        return False
    return hash_password(password, bytes.fromhex(salt_hex)) == stored


# Registered users — passwords stored ONLY as salted hashes, never plaintext.
USERS = {
    "user1": hash_password("Wonderland10"),
    "user2":   hash_password("01buildeR"),
    "user3":   hash_password("comp3500"),
}


# Input validation  (Security feature: INPUT VALIDATION)

def sanitize(text):
    """Cap length and strip non-printable control characters from a message."""
    text = text[:MAX_MESSAGE_LENGTH]
    return "".join(ch for ch in text if ch == "\t" or (ch >= " " and ch != "\x7f"))


# Logging  (Security feature: LOGGING) Human-readable console output is kept as in Homework 1; the file handler
# adds a persistent, timestamped forensic trail in server.log.

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    handlers=[logging.FileHandler("server.log")],
)
log = logging.getLogger("udp-chat")


def get_timestamp():
    """Return current datetime as a formatted string."""
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ── Rate limiting  (Security feature: RATE LIMITING) ────────────
def is_rate_limited(client_addr, message_times):
    """
    Sliding-window check: returns True if this client has sent more than
    RATE_MAX messages within the last RATE_WINDOW seconds.
    """
    now = datetime.datetime.now().timestamp()
    times = message_times[client_addr]
    while times and now - times[0] > RATE_WINDOW:
        times.popleft()
    if len(times) >= RATE_MAX:
        return True
    times.append(now)
    return False


def broadcast(server_socket, message, clients, sender_addr=None):
    """Send an (encrypted) message to every known client except the sender."""
    for client_addr in list(clients):
        if client_addr != sender_addr:
            try:
                server_socket.sendto(encrypt(message), client_addr)
            except Exception as e:
                print(f"[ERROR] Could not send to {client_addr}: {e}")
                clients.pop(client_addr, None)


def send_to(server_socket, message, client_addr):
    """Send an encrypted message directly to a single client."""
    try:
        server_socket.sendto(encrypt(message), client_addr)
    except Exception as e:
        print(f"[ERROR] Could not send to {client_addr}: {e}")


def start_server():
    """Create the UDP socket, bind it, and enter the receive loop."""

    # Creates a UDP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Bind to port
    server_socket.bind((HOST, PORT))

    # Track authenticated clients:  (ip, port) -> username
    clients = {}
    # Track recent send times per client for rate limiting
    message_times = {}

    print(f"Secure UDP Chat Server Started on {HOST}:{PORT}")
    print("-" * 45)
    log.info("Server started on %s:%s", HOST, PORT)

    while True:
        try:
            blob, client_addr = server_socket.recvfrom(BUFFER_SIZE)

            # Control 1: Encryption
            # Any packet that fails to decrypt is forged, corrupted, or sent
            # with the wrong key. Drop it and log the source.
            try:
                message = decrypt(blob).strip()
            except (InvalidToken, ValueError):
                print(f"[DROP] Undecryptable packet from {client_addr}")
                log.warning("DROP undecryptable packet from %s", client_addr)
                continue

            timestamp = get_timestamp()

            # Control 2: Authentication — login handling

            if message.startswith("__LOGIN__"):
                parts = message.split("|", 2)
                username = sanitize(parts[1]) if len(parts) > 1 else ""
                password = parts[2] if len(parts) > 2 else ""

                if username in USERS and verify_password(password, USERS[username]):
                    clients[client_addr] = username
                    message_times[client_addr] = deque()
                    print(
                        f"[{timestamp}] {username} ({client_addr[0]}:{client_addr[1]}) joined")
                    log.info("LOGIN user=%s from %s", username, client_addr)
                    send_to(
                        server_socket, f"[Server] Welcome, {username}! You are connected.", client_addr)
                    broadcast(server_socket,
                              f"[Server] {username} has joined the chat.",
                              clients, sender_addr=client_addr)
                else:
                    print(
                        f"[{timestamp}] AUTH FAILURE from {client_addr} (user={username!r})")
                    log.warning("AUTH FAILURE user=%r from %s",
                                username, client_addr)
                    send_to(
                        server_socket, "[Server] Login failed: bad credentials.", client_addr)
                continue

            # ── Control 2: Authentication — reject unauthenticated senders ──
            if client_addr not in clients:
                send_to(
                    server_socket, "[Server] Please log in before sending messages.", client_addr)
                log.warning("UNAUTH message from %s dropped", client_addr)
                continue

            username = clients[client_addr]

            # Graceful exit
            if message.lower() == "bye":
                print(
                    f"[{timestamp}] {username} ({client_addr[0]}:{client_addr[1]}) disconnected")
                log.info("QUIT user=%s from %s", username, client_addr)
                clients.pop(client_addr, None)
                message_times.pop(client_addr, None)
                broadcast(server_socket,
                          f"[Server] {username} has left the chat.",
                          clients)
                continue

            # Control 3: Rate limiting
            if is_rate_limited(client_addr, message_times):
                print(
                    f"[{timestamp}] RATE LIMIT {username} ({client_addr[0]}:{client_addr[1]})")
                log.warning("RATE LIMIT user=%s from %s",
                            username, client_addr)
                send_to(server_socket,
                        "[Server] Rate limit exceeded. Slow down.", client_addr)
                continue

            # Control 4: Input validation

            message = sanitize(message)
            if not message:
                continue

            # Display connection info + message

            print(f"[{username}] {message}")

            # Control 5: Security log with timestamp (now to file too)

            print(
                f"  LOG: [{timestamp}] {username}@{client_addr[0]}:{client_addr[1]} -> {message}")
            log.info("MSG user=%s: %s", username, message)

            # Broadcast to all other clients (by username, now that we have authinticated them)

            broadcast(server_socket,
                      f"[{username}]: {message}",
                      clients,
                      sender_addr=client_addr)

        except KeyboardInterrupt:
            print("\n[Server] Shutting down.")
            log.info("Server shutting down")
            break
        except Exception as e:
            print(f"[ERROR] {e}")
            log.warning("loop error: %s", e)

    server_socket.close()


if __name__ == "__main__":
    start_server()
