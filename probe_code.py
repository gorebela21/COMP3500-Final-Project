#!/usr/bin/env python3

import socket
import json

HOST = "127.0.0.1"
PORT = 5000


def probe(student_id, challenge, payload=b"A"):

    request = {
        "student_id": student_id,
        "challenge": challenge,
        "payload": payload.hex()
    }

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))

    sock.send(json.dumps(request).encode())

    response = sock.recv(4096)

    print("\n" + "=" * 60)
    print(f"CHALLENGE {challenge} PROBE OUTPUT")
    print("=" * 60)
    print(response.decode())
    print("=" * 60 + "\n")

    sock.close()


def main():

    print("Stack Smashing Simulator - Recon Tool")
    print("This tool helps you observe server behavior before exploiting.\n")

    student_id = input("Student ID: ").strip()

    mode = input(
        "Mode (1 = single challenge, 2 = all challenges): "
    ).strip()

    if mode == "1":

        challenge = int(input("Challenge number (1-5): "))

        probe(student_id, challenge)

    else:

        for c in range(1, 6):

            probe(student_id, c)

    print("Recon complete.")


if __name__ == "__main__":
    main()