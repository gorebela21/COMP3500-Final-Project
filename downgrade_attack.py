import socket
import json
HOST = "127.0.0.1"
PORT = 4444
client = socket.socket(
    socket.AF_INET,
    socket.SOCK_STREAM
)
client.connect((HOST, PORT))
client_hello = {
    "versions": [
        "TLS1.0",
        "TLS1.2",
        "TLS1.3"
    ],
    "ciphers": [
        "AES256",
        "CHACHA20"
    ]
}
client.send(json.dumps(client_hello).encode())
response = client.recv(4096).decode()
print("\nServerHello")
print(response)
try:
    extra = client.recv(4096)
    if extra:
        print(extra.decode())
except Exception:
    pass
