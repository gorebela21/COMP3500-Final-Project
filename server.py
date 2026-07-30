
import socket
import datetime


def log_connection(address):
    """Log client IP, Port, and Time of connection."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] Connection from {address[0]}:{address[1]}")


def handle_client(client_socket, client_address):
    """Handle message exchange with a single client."""
    log_connection(client_address)

    while True:
        message = client_socket.recv(1024).decode()
        if not message:
            print("Client disconnected unexpectedly.")
            break

        print(f"Client: {message}")

        if message.lower() == "bye":
            client_socket.send("bye".encode())
            print("Connection closed.")
            break

        reply = input("Server: ")
        client_socket.send(reply.encode())

        if reply.lower() == "bye":
            print("Connection closed.")
            break

    client_socket.close()


def start_server():
    """Start the server and accept multiple clients sequentially."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 12345))
    server.listen()
    print("Server listening...")

    while True:
        client_socket, client_address = server.accept()
        handle_client(client_socket, client_address)


start_server()
