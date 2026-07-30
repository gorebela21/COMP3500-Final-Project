import socket


def connect_to_public_server():
    """Connect to a public server (example.com) and exchange messages."""
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("example.com", 80))
    client.send("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".encode())
    response = client.recv(14096).decode()
    print("Public Server Response:")
    print(response)
    client.close()


def start_client():
    """COnnect to local server and exchange messages."""
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("127.0.0.1", 12345))
    print("connected to server. Type 'bye' to exit. \n")

    while True:
        # Client message to server
        message = input("Client: ")
        client.send(message.encode())

        # check if client said bye, if so, close connection
        if message.lower() == "bye":
            print("Connection closed.")
            break

        # Receive response from server
        reply = client.recv(1024).decode()
        print("Server:", reply)

        # Check if server said bye, if so, close connection
        if reply.lower() == "bye":
            print("Connection closed.")
            break

    client.close()


# Run the client functions
start_client()
