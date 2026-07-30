# COMP 3500 — Final Project
UDP chat application

A socket-programming project demonstrating client–server communication over TCP and UDP, along with a **protocol downgrade attack** against the connection.

> Course: COMP 3500 (Network Security) — Wentworth Institute of Technology

## Overview

This project implements a client and server that negotiate a connection, then shows how an on-path attacker can force the parties down to a weaker/insecure mode by tampering with that negotiation. Both TCP and UDP variants are included, along with a probing tool used to inspect the server's behavior.

## Files

| File | Description |
|------|-------------|
| `server.py` | TCP server that accepts client connections and handles the protocol negotiation. |
| `client.py` | TCP client that connects to the server. |
| `client2.py` | Second client variant *(e.g. an alternate config or a second peer for multi-client testing — update to match)*. |
| `udp_server.py` | UDP version of the server. |
| `udp_client.py` | UDP version of the client. |
| `downgrade_attack.py` | The attack script — intercepts/tampers with the negotiation to force a downgrade to a weaker mode. |
| `probe_code.py` | Probes the server to inspect its responses / supported options. |
| `starter_code.py` | Provided starter/scaffolding code for the assignment. |
| `README.md` | This file. |

## Requirements

- Python 3.x
- A terminal/command line to run the scripts.
- "Cryptography" (https://pypi-org/project/cryptography/) - provides Ferent for symmetric encryption

- Install with:
 ```bash
  pip install cryptography 
```

## Usage

Run the server and client in **separate terminals**.

### TCP

```bash
# Terminal 1 — start the server
python3 server.py

# Terminal 2 — connect a client
python3 client.py
```

### UDP

```bash
# Terminal 1
python3 udp_server.py

# Terminal 2
python3 udp_client.py
```

### Running the downgrade attack

With the server running, launch the attack script to intercept the negotiation:

```bash
python3 downgrade_attack.py
```

*(`python3 downgrade_attack.py --target 127.0.0.1 --port 5000`.)*

### Probing the server

```bash
python3 probe_code.py
```

## Notes

- This code is for **educational use** in a controlled lab environment only. Do not run the attack against systems you do not own or have permission to test.

## Author

Fekadu — [@gorebela21](https://github.com/gorebela21)
