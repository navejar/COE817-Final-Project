import socket
import threading
import hashlib
import hmac
import time

# Shared key between ATM and bank server
shared_key = b'SharedSecretKey123'

# Dictionary to store account information (username, password, balance)
accounts = {'Alice': {'password': 'password123', 'balance': 1000},
            'Bob': {'password': 'securepwd', 'balance': 500},
            'Eve': {'password': 'password', 'balance': 2000}}

# Dictionary to store audit log
audit_log = {}


def generate_master_secret():
    # Generate master secret using a secure hash function
    return hashlib.sha256(shared_key).digest()


def generate_keys(master_secret):
    # Derive encryption key and MAC key from master secret
    encryption_key = master_secret[:16]  # 128 bits for AES encryption
    mac_key = master_secret[16:]         # Remaining for MAC
    return encryption_key, mac_key


def authenticate_client(client_socket):
    # Authenticates client using the shared key
    client_socket.send(b"Authenticate")
    received_data = client_socket.recv(1024)
    if hmac.compare_digest(received_data, shared_key):
        return True
    else:
        return False


def handle_client(client_socket, client_address):
    try:
        authenticated = authenticate_client(client_socket)
        if not authenticated:
            print(f"Authentication failed for {client_address}")
            return

        while True:
            # Receive action from client
            action = client_socket.recv(1024).decode()

            if action == "deposit":
                username = client_socket.recv(1024).decode()
                amount = float(client_socket.recv(1024).decode())

                # Update balance
                accounts[username]['balance'] += amount

                # Log the action
                audit_log[username] = (action, time.time())

            elif action == "withdraw":
                username = client_socket.recv(1024).decode()
                amount = float(client_socket.recv(1024).decode())

                # Check if sufficient balance
                if accounts[username]['balance'] >= amount:
                    # Update balance
                    accounts[username]['balance'] -= amount

                    # Log the action
                    audit_log[username] = (action, time.time())
                else:
                    client_socket.send(b"Insufficient balance")

            elif action == "balance_inquiry":
                username = client_socket.recv(1024).decode()

                # Send balance to client
                balance = str(accounts[username]['balance']).encode()
                client_socket.send(balance)

                # Log the action
                audit_log[username] = (action, time.time())

            else:
                break

    except Exception as e:
        print(f"Error handling client {client_address}: {str(e)}")
    finally:
        client_socket.close()


def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 8888))
    server_socket.listen(5)
    print("Server listening...")

    while True:
        client_socket, client_address = server_socket.accept()
        print(f"Connection from {client_address} established.")
        client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
        client_thread.start()


def main():
    master_secret = generate_master_secret()
    encryption_key, mac_key = generate_keys(master_secret)
    print("Master Secret:", master_secret)
    print("Encryption Key:", encryption_key)
    print("MAC Key:", mac_key)
    start_server()


if __name__ == "__main__":
    main()
