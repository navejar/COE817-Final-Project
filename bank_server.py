import socket
import threading
import hashlib
import hmac
import os

# Define global variables
MASTER_SECRET = b''  # Master Secret key shared between ATM and server
DATA_ENCRYPTION_KEY = b''  # Key for data encryption
MAC_KEY = b''  # Key for Message Authentication Code
client_accounts = [["client_1", "secret_1"], ["client_2", "secret_2"], ["client_3", "secret_3"]]  # Dictionary to store ATM clients' information
AUDIT_LOG_FILE = "audit_log.txt"


def generate_master_secret():
    """
    Generate a Master Secret key.
    """
    global MASTER_SECRET
    MASTER_SECRET = os.urandom(16)


def key_derivation():
    """
    Derive two keys from the Master Secret: one for data encryption, the other for MAC.
    """
    global DATA_ENCRYPTION_KEY, MAC_KEY
    derived_key = hashlib.sha256(MASTER_SECRET).digest()
    DATA_ENCRYPTION_KEY = derived_key[:16]  # Using the first 128 bits for encryption
    MAC_KEY = derived_key[16:]  # Using the next 128 bits for MAC


def generate_mac(data):
    """
    Generate a Message Authentication Code (MAC) for data integrity.
    """
    return hmac.new(MAC_KEY, data, hashlib.sha256).digest()


def verify_mac(data, mac_received):
    """
    Verify the Message Authentication Code (MAC) for data integrity.
    """
    return hmac.compare_digest(generate_mac(data), mac_received)


def log_transaction(username, action, amount):
    """
    Log the transaction information into an audit log file.
    """
    with open(AUDIT_LOG_FILE, "a") as file:
        file.write(f"Username: {username}, Action: {action}, Amount: {amount}\n")


def handle_client_connection(client_socket, client_address):
    """
    Handle the connection from an ATM client.
    """
    try:
        # Getting authenticated
        print("Entered authentication phase")
        username, password = client_socket.recv(1024).decode().split(",")
        if [username, password] in client_accounts:
            print("Entered if statement for authentication")
            client_socket.send(b"Authenticated successfully")
        else:
            client_socket.send(b"Authentication Failed. Invalid username and/or password.")
            client_socket.close()
            return

        # Server sends master secret key to client
        client_socket.send(MASTER_SECRET)


        # Data transaction phase
        while True:
            action = client_socket.recv(1024).decode() #receive action input from client and socket, and convert bytes message into string
            amount = client_socket.recv(1024).decode()
            mac_received = client_socket.recv(32)  # 256-bit MAC

            if verify_mac(action.encode() + amount.encode(), mac_received):
                # Process the transaction
                log_transaction(username, action, amount)
                client_socket.send(b"Transaction Successful")
            else:
                client_socket.send(b"Transaction Failed: Integrity Check Failed")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        client_socket.close()


def main():
    # The server socket must first be initialized
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("localhost", 45687))
    server_socket.listen(3)  # Initializes the bank server to listen to three client connections

    generate_master_secret()
    key_derivation()

    print("Server started. Listening for connections...")

    try:
        while True:
            client_socket, client_address = server_socket.accept()
            print(f"Connection from {client_address} established.")
            threading.Thread(target=handle_client_connection, args=(client_socket, client_address)).start()
    except KeyboardInterrupt:
        print("Server shutting down...")
    finally:
        server_socket.close()


if __name__ == "__main__":
    main()
