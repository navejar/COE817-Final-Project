import socket
import hmac

# Shared key between ATM and bank server
shared_key = b'SharedSecretKey123'

def authenticate_client(client_socket):
    # Authenticates client using the shared key
    client_socket.send(b"Authenticate")
    received_data = client_socket.recv(1024)
    if hmac.compare_digest(received_data, shared_key):
        return True
    else:
        return False

def main():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 8888))
    print("Connected to server.")

    # Your client logic goes here

if __name__ == "__main__":
    main()
