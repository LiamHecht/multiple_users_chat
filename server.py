import socket
import threading
from colorama import Fore

from cryptography.fernet import Fernet

with open('encryption_key.key', 'rb') as key_file:
    encryption_key = key_file.read()
cipher_suite = Fernet(encryption_key)


HOST = '127.0.0.1'
PORT = 1234
LISTENER_LIMIT = 5
active_clients = {}  # Dictionary to store active clients and their sockets

# COLORS
green = Fore.GREEN
red = Fore.RED
reset = Fore.RESET

# Function to listen for upcoming messages from a client
def listen_for_messages(client, username):
    try:
        while True:
            encrypted_message = client.recv(2048)
            if not encrypted_message:
                break

            decrypted_message = cipher_suite.decrypt(encrypted_message).decode('utf-8')
            
            if decrypted_message == '/logout' or decrypted_message == '':
                print(f"{red}User '{username}' left the chat.")
                
                # Send message to all clients that the user has left
                departure_msg = f"SERVER~{username} left the chat."
                send_messages_to_all(departure_msg)
                
                # Remove from active clients and close connection
                del active_clients[username]
                client.close()
                return
            
            elif decrypted_message.startswith("/private"):
                parts = decrypted_message.split(" ")
                if len(parts) >= 3:
                    target_username = parts[1]
                    private_message = " ".join(parts[2:])
                    send_private_message(username, target_username, private_message)
                else:
                    send_message_to_client(client, "Usage: /private <username> <message>")
            else:
                final_msg = f"{decrypted_message}"
                print(final_msg)
                send_messages_to_all(final_msg)
    except ConnectionResetError:
        print(f"{red}Connection reset by peer {username}")
        if username in active_clients:
            del active_clients[username]
    except Exception as e:
        print(f"{red}An error occurred with client {username}: {e}")
        if username in active_clients:
            del active_clients[username]


def send_private_message(sender, target_username, message):
    if target_username in active_clients:
        target_socket = active_clients[target_username]
        message_to_send = f"[PRIVATE] {sender} (Private): {message}"
        encrypted_message = cipher_suite.encrypt(message_to_send.encode())
        send_message_to_client(target_socket, encrypted_message)
    else:
        send_message_to_client(active_clients[sender], f"User '{target_username}' is not available for private chat.")

def send_message_to_client(client, message):
    client.sendall(message.encode())

# Function to send messages to all clients
def send_messages_to_all(message, sender=None):
    message = f"{sender}~{message}" if sender else message
    encrypted_message = cipher_suite.encrypt(message.encode())
    for client_socket in active_clients.values():
        client_socket.sendall(encrypted_message)

# Function to handle client
def client_handler(client):
    try:
        while True:
            username = client.recv(2048).decode('utf-8')
            if username != '':
                active_clients[username] = client
                prompt_message = "SERVER~" + f"{username} added to the chat"
                send_messages_to_all(prompt_message)
                listen_for_messages(client, username)  # Pass username here
                break
            else:
                print(f"{red}Client username is empty")
                client.close()
                break
    except KeyboardInterrupt as e:
        print(e)

# Main function
def main():
    # Creating the socket class object
    # AF_INET: we are going to use IPv4 addresses
    # SOCK_STREAM: we are using TCP packets for communication
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # Provide the server with an address in the form of
        # host IP and port
        server.bind((HOST, PORT))
        print(f"{green}Running the server on {HOST} {PORT}")
    except:
        print(f"{red}Unable to bind to host {HOST} and port {PORT}")

    # Set server limit
    server.listen(LISTENER_LIMIT)

    # This while loop will keep listening to client connections
    while True:
        client, address = server.accept()
        print(f"{green}[*]{reset} Successfully connected to client {address[0]} {address[1]}")

        threading.Thread(target=client_handler, args=(client,)).start()

if __name__ == '__main__':
    main()
