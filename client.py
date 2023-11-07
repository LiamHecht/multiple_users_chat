import socket
import threading
import tkinter as tk
from tkinter import scrolledtext
from tkinter import messagebox
from cryptography.fernet import Fernet

HOST = '127.0.0.1'
PORT = 1234

DARK_GREY = '#121212'
MEDIUM_GREY = '#1F1B24'
OCEAN_BLUE = '#464EB8'
WHITE = "white"
FONT = ("Helvetica", 17)
BUTTON_FONT = ("Helvetica", 15)
SMALL_FONT = ("Helvetica", 13)


# Read the encryption key from the file
with open('encryption_key.key', 'rb') as key_file:
    encryption_key = key_file.read()
cipher_suite = Fernet(encryption_key)

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

def add_message(message):
    message_box.config(state=tk.NORMAL)
    message_box.insert(tk.END, message + '\n')
    message_box.config(state=tk.DISABLED)

def connect():
    try:
        client.connect((HOST, PORT))
        add_message(f"[SERVER] Connected to {HOST}:{PORT}")
    except Exception as e:
        messagebox.showerror("Connection Error", f"Unable to connect to {HOST}:{PORT}\nException: {str(e)}")
        return

    username = username_textbox.get()
    if username.strip():
        client.sendall(username.encode())
        threading.Thread(target=listen_for_messages_from_server).start()
        username_textbox.config(state=tk.DISABLED)
        username_button.config(state=tk.DISABLED)
    else:
        messagebox.showerror("Invalid Username", "Username cannot be empty")

def send_message():
    message = message_textbox.get()
    if message.strip():
        if message.startswith("/private"):
            parts = message.split(" ")
            if len(parts) >= 3:
                target_username = parts[1]
                private_message = " ".join(parts[2:])
                private_msg_to_send = f"/private {target_username} {private_message}"
                encrypted_message = cipher_suite.encrypt(private_msg_to_send.encode())
                client.sendall(encrypted_message)
            else:
                add_message("Usage: /private <username> <message>")
        else:
            encrypted_message = cipher_suite.encrypt(f"{username_textbox.get()}~{message}".encode())
            client.sendall(encrypted_message)
        message_textbox.delete(0, tk.END)
    else:
        messagebox.showerror("Message Error", "Message cannot be empty")

def listen_for_messages_from_server():
    try:
        while True:
            encrypted_message = client.recv(2048)
            if encrypted_message:
                decrypted_message = cipher_suite.decrypt(encrypted_message).decode('utf-8')
                if decrypted_message.startswith("[SERVER]"):
                    add_message(decrypted_message)
                elif decrypted_message.startswith("[PRIVATE]"):
                    parts = decrypted_message.split(" ", 2)
                    if len(parts) == 3:
                        sender, content = parts[1], parts[2]
                        add_message(f"[Private from {sender}] {content}")
                else:
                    if "~" in decrypted_message:
                        sender, content = decrypted_message.split("~", 1)
                        add_message(f"[{sender}] {content}")
                    else:
                        add_message("Error: Malformed message received")
            else:
                add_message("Error: Message received from the server is empty")
    except Exception as e:
        add_message(f"Error: An error occurred while listening to messages from the server\nException: {str(e)}")

        
def on_closing():
    try:
        # Notify the server about the logout
        client.sendall(f"{username_textbox.get()}~/logout".encode()) # changed LOGOUT to /logout
    except:
        pass  # In case the connection is already lost before closing
    finally:
        # Close the connection and destroy the tkinter window
        client.close()
        root.destroy()


root = tk.Tk()
root.geometry("600x600")
root.title("Messenger Client")
root.resizable(False, False)

root.grid_rowconfigure(0, weight=1)
root.grid_rowconfigure(1, weight=4)
root.grid_rowconfigure(2, weight=1)

top_frame = tk.Frame(root, width=600, height=100, bg=DARK_GREY)
top_frame.grid(row=0, column=0, sticky=tk.NSEW)

middle_frame = tk.Frame(root, width=600, height=400, bg=MEDIUM_GREY)
middle_frame.grid(row=1, column=0, sticky=tk.NSEW)

bottom_frame = tk.Frame(root, width=600, height=100, bg=DARK_GREY)
bottom_frame.grid(row=2, column=0, sticky=tk.NSEW)

username_label = tk.Label(top_frame, text="Enter username:", font=FONT, bg=DARK_GREY, fg=WHITE)
username_label.pack(side=tk.LEFT, padx=10)

username_textbox = tk.Entry(top_frame, font=FONT, bg=MEDIUM_GREY, fg=WHITE, width=23)
username_textbox.pack(side=tk.LEFT)

username_button = tk.Button(top_frame, text="Join", font=BUTTON_FONT, bg=OCEAN_BLUE, fg=WHITE, command=connect)
username_button.pack(side=tk.LEFT, padx=15)

message_textbox = tk.Entry(bottom_frame, font=FONT, bg=MEDIUM_GREY, fg=WHITE, width=38)
message_textbox.pack(side=tk.LEFT, padx=10)

message_button = tk.Button(bottom_frame, text="Send", font=BUTTON_FONT, bg=OCEAN_BLUE, fg=WHITE, command=send_message)
message_button.pack(side=tk.LEFT, padx=10)

message_box = scrolledtext.ScrolledText(middle_frame, font=SMALL_FONT, bg=MEDIUM_GREY, fg=WHITE, width=67, height=26.5)
message_box.config(state=tk.DISABLED)
message_box.pack(side=tk.TOP)


root.protocol("WM_DELETE_WINDOW", on_closing)

def main():
    root.mainloop()

if __name__ == '__main__':
    main()
