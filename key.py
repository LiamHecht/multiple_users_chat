from cryptography.fernet import Fernet

# Generate a shared encryption key
encryption_key = Fernet.generate_key()

# Save the key to a file
with open('encryption_key.key', 'wb') as key_file:
    key_file.write(encryption_key)
