from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key

# Load the friend's public key
with open("public_key.pem", "rb") as f:
    public_key = load_pem_public_key(f.read())

# The message you want to send
message = b"Hey buddy, how are you, you freaak of nature? I needd you to calm down and stop being so crazy. LOL :D"

# Encrypt the message
encrypted_message = public_key.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Save the encrypted message to a file
with open("encrypted_message.bin", "wb") as f:
    f.write(encrypted_message)

print("Message encrypted and saved!")
