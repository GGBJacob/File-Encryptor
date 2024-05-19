from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from tkinter import messagebox as mb


def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key


def encrypt_asym(text, key_pub):
    encoded_message = text.encode('utf-8')
    ciphertext = key_pub.encrypt(
        encoded_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext


def decrypt_asym(ciphertext, key_priv):
    try:
        decrypted = key_priv.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted.decode('utf-8')
    except Exception as e:
        mb.showerror("Error", f"Decryption failed: {e}")


def save_private_key(private_key, filename):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(filename, 'wb') as pem_out:
        pem_out.write(pem)


def save_public_key(public_key, filename):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(filename, 'wb') as pem_out:
        pem_out.write(pem)


def load_private_key(filename, password=None):
    with open(filename, 'rb') as pem_in:
        pem_data = pem_in.read()
    private_key = serialization.load_pem_private_key(
        pem_data,
        password=password,
        backend=default_backend()
    )
    return private_key


def load_public_key(filename):
    with open(filename, 'rb') as pem_in:
        pem_data = pem_in.read()
    public_key = serialization.load_pem_public_key(
        pem_data,
        backend=default_backend()
    )
    return public_key


if __name__ == "__main__":
    private_key = generate_key_pair()
    message = "This is a secret message!"

    encrypted_text = encrypt_asym(message, private_key.public_key())
    decrypted_text = decrypt_asym(encrypted_text, private_key)

    print("Original message:", message)
    print("Encrypted message:", encrypted_text)
    print("Decrypted message:", decrypted_text)
