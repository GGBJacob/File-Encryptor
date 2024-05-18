from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding


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
    decrypted = key_priv.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode('utf-8')  # Decode bytes back to string


if __name__ == "__main__":
    private_key = generate_key_pair()
    message = "This is a secret message!"

    encrypted_text = encrypt_asym(message, private_key.public_key())
    decrypted_text = decrypt_asym(encrypted_text, private_key)

    print("Original message:", message)
    print("Encrypted message:", encrypted_text)  # This will be a byte sequence
    print("Decrypted message:", decrypted_text)

