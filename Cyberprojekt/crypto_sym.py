import string
import secrets

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from tkinter import messagebox as mb
from cryptography.hazmat.primitives import padding

KEY_LENGTH = 16

#implementacja generowania klucza (key_value samo się wyświetli w okienku)
def generate_key(key_value, key_length):
    new_key = random_characters(key_length)
    key_value.set(new_key)
    pass
    # key_value.set(*wartość klucza jako string*)

def random_characters(key_length): #zwraca string
    new_text = ""
    characters = string.digits + string.ascii_lowercase + string.ascii_uppercase

    for _ in range(key_length):
        new_text += characters[secrets.randbelow(len(characters))]

    return new_text

def encrypt_sym(data, key_value, mode):
    if key_value.get() == "Null":
        mb.showerror("Error", "Missing arguments!")

    iv = random_characters(KEY_LENGTH)
    iv_new = iv.encode('utf-8')
    key_value = key_value.get().encode('utf-8')

    assert len(key_value) == KEY_LENGTH, mb.showerror("Error","Key must be 16 bytes for AES-128")
    assert len(iv_new) == KEY_LENGTH, mb.showerror("Error", "IV must be 16 bytes for AES")

    if mode == "block":
        padder = padding.PKCS7(algorithms.AES.block_size).padder() #PKCS7 to popularny padding scheme
        data = padder.update(data) + padder.finalize()
        cipher = Cipher(algorithms.AES(key_value), modes.CBC(iv_new), backend=default_backend())
    elif mode == "stream":
        cipher = Cipher(algorithms.AES(key_value), modes.CTR(iv_new), backend=default_backend()) #AES w trybie CTR działa strumieniowo
    else:
        print(mode)
        mb.showerror("Error", "Wrong mode!")
        return None, None

    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()

    return ciphertext, iv_new

def decrypt_sym(ciphertext, key, iv, mode):

    assert len(key) == KEY_LENGTH, "Key must be 16 bytes for AES-128"
    assert len(iv) == KEY_LENGTH, "IV must be 16 bytes for AES"

    if mode == "block":
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    elif mode == "stream":
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    else:
        print("wrong mode")
        return None

    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    if mode == "block":
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(plaintext) + unpadder.finalize()

    return plaintext

if __name__ == "__main__":
    print(".")
    # message = "This is a secret message!"
    # key = "Q64kr4FxivuF6yHM"
    # encrypted_text, iv = encrypt_sym(message, key, mode="block") #coś tu nie działa z key
    # decrypted_text = decrypt_sym(encrypted_text, key, iv, mode="block")

