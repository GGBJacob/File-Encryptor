import string
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from tkinter import messagebox as mb
import os

def encrypt_sym(input_file, output_file, key_value, mode):
    # if (input_file.get() == "Null" or key_value.get() == "Null"
    #         or output_file.get() == "Null"):
    #     mb.showerror("Error", "Missing arguments!")

#TODO change to better random
    iv = os.urandom(16)

    print(key_value)
    print(iv)
    with open(input_file, "rb") as f:
        data = f.read()

    if mode == "block":
        cipher = Cipher(algorithms.AES(key_value), modes.CBC(iv), backend=default_backend())
    elif mode == "stream":
        cipher = Cipher(algorithms.AES(key_value), modes.CTR(iv), backend=default_backend()) #AES w trybie CTR działa strumieniowo
    else:
        print("wrong mode")
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()

    with open(output_file, "wb") as f:
        f.write(ciphertext)

    return iv

def decrypt_sym(input_filename, output_filename, key, iv, mode):
    with open(input_filename, "rb") as f:
        ciphertext = f.read()

    assert len(key) == 16, "Key must be 16 bytes for AES-128"
    assert len(iv) == 16, "IV must be 16 bytes for AES"

    if mode == "block":
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    elif mode == "stream":
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    else:
        print("wrong mode")
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    with open(output_filename, "wb") as f:
        f.write(plaintext)

if __name__ == "__main__":
    input_file1 = "input.txt"
    output_file1 = "encrypted.bin"
    input_file2 = "encrypted.bin"
    output_file2 = "decrypted.txt"
    key = b"thisisaverylongs"

    iv = encrypt_sym(input_file1, output_file1, key, mode="stream")
    decrypt_sym(input_file2, output_file2, key, iv, mode="stream")

# TODO szyfrowanie pliku
def encrypt_file(input_file, key_value, key_file, output_file):
    if (input_file.get() == "Null" or key_value.get() == "Null"
            or key_file.get() == "Null" or output_file.get() == "Null"):
        mb.showerror("Error", "Missing arguments!")
    # input file zawiera pełną ścieżkę pliku który szyfrujemy
    # key_value to zmienna, która zawiera wartość klucza
    # key_file ma ścieżkę pliku tekstowego do którego zapiszesz klucz
    # output_file - ścieżka pliku zaszyfrowanego

    # ! UŻYWAJ METOD .get() DO POBRANIA TYCH WARTOŚCI !
    # chyba i tak trzeba sprawdzać czy rozszerzenie pliku z kluczem jest .txt (zostawiam funkcję wyżej do inspiracji)


# DONE implementacja generowania klucza (key_value samo się wyświetli w okienku)
def generate_key(key_value, key_length):
    new_key = ""
    characters = string.digits + string.ascii_lowercase + string.ascii_uppercase

    for _ in range(key_length):
        new_key += characters[secrets.randbelow(len(characters))]
    key_value.set(new_key)
    pass
    # key_value.set(*wartość klucza jako string*)


# TODO implementacja deszyfrowania plików
def decrypt_file(input_file, key_file, output_file):
    if (input_file.get() == "Null" or key_file.get() == "Null" or output_file.get() == "Null"):
        mb.showerror("Error", "Missing arguments!")

    # Zasada ta sama co przy szyfrowaniu
    # .get() i te sprawy
    pass