import string
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from tkinter import messagebox as mb
import os
from cryptography.hazmat.primitives import padding

KEY_LENGTH = 16


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


# TODO implementacja deszyfrowania plików
def decrypt_file(input_file, key_file, output_file):
    if (input_file.get() == "Null" or key_file.get() == "Null" or output_file.get() == "Null"):
        mb.showerror("Error", "Missing arguments!")

    # Zasada ta sama co przy szyfrowaniu
    # .get() i te sprawy
    pass

def encrypt_sym(input_file, output_file, key_file, key_value, mode):
    if input_file.get() == "Null" or key_value.get() == "Null" or key_file.get() == "Null" or output_file.get() == "Null":
        mb.showerror("Error", "Missing arguments!")

    iv = random_characters(KEY_LENGTH)
    iv = iv.encode('utf-8')
    key_value = key_value.get().encode('utf-8')

    assert len(key_value) == KEY_LENGTH, "Key must be 16 bytes for AES-128"
    assert len(iv) == KEY_LENGTH, "IV must be 16 bytes for AES"

    with open(input_file.get(), "rb") as f:
        data = f.read()

    if mode == "block":
        padder = padding.PKCS7(algorithms.AES.block_size).padder() #PKCS7 to popularny padding scheme
        data = padder.update(data) + padder.finalize()
        cipher = Cipher(algorithms.AES(key_value), modes.CBC(iv), backend=default_backend())
    elif mode == "stream":
        cipher = Cipher(algorithms.AES(key_value), modes.CTR(iv), backend=default_backend()) #AES w trybie CTR działa strumieniowo
    else:
        print("wrong mode")
        return None

    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()

    with open(output_file.get(), "wb") as f:
        f.write(ciphertext)

    return iv

def decrypt_sym(input_filename, output_filename, key, iv, mode):
    with open(input_filename, "rb") as f:
        ciphertext = f.read()

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

    with open(output_filename, "wb") as f:
        f.write(plaintext)

if __name__ == "__main__":
    input_file1 = "input.txt"
    output_file1 = "encrypted.bin"
    input_file2 = "encrypted.bin"
    output_file2 = "decrypted.txt"
    key = b"thisisaverylongs"

    iv = encrypt_sym(input_file1, output_file1, key, mode="block")
    decrypt_sym(input_file2, output_file2, key, iv, mode="block")

