import string
from tkinter import messagebox as mb
import secrets

KEY_LENGTH = 8

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
def generate_key(key_value):
    new_key = ""
    characters = string.digits + string.ascii_lowercase + string.ascii_uppercase

    for _ in range(KEY_LENGTH):
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