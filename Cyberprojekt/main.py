import os
import tkinter as tk
from tkinter import filedialog as fd
from tkinter import messagebox as mb
import crypto_sym as cs
import crypto_asym as ca
from crypto_sym import KEY_LENGTH


def get_file(entry, input_file, filetypes):
    filepath = fd.askopenfilename(title='Select file', filetypes=filetypes)
    entry.config(state='normal')
    if not filepath:
        input_file.set("Null")
    else:
        input_file.set(filepath)
    entry.config(state='readonly')


def change_frame(frame_to_forget, frame_to_add, appMode, root):
    frame_to_forget.grid_forget()
    frame_to_add.grid(column=0, row=0)
    if appMode == 1:
        root.title("File Encryptor")
    elif appMode == 2:
        root.title("File Decryptor")


def reset_form(arguments):
    for argument in arguments:
        argument.set("Null")


def save_file(entry, file, filetypes):
    filepath = fd.asksaveasfilename(title="Select file", defaultextension=filetypes[-1][1],
                                    filetypes=filetypes)
    entry.config(state='normal')
    if not filepath:
        file.set("Null")
    else:
        file.set(filepath)
    entry.config(state='readonly')


def are_variables_set(variables):
    for variable in variables:
        if (isinstance(variable, str) and variable == "Null") or (
                isinstance(variable, tk.StringVar) and variable.get() == "Null"):
            mb.showerror("Come on...", "Not all arguments set!")
            return False
    return True


def get_directory(entry, input_dir):
    directory = fd.askdirectory(title='Select file')
    entry.config(state='normal')
    if not directory:
        input_dir.set("Null")
    else:
        input_dir.set(directory)
    entry.config(state='readonly')


def create_encryption_output_path(input_file):
    path = os.path.dirname(input_file) + '/Cryptography Output'
    if not os.path.exists(path):
        os.makedirs(path)
    return path


def encrypt(input_file, key_value, encrypt_mode):
    if not are_variables_set([input_file, key_value, encrypt_mode]):
        return

    folder_path = create_encryption_output_path(input_file)

    output_file, key_file = createFilePaths(input_file, folder_path)
    with open(input_file, "rb") as f:
        data = f.read()

    newline = bytes("\n", 'utf-8')

    # szyfrowanie symetrtyczne
    encrypted_file_sym, iv = cs.encrypt_sym(data, key_value, encrypt_mode)
    key_sym = bytes(encrypt_mode, 'utf-8') + newline + iv + newline + bytes(key_value.get(), 'utf-8')

    # szyfrowanie asymetryczne
    private_key = ca.generate_key_pair()
    encrypted_asym_key_sym = ca.encrypt_asym(key_sym.decode(), private_key.public_key())
    combined_file_sym_and_asym_key_sym = encrypted_asym_key_sym + encrypted_file_sym

    with open(output_file, "wb") as f:
        f.write(combined_file_sym_and_asym_key_sym)

    ca.save_private_key(private_key, os.path.join(folder_path, "key.priv"))
    ca.save_public_key(private_key.public_key(), os.path.join(folder_path, "key.pub"))


def createFilePaths(input_file, folder_path):
    input_file_name = input_file.split('/')[-1].split('.')[0] # wyjmuje nazwę pliku
    file_paths = ['encrypted_' + input_file_name + '.txt', 'keypair.key']
    for i in range(len(file_paths)):
        file_paths[i] = os.path.join(folder_path, file_paths[i]) # tworzenie ścieżek do wygenerowania
    return file_paths


def create_decryption_output_file(input_file):
    return os.path.dirname(input_file.get()) + '/decrypted_' + input_file.get().split('/')[-1].split('_')[1]
    # wyjmuje ścieżkę z pliku, dodaje przedrostek decrypted i resztę nazwy z rozszerzeniem txt


def decrypt(input_file, key_file):
    with open(input_file.get(), "rb") as f:
        encrypted_asym_key_sym = f.read(256)
        encrypted_file_sym = f.read()

    private_key = ca.load_private_key(key_file.get())

    encrypt_mode, iv, key_sym = ca.decrypt_asym(encrypted_asym_key_sym, private_key).split('\n')
    plaintext = cs.decrypt_sym(encrypted_file_sym, key_sym.encode(), iv.encode(), mode=encrypt_mode)

    output_file = create_decryption_output_file(input_file)

    with open(output_file, "wb") as f:
        f.write(plaintext)


def create_encryption_UI(frame, input_file, key_value):
    # Napis input
    label_selected = tk.Label(frame, text="Input file:")
    label_selected.grid(row=0, column=0, padx=5, pady=10)

    # Pole do wyświetlania wybranego pliku
    entry_input = tk.Entry(frame, textvariable=input_file)
    entry_input.config(state='readonly')
    entry_input.grid(row=0, column=1, padx=5, pady=10)

    # Przycisk do wyboru pliku
    button_select_input = tk.Button(frame, text="Select file",
                                    command=lambda: get_file(entry_input, input_file, [("All files", ".*")]))
    button_select_input.grid(row=0, column=2, padx=5, pady=10)

    # Napis do klucza
    label_key_value = tk.Label(frame, text="Key value:")
    label_key_value.grid(row=1, column=0, padx=5, pady=10)

    # Pole do wyświetlania klucza
    entry_key_value = tk.Entry(frame, textvariable=key_value)
    entry_key_value.grid(row=1, column=1, padx=5, pady=10)

    # Generacja nowego klucza
    reroll_button = tk.Button(frame, text="Reroll key", command=lambda: cs.generate_key(key_value, KEY_LENGTH))
    reroll_button.grid(row=1, column=2, padx=10, pady=10)

    # Label do wyboru
    label_encrypt_mode = tk.Label(frame, text="Encrypt mode:")
    label_encrypt_mode.grid(row=4, column=0, padx=5, pady=10)

    # Wybór szyfrowania
    encrypt_mode = tk.StringVar(value="block")  # Tryb szyfrowania
    rbutton1 = tk.Radiobutton(frame, text="Block", value="block", variable=encrypt_mode)
    rbutton2 = tk.Radiobutton(frame, text="Stream", value="stream", variable=encrypt_mode)

    rbutton1.grid(row=4, column=1, padx=5, pady=10)
    rbutton2.grid(row=4, column=2, padx=5, pady=10)

    # Przycisk szyfrowania
    confirm = tk.Button(frame, text="Encrypt!", bg="#23FF00",
                        command=lambda: encrypt(input_file.get(), key_value, encrypt_mode.get()))
    confirm.grid(row=5, column=0, padx=10, pady=10)

    # Przycisk clear
    button_clear = tk.Button(frame, text="Clear", bg="#FFF300",
                             command=lambda: reset_form([input_file, key_value]))
    button_clear.grid(row=5, column=2, pady=10, padx=10)


def create_decryption_UI(frame, input_file, key_file):
    # Napis wybrany plik
    label_selected = tk.Label(frame, text="Selected file:")
    label_selected.grid(row=0, column=0, padx=5, pady=10)

    # Pole do wyświetlania wybranego pliku
    entry_input = tk.Entry(frame, textvariable=input_file)
    entry_input.config(state='readonly')
    entry_input.grid(row=0, column=1, padx=5, pady=10)

    # Przycisk do wyboru pliku
    button1 = tk.Button(frame, text="Select file",
                        command=lambda: get_file(entry_input, input_file, [("Text files", "*.txt")]))
    button1.grid(row=0, column=2, pady=10, padx=10)

    # Napis klucz
    label_key = tk.Label(frame, text="Key file")
    label_key.grid(row=1, column=0, padx=10, pady=5)

    # Wczytanie klucza
    entry_key = tk.Entry(frame, textvariable=key_file)
    entry_key.config(state='readonly')
    entry_key.grid(row=1, column=1, padx=5, pady=10)

    # Przycisk do klucza
    button2 = tk.Button(frame, text="Select file",
                        command=lambda: get_file(entry_key, key_file, [("Key files", ".priv")]))
    button2.grid(row=1, column=2, padx=5, pady=10)

    # Przycisk decrypt
    button_decrypt = tk.Button(frame, text="Decrypt!", bg="#FF7C00",
                               command=lambda: decrypt(input_file, key_file))
    button_decrypt.grid(row=3, column=0, padx=5, pady=10)

    # Przycisk clear
    button_clear = tk.Button(frame, text="Clear", bg="#FFF300", command=lambda: reset_form([input_file, key_file]))
    button_clear.grid(row=3, column=2, padx=5, pady=10)


def main():
    # Główne okno
    root = tk.Tk()
    # root.geometry("357x200")
    root.iconbitmap("icon.ico")
    # root.eval('tk::PlaceWindow . center') # <- środkuje okno na ekranie
    root.resizable(False, False)

    encryption_input_file = tk.StringVar(value="Null")
    decryption_input_file = tk.StringVar(value="Null")
    key_value = tk.StringVar(value="Null")
    key_file = tk.StringVar(value="Null")
    output_file = tk.StringVar(value="Null")

    # Menu
    menubar = tk.Menu(root)
    appMode = tk.IntVar(value=1)

    options_menu = tk.Menu(menubar, tearoff=0)
    options_menu.add_radiobutton(label="Encrypt", value=1, variable=appMode,
                                 command=lambda: change_frame(decrypt_frame, encrypt_frame, appMode.get(), root))
    options_menu.add_radiobutton(label="Decrypt", value=2, variable=appMode,
                                 command=lambda: change_frame(encrypt_frame, decrypt_frame, appMode.get(), root))
    options_menu.add_command(label="Exit", command=root.quit)
    menubar.add_cascade(label="Options", menu=options_menu)

    # Ramki do zmiany wyglądu szyfrowanie/odszyfrowywanie
    encrypt_frame = tk.Frame(root)
    decrypt_frame = tk.Frame()

    create_decryption_UI(decrypt_frame, decryption_input_file, key_file)
    create_encryption_UI(encrypt_frame, encryption_input_file, key_value)

    if appMode.get() == 1:
        change_frame(decrypt_frame, encrypt_frame, appMode.get(), root)
    else:
        change_frame(encrypt_frame, decrypt_frame, appMode.get(), root)

    # Config i pętla apki
    root.config(menu=menubar)
    root.mainloop()


main()
