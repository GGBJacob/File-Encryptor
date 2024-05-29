import os
import tkinter as tk
from tkinter import filedialog as fd
from tkinter import messagebox as mb
import crypto_sym as cs
import crypto_asym as ca
import webbrowser
from crypto_sym import KEY_LENGTH


def get_file(entry, input_file, file_name, filetypes):
    filepath = fd.askopenfilename(title='Select file', filetypes=filetypes)
    entry.config(state='normal')
    if not filepath:
        input_file.set("Null")
        file_name.set("Null")
    else:
        input_file.set(filepath)
        file_name.set(input_file.get().split('/')[-1])
    entry.config(state='readonly')


def change_frame(frame_to_forget, frame_to_add, app_mode, root):
    frame_to_forget.grid_forget()
    frame_to_add.grid(column=0, row=0)
    if app_mode == 1:
        root.title("File Encryptor")
    elif app_mode == 2:
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


def create_encryption_output_path(input_file):
    path = os.path.dirname(input_file) + '/Cryptography Output'
    if not os.path.exists(path):
        os.makedirs(path)
    return path


def encrypt(input_file, encrypt_mode, user):
    if not are_variables_set([input_file, encrypt_mode]):
        return

    key_value = tk.StringVar(value="")
    cs.generate_key(key_value, KEY_LENGTH)
    folder_path = create_encryption_output_path(input_file)

    output_file = create_file_path(input_file, folder_path)
    with open(input_file, "rb") as f:
        data = f.read()

    file_name, extension = os.path.splitext(input_file)
    file_name = file_name.split('/')[-1]

    newline = bytes("\n", 'utf-8')

    # szyfrowanie symetrtyczne
    encrypted_file_sym, iv = cs.encrypt_sym(data, key_value, encrypt_mode)
    key_sym = bytes(encrypt_mode, 'utf-8') + newline + bytes(extension, 'utf-8') + newline + iv + newline + bytes(
        key_value.get(), 'utf-8')

    # TODO: odczytanie klucza publicznego dla wybranego użytkownika (rozpoczęte poniżej)

    private_key_file, public_key_file = get_user_keys(user)
    if private_key_file is None or public_key_file is None:
        mb.showwarning(title="Error", message="User does not exist!")
        return
    private_key_from_file = ca.load_private_key(private_key_file) # TODO: użyć tego poprawnie
    print("private_key_from_file", private_key_from_file)
    
    # szyfrowanie asymetryczne
    private_key = ca.generate_key_pair()
    encrypted_asym_key_sym = ca.encrypt_asym(key_sym.decode(), private_key.public_key())
    combined_file_sym_and_asym_key_sym = encrypted_asym_key_sym + encrypted_file_sym

    with open(output_file, "wb") as f:
        f.write(combined_file_sym_and_asym_key_sym)

    ca.save_private_key(private_key, os.path.join(folder_path, file_name + "_key.priv"))
    ca.save_public_key(private_key.public_key(), os.path.join(folder_path, file_name + "_key.pub"))

    mb.showinfo("Success!", "File encrypted successfully!")


def create_file_path(input_file, folder_path):
    input_file_name = input_file.split('/')[-1].split('.')[0]  # wyjmuje nazwę pliku
    file_path = 'encrypted_' + input_file_name + '.txt'
    file_path = os.path.join(folder_path, file_path)  # tworzenie ścieżek do wygenerowania
    return file_path


def create_decryption_output_file(input_file, extension):
    path = os.path.dirname(input_file.get())
    output_path = os.path.join(path, "Decrypted files")
    if not os.path.exists(output_path):
        os.makedirs(output_path)
    input_file_name = input_file.get().split('/')[-1].split('.')[0]
    output_file_name = 'decrypted_' + input_file_name.replace("encrypted_", "", 1) + extension
    output_file_path = os.path.join(output_path, output_file_name)
    return output_file_path
    # wyjmuje ścieżkę z pliku, dodaje przedrostek decrypted i resztę nazwy z rozszerzeniem txt


# jak działa szyfrowanie symetryczne, asymetryczne, oraz mieszane
# https://cdn.discordapp.com/attachments/1234544566556692570/1241049559577137284/voice-message.ogg?ex=664ac338&is=664971b8&hm=a2a340bf1e0d99d322e67bc371bb5d7150ef0227d77d2e1d0e7e6684acd46beb&
# https://cdn.discordapp.com/attachments/1234544566556692570/1241049702758350981/voice-message.ogg?ex=664ac35a&is=664971da&hm=f25e037100dbb5cd06f1901b36b1258af82277d1b73562c58a25d1146115e955&

def decrypt(input_file, key_file):
    with open(input_file.get(), "rb") as f:
        encrypted_asym_key_sym = f.read(256)
        encrypted_file_sym = f.read()
    # TODO: odczytanie klucza prywatnego
    private_key = ca.load_private_key(key_file.get())

    encrypt_mode, extension, iv, key_sym = ca.decrypt_asym(encrypted_asym_key_sym, private_key).split('\n')
    plaintext = cs.decrypt_sym(encrypted_file_sym, key_sym.encode(), iv.encode(), mode=encrypt_mode)

    output_file = create_decryption_output_file(input_file, extension)

    with open(output_file, "wb") as f:
        f.write(plaintext)

    mb.showinfo("Success!", "File decrypted successfully!")


def add_user(is_menu_alive, menu, selected_user, users_list):
    if is_menu_alive.get():
        return
    is_menu_alive.set(True)

    # Konfiguracja okna
    add_user_root = tk.Toplevel()
    add_user_root.title("Add user")
    add_user_root.iconbitmap("icon.ico")
    add_user_root.resizable(False, False)
    print(add_user_root.winfo_width(), add_user_root.winfo_height())
    add_user_root.protocol("WM_DELETE_WINDOW", lambda: (add_user_root.destroy(), is_menu_alive.set(False)))

    # Tekst "enter username"
    username_label = tk.Label(add_user_root, text="Enter username:")
    username_label.grid(row=0, padx=5, pady=10)

    # Pole na nazwę użytkownika
    user_name = tk.StringVar(value="")
    username_entry = tk.Entry(add_user_root, textvariable=user_name, width=30)
    username_entry.grid(row=1, padx=5, pady=10)

    # Utworzenie katalogu z kluczami użytkownika
    def create_user_files():
        path = os.getcwd()
        folder_path = os.path.join(path, "users")
        if not os.path.exists(folder_path):
            os.mkdir(folder_path)
        user_folder_path = os.path.join(folder_path, user_name.get())
        os.mkdir(user_folder_path)
        key_pair = ca.generate_key_pair()
        public_key_filepath = os.path.join(user_folder_path, "key.pub")
        private_key_filepath = os.path.join(user_folder_path, "key.priv")
        ca.save_public_key(key_pair.public_key(), public_key_filepath)
        ca.save_private_key(key_pair, private_key_filepath)

    # Sprawdzenie czy użytkownik istnieje
    def finalize():
        # Sprawdza, czy użytkownik nie istnieje
        if user_name.get() in users_list:
            mb.showerror("Error", "Username already taken!")
            return

        # Sprawdza, czy użytkownik został podany
        if user_name.get() == "":
            mb.showerror("Error", "Username empty!")
            return

        # Dodawanie
        users.append(user_name.get())
        create_user_files()
        menu.config(state=tk.NORMAL)
        # Odświeżenie listy
        menu['menu'].delete(0, 'end')
        for user in load_users():
            menu['menu'].add_command(label=user, command=lambda value=user: selected_user.set(value))

        # Zamknięcie okna
        is_menu_alive.set(False)
        add_user_root.destroy()

    # Przycisk zatwierdzenia
    user_add_button = tk.Button(add_user_root, text="Add user", command=finalize)
    user_add_button.grid(row=2, padx=5, pady=10)


def get_user_keys(user):
    users_dir = os.path.join(os.getcwd(), "users")
    user_folder = os.path.join(users_dir, user)
    if not os.path.isdir(user_folder):
        return None, None
    private_key_file = os.path.join(user_folder, "key.priv")
    public_key_file = os.path.join(user_folder, "key.pub")
    return private_key_file, public_key_file


def create_encryption_UI(frame, input_file, users):
    # Napis input
    label_selected = tk.Label(frame, text="Input file:")
    label_selected.grid(row=0, column=0, padx=5, pady=10)

    # Pole do wyświetlania wybranego pliku
    file_name = tk.StringVar(value="Null")
    entry_input = tk.Entry(frame, textvariable=file_name)
    entry_input.config(state='readonly')
    entry_input.grid(row=0, column=1, padx=5, pady=10)

    # Przycisk do wyboru pliku
    button_select_input = tk.Button(frame, text="Select file",
                                    command=lambda: get_file(entry_input, input_file, file_name, [("All files", ".*")]))
    button_select_input.grid(row=0, column=2, padx=5, pady=10)

    # Napis do użytkownika
    label_user = tk.Label(frame, text="To:")
    label_user.grid(row=1, column=0, padx=5, pady=10)

    # Wybór użytkownika
    user_selected = tk.StringVar(value="Select user")
    dropdown_user = tk.OptionMenu(frame, user_selected, *users)
    dropdown_user.config(width=14)
    dropdown_user.grid(row=1, column=1, padx=5, pady=10)
    if len(users) == 1 and users[0] == "<Null>":
        dropdown_user.config(state=tk.DISABLED)

    # Dodawanie użytkownika
    add_menu_open = tk.BooleanVar(value=False)
    add_user_button = tk.Button(frame, text="Add user",
                                command=lambda: add_user(add_menu_open, dropdown_user, user_selected, users))
    add_user_button.grid(row=1, column=2, padx=5, pady=10)

    # # Napis do klucza
    # label_key_value = tk.Label(frame, text="Key value:")
    # label_key_value.grid(row=1, column=0, padx=5, pady=10)
    #
    # # Pole do wyświetlania klucza
    # entry_key_value = tk.Entry(frame, textvariable=key_value)
    # entry_key_value.grid(row=1, column=1, padx=5, pady=10)
    #
    # # Generacja nowego klucza
    # reroll_button = tk.Button(frame, text="Reroll key", command=lambda: cs.generate_key(key_value, KEY_LENGTH))
    # reroll_button.grid(row=1, column=2, padx=10, pady=10)

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
    confirm = tk.Button(frame, text="Encrypt!", bg="#9EDBC9",
                        command=lambda: encrypt(input_file.get(), encrypt_mode.get(), user_selected.get()))
    confirm.grid(row=5, column=0, padx=10, pady=10)

    # Przycisk clear
    button_clear = tk.Button(frame, text="Clear", bg="#FC68A0",
                             command=lambda: reset_form([input_file, key_value, file_name]))
    button_clear.grid(row=5, column=2, pady=10, padx=10)


def create_decryption_UI(frame, input_file, key_file):
    # Napis wybrany plik
    label_selected = tk.Label(frame, text="Input file:")
    label_selected.grid(row=0, column=0, padx=10, pady=10)

    # Pole do wyświetlania wybranego pliku
    file_name = tk.StringVar(value="Null")
    entry_input = tk.Entry(frame, textvariable=file_name)
    entry_input.config(state='readonly')
    entry_input.grid(row=0, column=1, padx=5, pady=10)

    # Przycisk do wyboru pliku
    button1 = tk.Button(frame, text="Select file",
                        command=lambda: get_file(entry_input, input_file, file_name, [("Text files", "*.txt")]))
    button1.grid(row=0, column=2, pady=10, padx=10)

    # Napis klucz
    label_key = tk.Label(frame, text="Key file")
    label_key.grid(row=1, column=0, padx=10, pady=5)

    # Wczytanie klucza
    key_file_name = tk.StringVar(value="Null")
    entry_key = tk.Entry(frame, textvariable=key_file_name)
    entry_key.config(state='readonly')
    entry_key.grid(row=1, column=1, padx=5, pady=10)

    # Przycisk do klucza
    button2 = tk.Button(frame, text="Select file",
                        command=lambda: get_file(entry_key, key_file, key_file_name, [("Key files", ".priv")]))
    button2.grid(row=1, column=2, padx=5, pady=10)

    # Przycisk decrypt
    button_decrypt = tk.Button(frame, text="Decrypt!", bg="#E2A879",
                               command=lambda: decrypt(input_file, key_file))
    button_decrypt.grid(row=3, column=0, padx=5, pady=10)

    # Przycisk clear
    button_clear = tk.Button(frame, text="Clear", bg="#FC68A0",
                             command=lambda: reset_form([input_file, key_file, key_file_name, file_name]))
    button_clear.grid(row=3, column=2, padx=5, pady=10)


def show_about_section(section_open):
    if section_open.get() == 1:
        return

    section_open.set(1)
    # Stworzenie nowego okna
    fonts = ['Helvetica', 'Verdana', 'Cascadia Mono', 'Lato', 'Roboto']
    font = fonts[4]
    about_root = tk.Toplevel()
    about_root.title("About")
    about_root.iconbitmap("icon.ico")
    about_root.protocol("WM_DELETE_WINDOW", lambda: (about_root.destroy(), section_open.set(0)))
    text_widget = tk.Text(about_root, wrap='word', height=39, width=50, font=(font, 11))

    # Dodawanie tekstu
    text_widget.insert('1.0', "Project Name:\n", 'title')
    text_widget.insert(tk.END, "File Encryptor / File Decryptor\n\n")
    text_widget.insert(tk.END, "Description:\n", 'title')
    description = ("File Encryptor is a user-friendly tool designed to encrypt any file using either block or stream"
                   " encryption methods, with the option to use a generated or custom key. Encrypted files, as well"
                   " as both public and private keys generated by the program, are stored within the Cryptography"
                   " Output folder located in the source directory.\n\n"
                   "File Decryptor is a user-friendly tool designed to decrypt files encrypted exclusively by"
                   " the File Encryptor. The program automatically identifies the encryption method, ensuring accurate"
                   " decryption, and preserves the original file extension. Decryption requires only the encrypted file"
                   " and the corresponding private key.\n\n")
    text_widget.insert(tk.END, description)

    text_widget.insert(tk.END, "Usage:\n", 'title')
    text_widget.insert(tk.END, ("1. Encrypt files using File Encryptor with a chosen encryption "
                                "method and a 16-byte key.\n"
                                "2. Store the encrypted files and keys in the Cryptography Output folder.\n"
                                "3. Use File Decryptor to decrypt files, relying on the program's automatic"
                                " encryption method detection.\n\n"))

    text_widget.insert(tk.END, "Authors:\n", 'title')
    authors = ["Hanna Banasiak, 193078", "Aleksandra Bujny, 193186", "Marcel Grużewski, 193589",
               "Michał Pawiłojć, 193159", "Jakub Romanowski, 193637"]
    for author in authors:
        text_widget.insert(tk.END, author + '\n')

    text_widget.insert(tk.END, "\nGitHub:\n", 'title')
    text_widget.insert(tk.END, "For more information and source code visit our\n")
    text_widget.insert(tk.END, "[GitHub repository]", 'hyperlink')

    # Definiowanie stylu pogrubienia
    text_widget.tag_configure('title', font=(font, 16, 'bold'))

    # Definiowanie podkreślenia hiperłącza
    text_widget.tag_configure('hyperlink', foreground="blue", underline=True)
    text_widget.tag_bind('hyperlink', '<Enter>', lambda e: text_widget.config(cursor='hand2'))
    text_widget.tag_bind('hyperlink', '<Leave>', lambda e: text_widget.config(cursor=''))
    text_widget.tag_bind('hyperlink', '<Button-1>',
                         lambda e: webbrowser.open_new("https://github.com/GGBJacob/File-Encryptor"))

    # Wyłączenie edycji tekstu
    text_widget.config(state='disabled', padx=10, pady=5, cursor='')
    text_widget.pack(pady=10, padx=10)


def load_users():
    users_path = os.path.join(os.getcwd(), "users")
    if not os.path.exists(users_path) or len(os.listdir(users_path)) == 0:
        return ["<Null>"]
    return os.listdir(users_path)


if __name__ == "__main__":
    # Główne okno
    root = tk.Tk()
    # root.geometry("357x200")
    root.iconbitmap("icon.ico")
    root.eval('tk::PlaceWindow . center')  # <- środkuje okno na ekranie
    root.resizable(False, False)

    encryption_input_file = tk.StringVar(value="Null")
    decryption_input_file = tk.StringVar(value="Null")
    user_selected = tk.StringVar(value="Null")
    users = load_users()
    key_value = tk.StringVar(value="Null")
    key_file = tk.StringVar(value="Null")
    about_section_open = tk.IntVar(value=0)

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

    menubar.add_command(label="About", command=lambda: show_about_section(about_section_open))

    # Ramki do zmiany wyglądu szyfrowanie/odszyfrowywanie
    encrypt_frame = tk.Frame(root)
    decrypt_frame = tk.Frame()

    create_decryption_UI(decrypt_frame, decryption_input_file, key_file)
    create_encryption_UI(encrypt_frame, encryption_input_file, users)

    if appMode.get() == 1:
        change_frame(decrypt_frame, encrypt_frame, appMode.get(), root)
    else:
        change_frame(encrypt_frame, decrypt_frame, appMode.get(), root)

    # Config i pętla apki
    root.config(menu=menubar)
    root.mainloop()
