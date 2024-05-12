import tkinter as tk
from tkinter import filedialog as fd
from tkinter import messagebox as mb


def get_file(entry, input_file, filetypes):
    filepath = fd.askopenfilename(title='Wybierz plik', filetypes=filetypes)
    entry.config(state='normal')
    if not filepath:
        input_file.set("Null")
    else:
        input_file.set(filepath)
    entry.config(state='readonly')


def change_frame(frame_to_forget, frame_to_add):
    frame_to_forget.grid_forget()
    frame_to_add.grid(column=0, row=0)


def reset_form(arguments):
    for argument in arguments:
        argument.set("Null")


def save_file(entry, file, filetypes):
    filepath = fd.asksaveasfilename(title="Wybierz plik", defaultextension=filetypes[-1][1],
                                    filetypes=filetypes)
    entry.config(state='normal')
    if not filepath:
        file.set("Null")
    else:
        file.set(filepath)
    entry.config(state='readonly')


def check_file_name(output_name, input_file):
    if input_file.get() == "Null":
        mb.showerror("Error", "Select a file to encrypt!")
        return
    elif len(input_file.get().split('.')) > 1 and input_file.get().split('.') != "txt":
        mb.showerror("Error", "Wrong file format!")
        return
    elif len(output_name.get()) == 0:
        mb.showerror("Error", "Enter output file name!")
        return
    tmp = output_name.get().split('.')
    if len(tmp) < 2:
        mb.showerror("Error", "Provide file extension!")
        return
    elif tmp[len(tmp) - 1] != "txt":
        mb.showerror("Error", "Invalid file extension!\nAccepted extensions: *.txt")
        return


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


# TODO implementacja generowania klucza (key_value samo się wyświetli w okienku)
def generate_key(key_value):
    key_value.set("XYZ")
    pass
    # key_value.set(*wartość klucza jako string*)


# TODO implementacja deszyfrowania plików
def decrypt_file(input_file, key_file, output_file):
    if (input_file.get() == "Null" or key_file.get() == "Null" or output_file.get() == "Null"):
        mb.showerror("Error", "Missing arguments!")

    # Zasada ta sama co przy szyfrowaniu
    # .get() i te sprawy
    pass


def create_encryption_UI(frame, input_file, key_value, key_file, output_file):
    # Napis 1
    label_selected = tk.Label(frame, text="Selected file:")
    label_selected.grid(row=0, column=0, padx=5, pady=10)

    # Pole do wyświetlania wybranego pliku
    entry_input = tk.Entry(frame, textvariable=input_file)
    entry_input.config(state='readonly')
    entry_input.grid(row=0, column=1, padx=5, pady=10)

    # Przycisk do wyboru pliku
    button_select_input = tk.Button(frame, text="Select file",
                                    command=lambda: get_file(entry_input, input_file, [("All files", ".*")]))
    button_select_input.grid(row=0, column=2, padx=5, pady=10)

    # Napis 2
    label_key_value = tk.Label(frame, text="Encryption key value:")
    label_key_value.grid(row=1, column=0, padx=5, pady=10)

    # Pole do wyświetlania klucza
    entry_key_value = tk.Entry(frame, textvariable=key_value)
    entry_key_value.grid(row=1, column=1, padx=5, pady=10)

    # Napis 3
    label_key_file = tk.Label(frame, text="Encryption key file:")
    label_key_file.grid(row=2, column=0, padx=5, pady=10)

    # Pole do wyświetlania pliku z kluczem
    entry_key_file = tk.Entry(frame, textvariable=key_file)
    entry_key_file.config(state='readonly')
    entry_key_file.grid(row=2, column=1, padx=5, pady=10)

    # Przycisk do stworzenia pliku z kluczem
    button_key_output = tk.Button(frame, text="Create file", command=lambda: save_file(entry_key_file, key_file,
                                                                                       filetypes=[
                                                                                           ("Text files", "*.txt")]))
    button_key_output.grid(row=2, column=2, padx=5, pady=10)

    # Napis 4
    label_output = tk.Label(frame, text="Output file:")
    label_output.grid(row=3, column=0, padx=5, pady=10)

    # Pole do wyświetlania pliku wyjściowego
    entry_output = tk.Entry(frame, textvariable=output_file)
    entry_output.config(state='readonly')
    entry_output.grid(row=3, column=1, padx=5, pady=10)

    # Przycisk do wyboru pliku
    button_select_output = tk.Button(frame, text="Select file",
                                     command=lambda: get_file(entry_output, output_file, [("All files", ".*")]))
    button_select_output.grid(row=3, column=2, pady=5, padx=10)

    # # Wybór szyfrowania
    # encryption = tk.IntVar(value=1)
    # rbutton1 = tk.Radiobutton(frame, text="Szyfrowanie 1", value=1, variable=encryption, activebackground="red")
    # rbutton2 = tk.Radiobutton(frame, text="Szyfrowanie 2", value=2, variable=encryption)
    # rbutton3 = tk.Radiobutton(frame, text="Szyfrowanie 3", value=3, variable=encryption)
    #
    # rbutton1.grid(row=2, column=0, padx=5, pady=10)
    # rbutton2.grid(row=2, column=1, padx=0, pady=10)
    # rbutton3.grid(row=2, column=2, padx=5, pady=10)

    # Przycisk szyfrowania
    confirm = tk.Button(frame, text="Encrypt!",
                        command=lambda: encrypt_file(input_file, key_value, key_file, output_file))
    confirm.grid(row=4, column=0, padx=10, pady=10)

    # Generacja nowego klucza
    reroll_button = tk.Button(frame, text="Reroll key", command=lambda: generate_key(key_value))
    reroll_button.grid(row=4, column=1, padx=10, pady=10)

    # Przycisk clear
    button_clear = tk.Button(frame, text="Clear",
                             command=lambda: reset_form([input_file, key_file, key_value, output_file]))
    button_clear.grid(row=4, column=2, pady=10, padx=10)


def create_decryption_UI(frame, input_file, key_file, output_file):
    # Napis wybrany plik
    label_selected = tk.Label(frame, text="Selected file:")
    label_selected.grid(row=0, column=0, padx=5, pady=10)

    # Pole do wyświetlania wybranego pliku
    entry_input = tk.Entry(frame, textvariable=input_file)
    entry_input.config(state='readonly')
    entry_input.grid(row=0, column=1, padx=5, pady=10)

    # Przycisk do wyboru pliku
    button1 = tk.Button(frame, text="Select file",
                        command=lambda: get_file(entry_input, input_file, [("All files", ".*")]))
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
                        command=lambda: get_file(entry_key, key_file, [("Text files", "*.txt")]))
    button2.grid(row=1, column=2, padx=5, pady=10)

    # Napis output
    label_output = tk.Label(frame, text="Output file:")
    label_output.grid(row=2, column=0, padx=5, pady=10)

    # Pole do wyświetlania ścieżki outputu
    entry_output = tk.Entry(frame, textvariable=output_file)
    entry_output.config(state="readonly")
    entry_output.grid(row=2, column=1, padx=5, pady=10)

    # Przycisk do wczytania outputu
    button3 = tk.Button(frame, text="Select file",
                        command=lambda: get_file(entry_output, output_file, [("Text files", "*.txt")]))
    button3.grid(row=2, column=2, padx=5, pady=10)

    # Przycisk decrypt
    button_decrypt = tk.Button(frame, text="Decrypt!", command=lambda: decrypt_file(input_file, key_file, output_file))
    button_decrypt.grid(row=3, column=0, padx=5, pady=10)

    # Przycisk clear
    button_clear = tk.Button(frame, text="Clear", command=lambda: reset_form([input_file, key_file, output_file]))
    button_clear.grid(row=3, column=2, padx=5, pady=10)


def main():
    # Główne okno
    root = tk.Tk()
    # root.geometry("357x200")
    root.title("Cyberprojekt")
    root.iconbitmap("icon.ico")
    # root.eval('tk::PlaceWindow . center') # <- środkuje okno na ekranie
    root.resizable(False, False)

    input_file = tk.StringVar(value="Null")
    key_value = tk.StringVar(value="ABCD")
    key_file = tk.StringVar(value="Null")
    output_file = tk.StringVar(value="Null")

    # Menu
    menubar = tk.Menu(root)
    appMode = tk.IntVar(value=1)

    options_menu = tk.Menu(menubar, tearoff=0)
    options_menu.add_radiobutton(label="Encrypt", value=1, variable=appMode,
                                 command=lambda: change_frame(decrypt_frame, encrypt_frame))
    options_menu.add_radiobutton(label="Decrypt", value=2, variable=appMode,
                                 command=lambda: change_frame(encrypt_frame, decrypt_frame))
    options_menu.add_command(label="Exit", command=root.quit)
    menubar.add_cascade(label="Options", menu=options_menu)

    # Ramki do zmiany wyglądu szyfrowanie/odszyfrowywanie
    encrypt_frame = tk.Frame(root)
    decrypt_frame = tk.Frame()

    create_decryption_UI(decrypt_frame, input_file, key_file, output_file)
    create_encryption_UI(encrypt_frame, input_file, key_value, key_file,output_file)

    if appMode.get() == 1:
        change_frame(decrypt_frame, encrypt_frame)
    else:
        change_frame(encrypt_frame, decrypt_frame)

    # Config i pętla apki
    root.config(menu=menubar)
    root.mainloop()


main()
