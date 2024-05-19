To build exe, run the following command in the directory with python files:

pyinstaller --noconsole ^
--onefile --clean --noconfirm ^
--distpath . ^
--icon=icon.ico ^
-n "File Encryptor" ^
main.py
