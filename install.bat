@echo off
echo Per continuare assicurati di aver installato python.
pause
python.exe -m pip install --upgrade pip
pip install pycryptodome
echo Installazione completata
pause
exit