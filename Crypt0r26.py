from Crypto.Cipher import AES
from Crypto.Hash import SHA256, HMAC
from Crypto.Random import get_random_bytes
import os, socket, datetime, platform, subprocess, tkinter as tk
from tkinter import filedialog, simpledialog, messagebox

BLOCK_SIZE = 16
LOG_KEY = b"DanielLogSecretKeySHA256"
LOG_FILE = ".log_sha.aes"

def pad(data):
    padding = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([padding]) * padding

def unpad(data):
    padding = data[-1]
    if padding > BLOCK_SIZE:
        raise ValueError("Padding non valido.")
    return data[:-padding]

def derive_key_sha256(password):
    hash = SHA256.new()
    hash.update(password.encode())
    return hash.digest()

def ottieni_ip_locale():
    try: return socket.gethostbyname(socket.gethostname())
    except: return "Sconosciuto"

def ottieni_nome_wifi():
    try:
        out = subprocess.check_output(["netsh", "wlan", "show", "interfaces"], text=True)
        for line in out.splitlines():
            if "SSID" in line and "BSSID" not in line:
                return line.split(":")[1].strip()
    except: return "Sconosciuto"

def scrivi_log(azione, file, esito):
    ora = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    pc = platform.node()
    ip = ottieni_ip_locale()
    wifi = ottieni_nome_wifi()
    riga = f"[{ora}] PC:{pc} IP:{ip} WiFi:{wifi} Azione:{azione} File:{file} Esito:{esito}\n"

    try:
        log = b""
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, "rb") as f:
                dati = f.read()
                if len(dati) >= 32:
                    corpo, hmac = dati[:-32], dati[-32:]
                    HMAC.new(LOG_KEY, corpo, SHA256).verify(hmac)
                    log = corpo
        log += riga.encode()
        hmac = HMAC.new(LOG_KEY, log, SHA256).digest()
        with open(LOG_FILE, "wb") as f:
            f.write(log + hmac)
    except Exception as e:
        print("Errore salvataggio log:", e)

def cripta_file():
    path = filedialog.askopenfilename(title="Scegli file da criptare")
    if not path: return
    pw = simpledialog.askstring("Password", "Inserisci password:", show="*")
    if not pw: return

    try:
        with open(path, "rb") as f: dati = f.read()
        chiave = derive_key_sha256(pw)
        iv = get_random_bytes(16)
        cifratore = AES.new(chiave, AES.MODE_CBC, iv)
        cifrato = cifratore.encrypt(pad(dati))
        out_path = path + ".Crypt0r26"
        with open(out_path, "wb") as f:
            f.write(iv + cifrato)
        print("File criptato:", out_path)
        scrivi_log("CRIPTA", out_path, "OK")
    except Exception as e:
        print("Errore:", e)
        scrivi_log("CRIPTA", path, "ERRORE")

def decripta_file():
    path = filedialog.askopenfilename(title="Seleziona file .crypt0r26", filetypes=[("File cifrati Crypt0r26", "*.crypt0r26")])
    if not path: return
    pw = simpledialog.askstring("Password", "Inserisci password:", show="*")
    if not pw: return

    try:
        with open(path, "rb") as f: dati = f.read()
        iv, cifrato = dati[:16], dati[16:]
        chiave = derive_key_sha256(pw)
        dec = AES.new(chiave, AES.MODE_CBC, iv).decrypt(cifrato)
        dati_finali = unpad(dec)
    except Exception:
        print("Password errata o file danneggiato.")
        scrivi_log("DECRIPTA", path, "FALLITA")
        return

    try:
        out_path = path.replace(".crypt0r26", ".decrypted")
        with open(out_path, "wb") as f:
            f.write(dati_finali)
        print("File decriptato:", out_path)
        scrivi_log("DECRIPTA", path, "OK")
    except Exception as e:
        print("Errore scrittura:", e)

def mostra_log():
    if not os.path.exists(LOG_FILE):
        print("Nessun log trovato.")
        return
    try:
        with open(LOG_FILE, "rb") as f:
            dati = f.read()
        if len(dati) >= 32:
            corpo, hmac = dati[:-32], dati[-32:]
            HMAC.new(LOG_KEY, corpo, SHA256).verify(hmac)
            print("\n--- LOG ---\n" + corpo.decode() + "\n-------------\n")
    except Exception as e:
        print("Errore lettura log:", e)

def mostra_info():
    print(" == Crypt0r26 == ")
    print("\n️ Criptatore AES + SHA-256 - by Daniel")
    print("- Derivazione chiave con SHA-256")
    print("- AES-256 in modalità CBC")
    print("- Log firmati e salvati automaticamente")
    print("- Estensione .crypt0r26")
    print("© 2025 Daniel. Tutti i diritti riservati.\n")

def main():
    root = tk.Tk(); root.withdraw()

    while True:
        print("\n=== Crypt0r26 ===")
        print("1. Cripta i file")
        print("2. Decripta i file")
        print("3. Visualizza i log")
        print("4. Informazioni su Crypt0r26")
        print("5. Esci")
        scelta = input("Scelta: ")
        if scelta == "1": cripta_file()
        elif scelta == "2": decripta_file()
        elif scelta == "3": mostra_log()
        elif scelta == "4": mostra_info()
        elif scelta == "5": break
        else: print("L'opzione inserita non valida.")

if __name__ == "__main__":
    main()
