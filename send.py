# IMPORTS
import tkinter as tk
from tkinter import *
import tkinter.ttk as ttk
from tkinter.ttk import *
from tkinter.filedialog import askopenfilename
import hashlib as h
from Crypto.Cipher import AES
import os
import sys
import subprocess
import ctypes
from ctypes import *
import socket
import netifaces
import getpass
import struct
# LOCAL IMPORTS
import Certificate as cert
import RSA as rsa
import ECC as ecc

# GLOBALS
SOFT_BLUE = "#4470b8"
DARK_BLUE = "#1e2970"
WHITE = "#FFFFFF"

# This class defines the application
# Attributes:
# root -> (Tk) UI Window
# target_ip-> (StringVar) String variable for the entry_name
# target_username -> (StringVar) String variable for the entry_country
# target_password -> (StringVar) String variable for the entry_location
# label_target_ip -> (Label) Label target ip
# entry_target_ip -> (Entry) Entry to insert the target ip
# label_target_username -> (Label) Label target username
# entry_target_username -> (Entry) Entry to insert the target username
# label_target_password -> (Label) Label target password
# entry_target_password -> (Entry) Entry to insert the target password
# connect_button -> (Button) This button has the function to generate a new certificate
class App:
    # Builder
    def __init__(self, root):
        self.root = root
        self.root.geometry("400x135")
        self.root.resizable(0, 0)
        self.root.title("SuperDoggy")
        self.root.configure(bg = DARK_BLUE)
        # Call to place_items() and textvariables needed
        self.target_ip = StringVar()
        self.target_username = StringVar()
        self.target_password = StringVar()
        self.place_items()

    # This method places the items in the root window
    # Return: (void)
    def place_items(self):
        # Target IP label and Entry
        self.label_target_ip = tk.Label(self.root, text = "Target IP: ", bg = DARK_BLUE, fg = WHITE)
        self.label_target_ip.place(x = 10, y = 10)
        self.entry_target_ip = tk.Entry(self.root, textvariable = self.target_ip)
        self.entry_target_ip.place(x = 95, y = 10)
        # Target username label and Entry
        self.label_target_username = tk.Label(self.root, text = "Username: ", bg = DARK_BLUE, fg = WHITE)
        self.label_target_username.place(x = 10, y = 35)
        self.entry_target_username = tk.Entry(self.root, textvariable = self.target_username)
        self.entry_target_username.place(x = 95, y = 35)
        # Target password label and Entry
        self.label_target_password = tk.Label(self.root, text = "Password: ", bg = DARK_BLUE, fg = WHITE)
        self.label_target_password.place(x = 10, y = 60)
        self.entry_target_password = tk.Entry(self.root, textvariable = self.target_password, show = "*")
        self.entry_target_password.place(x = 95, y = 60)
        # Buttons
        self.connect_button = tk.Button(self.root, text = "Connect", command = self.connect, cursor="hand1", bg = SOFT_BLUE, fg = WHITE)
        self.connect_button.place(x = 10, y = 95)

    # It defines a method to send a message
    # Parameters:
    # sck -> (Socket) The socket
    # message_type -> (int) Type of the message which is going to be sent
    # message -> (String) Message to be sent
    # aes_key -> (int) AES key of the communication
    # Return: (int) It returns 0 if succeded, -1 if not
    def _send(sck: socket.socket, message_type, message, aes_key = None):
        if(message_type == 0):
            # Obtaining the size of the file
            filesize = os.path.getsize(message)
            # Send the size to the server
            sck.sendall(struct.pack("<Q", filesize))
            # Send the file using 1024 bytes blocks
            try:
                with open(message, "rb") as f:
                    while read_bytes := f.read(1024):
                        sck.sendall(read_bytes)
            except IOError:
                return -1
        elif(message_type == 2):
            aes_cipher = AES.new(aes_key.to_bytes(32, sys.byteorder), AES.MODE_EAX)
            ciphertext, tag = aes_cipher.encrypt_and_digest(message.encode())
            # Message to send
            message_to_send = aes_cipher.nonce + tag + ciphertext
            sck.send(message_to_send)

        return 0

    # This method defines how to receive the AES key
    # Parameters:
    # sck -> (Socket) The socket
    # tls_version -> (String) The TLS version
    # filename -> (String) Name of the file
    # Return: (List) It returns [aes_key, nonce] if succeded, [] if not    
    def _rcvKey(sck: socket.socket, tls_version, filename):
        text_received = sck.recv(8192)
        # Receive the not verificated messages
        if(text_received.decode() == "false 1"):
            tk.messagebox.showerror(title = "Error en la IP", message = "El dominio desde el que se recibe la conexión no es el mismo que el del certificado")
            return []
        elif(text_received.decode() == "false 2"):
            tk.messagebox.showerror(title = "Error en el certificado", message = "El certificado enviado no es válido o se está conectando desde otro usuario")
            return []

        # If TLS version is TLS 1.2, then process the key this way
        if(tls_version == "TLS 1.2"):
            # Reading the keys
            try:
                file = open("KEYS/" + filename, "r")
                private_key_file_content = file.readlines()
                file.close()
            except IOError:
                return []
            
            try:
                file = open("KEYS/" + filename + ".pub", "r")
                public_key_file_content = file.readlines()
                file.close()
            except IOError:
                return []
            # Decoding the text received
            text_received = text_received.decode().split(" ")

            private_key = int(private_key_file_content[1].replace("0x", ""), 16)
            n = int(public_key_file_content[1].replace("Modulo: 0x", ""), 16)

            # Decrypting the text
            text_received_decrypted = rsa.RSACipher.decrypt(int(text_received[0]), private_key, n)

            aes_key = int(text_received_decrypted)
            nonce = int(text_received[1])
        # If TLS version is TLS 1.3, then process the key this way
        elif(tls_version == "TLS 1.3"):
            # Reading the keys
            try:
                file = open("KEYS/" + filename, "r")
                private_key_file_content = file.readlines()
                file.close()
            except IOError:
                return []
        
            # Decoding the text received
            text_received = text_received.decode().split(" ")

            private_key = int(private_key_file_content[1].replace("0x", ""), 16)

            kG = ecc.S256Point(int(text_received[0].replace("S256Point(", "").replace(",", "").replace("0x", ""), 16), int(text_received[1].replace(")", "").replace("0x", ""), 16))
            q = ecc.S256Point(int(text_received[2].replace("S256Point(", "").replace(",", "").replace("0x", ""), 16), int(text_received[3].replace(")", "").replace("0x", ""), 16))
            
            # Decrypting the text
            text_received_decrypted = ecc.S256Point.decrypt(kG, q, private_key)

            aes_key = h.sha256()
            aes_key.update(str(text_received_decrypted).encode('utf-8'))
            aes_key = int(aes_key.hexdigest(), 16)
            nonce = int(text_received[4])
        # If TLS version is TLS 1.5 or TLS 2.0, then process the key this way
        elif(tls_version == "TLS 1.5" or tls_version == "TLS 2.0"):
            # CDLL Library
            decrypt_crystals_c = CDLL("SO/decrypt_crystals.so")
            # Define the C function prototype
            decrypt_crystals_c.decrypt.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8)]
            decrypt_crystals_c.restype = None

            file = open("KEYS/" + filename, "r")
            lines = file.readlines()
            file.close()

            secret_key_line = lines[1].replace("]", "").replace("[", "").split(",")
            for i in range(len(secret_key_line)):
                secret_key_line[i] = int(secret_key_line[i])
            secret_key_array = (ctypes.c_uint8 * len(secret_key_line))(*secret_key_line)

            text_received = text_received.decode().split(" ")
            ciphertext_line = text_received[0].split(",")
            for i in range(len(ciphertext_line)):
                ciphertext_line[i] = int(ciphertext_line[i])
            ciphertext_array = (ctypes.c_uint8 * len(ciphertext_line))(*ciphertext_line)

            # Executing the C function
            decrypt_crystals_c.decrypt(secret_key_array, ciphertext_array)

            file = open("help.txt", "r")
            line = file.readline()
            file.close()
            os.remove("help.txt")

            line = line.split(",")
            aes_line = []
            for i in range(len(line)):
                aes_line.append(int(line[i]))
            aes_key = bytes(aes_line)

            aes_key = int.from_bytes(aes_key, byteorder=sys.byteorder)
            nonce = int(text_received[1])
            
        return [aes_key, nonce]

    # This method defines how to receive the validation
    # Parameters:
    # sck -> (Socket) The socket
    # password -> (String) The target password
    # username -> (String) The target username
    # ip -> (String) The target IP address
    # Return: (void)
    def _rcv_validation(sck: socket.socket, password, username, ip):
        text_received = sck.recv(1024)
        verified = True if(text_received.decode() == "true") else False

        if(verified):
            sshpass_command = 'sshpass -p {} ssh -o StrictHostKeyChecking=no {}@{}'.format(password, username, ip)
            subprocess.Popen(['gnome-terminal', '--', 'bash', '-c', sshpass_command])
        else:
            tk.messagebox.showerror(title = "Error en la verificación", message = "El certificado enviado no es válido")

    # This method controls the connections. It gets called when the connection button is pressed
    # Return: (void)
    def connect(self):
        hostname = socket.gethostname()
        ip_addr = socket.gethostbyname(hostname)
        filename = askopenfilename()

        try:
            file = open(filename, "r")
            tls_version = file.readline()
            file.close()
        except IOError:
            return
        
        interfaces = netifaces.interfaces()
        direcciones_ip_filtradas = []
        for interfaz in interfaces:
            direcciones = netifaces.ifaddresses(interfaz)
            if netifaces.AF_INET in direcciones:
                for direccion in direcciones[netifaces.AF_INET]:
                    if 'addr' in direccion and not direccion['addr'].startswith('127.'):
                        direcciones_ip_filtradas.append(direccion['addr'])
        ip_addr = direcciones_ip_filtradas[0]
        
        tls_version = tls_version.replace("TLS version: ", "").replace("\n", "")

        try:
            with socket.create_connection((self.target_ip.get(), 6190)) as conn:
                App._send(conn, 0, filename)
                conn.sendall(("\n" + self.target_username.get()).encode("utf-8"))
                conn.sendall(("\n" + getpass.getuser()).encode("utf-8"))
        except OSError as error:
            print("OSError:", error)
            tk.messagebox.showerror(title = "Error en la ruta", message = "No se puede establecer la ruta a {}".format(self.target_ip.get()))
            return

        with socket.create_server((ip_addr, 6191)) as server:
            conn, address = server.accept()
            filename = filename.split("/")

            if(tls_version == "TLS 1.2"):
                filename = filename[len(filename) - 1].replace(".txt", "")
            elif(tls_version == "TLS 1.3"):
                filename = filename[len(filename) - 1].replace(".txt", "")
            elif(tls_version == "TLS 1.5"):
                filename = filename[len(filename) - 1].replace(".txt", "")
            else:
                filename = filename[len(filename) - 1].replace(".txt", "")

            received_text = App._rcvKey(conn, tls_version, filename)
        
        if(received_text == []):
            return

        with socket.create_connection((self.target_ip.get(), 6192)) as conn:
            App._send(conn, 2, str(received_text[1]), aes_key=received_text[0])

        with socket.create_server((ip_addr, 6193)) as server:
            conn, address = server.accept()
            App._rcv_validation(conn, self.target_password.get(), self.target_username.get(), self.target_ip.get())

        return

root = tk.Tk()
app = App(root)
root.mainloop()