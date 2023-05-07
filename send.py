# Tkinter imports
import tkinter as tk
from tkinter import *
import tkinter.ttk as ttk
from tkinter.ttk import *
from tkinter.filedialog import askopenfilename
# Hashlib import
import hashlib as h
# Certificate import
import Certificate as cert
# RSA and EC Cryptography imports
import RSA as rsa
import ecc
import os
from ctypes import *
import socket
import struct
import subprocess
from Crypto.Cipher import AES
import sys

# Represents an Application
class App:
    # Builder
    def __init__(self, root):
        self.root = root
        self.root.geometry("400x180")
        self.root.resizable(0, 0)
        self.root.title("SuperDoggy")
        # Call to place_items() and textvariables needed
        self.target_ip = StringVar()
        self.target_username = StringVar()
        self.target_password = StringVar()
        self.on_password = IntVar()
        self.on_ip = IntVar()
        self.place_items()

    # Places the items in the root
    def place_items(self):
        # Target IP label and Entry
        self.label_target_ip = tk.Label(self.root, text = "Target IP: ")
        self.label_target_ip.place(x = 10, y = 10)
        self.entry_target_ip = tk.Entry(self.root, textvariable = self.target_ip)
        self.entry_target_ip.place(x = 95, y = 10)
        # Target username label and Entry
        self.label_target_username = tk.Label(self.root, text = "Username: ")
        self.label_target_username.place(x = 10, y = 35)
        self.entry_target_username = tk.Entry(self.root, textvariable = self.target_username)
        self.entry_target_username.place(x = 95, y = 35)
        # Target password label and Entry
        self.label_target_password = tk.Label(self.root, text = "Password: ")
        self.label_target_password.place(x = 10, y = 60)
        self.entry_target_password = tk.Entry(self.root, textvariable = self.target_password)
        self.entry_target_password.place(x = 95, y = 60)
        #Check Buttons
        self.checkbutton_password = tk.Checkbutton(root, text = "Ask password", variable = self.on_password, onvalue = 1, offvalue = 0)
        self.checkbutton_password.place(x = 10, y = 95)
        self.checkbutton_ip = tk.Checkbutton(root, text = "Check IP", variable = self.on_ip, onvalue = 1, offvalue = 0)
        self.checkbutton_ip.place(x = 10, y = 120)
        # Buttons
        self.connect_button = tk.Button(self.root, text = "Connect", command = self.connect)
        self.connect_button.place(x = 10, y = 145)

    def _send(sck: socket.socket, message_type, message, aes_key = None):
        if(message_type == 0):
            # Obtaining the size of the file
            filesize = os.path.getsize(message)
            # Send the size to the server
            sck.sendall(struct.pack("<Q", filesize))
            # Send the file using 1024 bytes blocks
            with open(message, "rb") as f:
                while read_bytes := f.read(1024):
                    sck.sendall(read_bytes)
        elif(message_type == 2):
            aes_cipher = AES.new(aes_key.to_bytes(32, sys.byteorder), AES.MODE_EAX)
            ciphertext, tag = aes_cipher.encrypt_and_digest(message.encode())
            # Message to send
            message_to_send = aes_cipher.nonce + tag + ciphertext
            sck.send(message_to_send)
            
    def _rcv_key(sck: socket.socket, tls_version, filename):
        text_received = sck.recv(1024)
        if(text_received.decode() == "false"):
            return []
        #verified = True if text_received.decode() == "true" else False

        if(tls_version == "TLS 1.2"):
            try:
                file = open("KEYS/" + filename.replace(".txt", "") + "-rsa", "r")
                private_key_file_content = file.readlines()
                file.close()
            except IOError:
                return -1
            
            try:
                file = open("KEYS/" + filename.replace(".txt", "-rsa.pub"), "r")
                public_key_file_content = file.readlines()
                file.close()
            except IOError:
                return -1

            text_received = text_received.decode().split(" ")
            private_key = int(private_key_file_content[1])
            n = int(public_key_file_content[1].replace("Modulo: ", ""))
            text_received_decrypted = rsa.RSACipher.decrypt(int(text_received[0]), private_key, n)

            aes_key = int(text_received_decrypted)
            nonce = int(text_received[1])
        elif(tls_version == "TLS 1.3"):
            try:
                file = open("KEYS/" + filename.replace(".txt", "") + "-ecc", "r")
                private_key_file_content = file.readlines()
                file.close()
            except IOError:
                return -1
            
            private_key = int(private_key_file_content[1])
            text_received = text_received.decode().split(" ")
            print(text_received)
            kG = ecc.S256Point(int(text_received[0].replace("S256Point(", "").replace(",", ""), 16), int(text_received[1].replace(")", ""), 16))
            q = ecc.S256Point(int(text_received[2].replace("S256Point(", "").replace(",", ""), 16), int(text_received[3].replace(")", ""), 16))
            text_received_decrypted = ecc.S256Point.decrypt(kG, q, private_key)
            aes_key = h.sha256()
            aes_key.update(str(text_received_decrypted).encode('utf-8'))
            aes_key = int(aes_key.hexdigest(), 16)
            nonce = int(text_received[4])
        print(aes_key)
        return [aes_key, nonce]

    def _rcv_validation(sck: socket.socket, password, username, ip):
        text_received = sck.recv(1024)
        verified = True if(text_received.decode() == "true") else False
        if(verified):
            print("OkeyPASS")
            sshpass_command = 'sshpass -p {} ssh {}@{}'.format(password, username, ip)
            subprocess.Popen(['gnome-terminal', '--', 'bash', '-c', sshpass_command])
            print("bye")
            #os.system("sshpass -p {} ssh {}@{}".format(password, username, ip))
        else:
            print("False")

    def connect(self):
        filename = askopenfilename()
        try:
            file = open(filename, "r")
            tls_version = file.readline()
            file.close()
        except IOError:
            return -1
        
        tls_version = tls_version.replace("TLS version: ", "").replace("\n", "")

        with socket.create_connection((self.target_ip.get(), 6190)) as conn:
            print("Conectado al servidor.")
            print("Enviando archivo...")
            #App._send_certificate(conn, filename)
            App._send(conn, 0, filename)
            print("Enviado.")
        print("Conexión cerrada.")

        with socket.create_server(("localhost", 6191)) as server:
            print("Esperando al cliente...")
            conn, address = server.accept()
            print(f"{address[0]}:{address[1]} conectado.")
            print("Recibiendo archivo...")
            received_text = App._rcv_key(conn, tls_version, filename.replace("/home/juanlu/Documentos/TFG-CODE_LOCAL/", ""))
            print("Archivo recibido.")
        print("Conexión cerrada.")
        
        print(received_text)
        if(received_text == []):
            return

        with socket.create_connection((self.target_ip.get(), 6192)) as conn:
            print("Conectado al servidor.")
            print("Enviando archivo...")
            #App._send_certificate(conn, filename)
            App._send(conn, 2, str(received_text[1]), aes_key=received_text[0])
            print("Enviado.")
        print("Conexión cerrada.")

        with socket.create_server(("localhost", 6193)) as server:
            print("Esperando al cliente...")
            conn, address = server.accept()
            print(f"{address[0]}:{address[1]} conectado.")
            print("Recibiendo archivo...")
            received_text = App._rcv_validation(conn, self.target_password.get(), self.target_username.get(), self.target_ip.get())
            print("Archivo recibido.")
        print("Conexión cerrada.")
        

"""     def _send_certificate(sck: socket.socket, filename):
        # Obtaining the size of the file
        filesize = os.path.getsize(filename)
        # Send the size to the server
        sck.sendall(struct.pack("<Q", filesize))
        # Send the file using 1024 bytes blocks
        with open(filename, "rb") as f:
            while read_bytes := f.read(1024):
                sck.sendall(read_bytes) """


root = tk.Tk()
app = App(root)
root.mainloop()