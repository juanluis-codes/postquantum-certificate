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

# GLOBALS
ISSUING_KEYSET = None
ISSUING_KEYS_FILENAME = os.getcwd() + "/KEYS/issuing_keys.txt"

# Represents an Application
class App:
    # Builder
    def __init__(self, root):
        self.root = root
        self.root.geometry("400x180")
        self.root.resizable(0, 0)
        self.root.title("Certificates Certlu")
        # Call to place_items() and textvariables needed
        self.organization_name = StringVar()
        self.organization_country = StringVar()
        self.organization_location = StringVar()
        self.organization_domain = StringVar()
        self.tls_version = StringVar()
        self.tls_versions = ["TLS 1.2", "TLS 1.3"]
        self.tls_version.set(self.tls_versions[0])
        self.place_items()
        # Read the Keys File
        self._read_issuing_keys_file()

    # Places the items in the root
    def place_items(self):
        # Name label and Entry
        self.label_name = tk.Label(self.root, text = "Organización: ")
        self.label_name.place(x = 10, y = 10)
        self.entry_name = tk.Entry(self.root, textvariable = self.organization_name)
        self.entry_name.place(x = 95, y = 10)
        # Country label and Entry
        self.label_country = tk.Label(self.root, text = "País: ")
        self.label_country.place(x = 10, y = 35)
        self.entry_country = tk.Entry(self.root, textvariable = self.organization_country)
        self.entry_country.place(x = 95, y = 35)
        # Location label and Entry
        self.label_location = tk.Label(self.root, text = "Localidad: ")
        self.label_location.place(x = 10, y = 60)
        self.entry_location = tk.Entry(self.root, textvariable = self.organization_location)
        self.entry_location.place(x = 95, y = 60)
        # Domain label and Entry
        self.label_domain = tk.Label(self.root, text = "Dominio: ")
        self.label_domain.place(x = 10, y = 85)
        self.entry_domain = tk.Entry(self.root, textvariable = self.organization_domain)
        self.entry_domain.place(x = 95, y = 85)
        # Choosing between TLS versions
        self.tls_menu = ttk.Combobox(self.root, textvariable = self.tls_version, values = self.tls_versions)
        self.tls_menu.place(x = 10, y = 110)
        # Buttons
        self.generate_button = tk.Button(self.root, text = "Generate certificate", command = self.generate)
        self.generate_button.place(x = 10, y = 145)
        self.verify_button = tk.Button(self.root, text = "Verify certificate", command = self.verify)
        self.verify_button.place(x = 130, y = 145)
        self.generate_issuing_keyset_button = tk.Button(self.root, text = "Generate a new Keyset", command = self._generate_issuing_keys_file)
        self.generate_issuing_keyset_button.place(x = 260, y = 145)

    # Generates a Certificate file. It calls the builder defined in the Certificate class
    def generate(self):
        if(self.tls_version.get() == "TLS 1.2"):
            cert.Certificate(self.organization_name.get(), self.organization_country.get(), self.organization_location.get(), self.organization_domain.get(), self.tls_version.get(), ISSUING_KEYSET)
        elif(self.tls_version.get() == "TLS 1.3"):
             cert.Certificate(self.organization_name.get(), self.organization_country.get(), self.organization_location.get(), self.organization_domain.get(), self.tls_version.get(), ISSUING_KEYSET)
    # Verifies a Certificate file. It calls the function verify defined in the Certificate class
    def verify(self):
        # Select the certificate file and open it in read mode
        filename = askopenfilename()
        file = open(filename, "r")
        cert_content = file.readlines()
        file.close()

        verified = cert.Certificate.verify(cert_content, ISSUING_KEYSET.publicKey, tls_version = self.tls_version.get()) if (self.tls_version.get() == "TLS 1.3") else cert.Certificate.verify(cert_content, ISSUING_KEYSET.n, tls_version = self.tls_version.get())

        if(verified):
            tk.messagebox.showinfo(title = "Verification", message = "The Certificate is correct and valid")

        else:
            tk.messagebox.showerror(title = "Verification", message = "The Certificate is not correct")
            
    # Private function which generates a Keyset file
    # Parameters:
    # tls_version -> TLS Version to use
    def _generate_issuing_keys_file(self):
        global ISSUING_KEYSET
        keyset = None

        tls_version = self.tls_version.get()
        
        # If TLS version is TLS 1.2, it creates the file this way
        if(tls_version == "TLS 1.2"):
            keyset = rsa.RSA()
            text = "RSA\nExponente: " + str(keyset.e) + "\nModulo: " + str(keyset.n) + "\nClave privada: " + str(keyset.d)
            
        # If TLS version is TLS 1.2, it creates the file this way
        elif(tls_version == "TLS 1.3"):
           keyset = ecc.S256EC_keyset()
           text = "ECC\nClave publica: " + str(keyset.publicKey) + "\nClave privada: " + str(keyset.privateKey)

        ISSUING_KEYSET = keyset
        
        file = open(ISSUING_KEYS_FILENAME, "w")
        file.write(text)
        file.close()

    # Private function which reads a Keyset file
    # Arguments:
    # tls_version -> TLS Version to use
    def _read_issuing_keys_file(self):
        global ISSUING_KEYSET

        # Open and read the file
        file = open(ISSUING_KEYS_FILENAME, "r")
        keys_content = file.readlines()
        file.close()

        tls_version = "TLS 1.2" if keys_content[0].replace("\n", "") == "RSA" else "TLS 1.3"

        # If TLS version is TLS 1.2, it reads the file this way
        if(tls_version == "TLS 1.2"):
            # Exponent
            e = int(keys_content[1].replace("Exponente: ", "").replace("\n", ""))
            # Module
            n = int(keys_content[2].replace("Modulo: ", "").replace("\n", ""))
            # Private Key
            d = int(keys_content[3].replace("Clave privada: ", ""))

            # Assigning the value to the ISSUING_KEYSET global
            ISSUING_KEYSET = rsa.RSA(e = e, n = n, d = d, generate = False)

        # If TLS version is TLS 1.3, it reads the file this way
        elif(tls_version == "TLS 1.3"):
            # Public Key
            line = keys_content[1].replace("Clave publica: S256Point(", "").replace(")\n", "").split(", ")
            publicKey_x = int(line[0], 16)
            publicKey_y = int(line[1], 16)
            publicKey = ecc.S256Point(publicKey_x, publicKey_y)
            # Private Key
            privateKey = int(keys_content[2].replace("Clave privada: ", ""))

            # Assigning the value to the ISSUING_KEYSET global
            ISSUING_KEYSET = ecc.S256EC_keyset(publicKey = publicKey, privateKey = privateKey, generate = False)


root = tk.Tk()
app = App(root)
root.mainloop()
