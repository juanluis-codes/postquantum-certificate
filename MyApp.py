# IMPORTS
import tkinter as tk
from tkinter import *
import tkinter.ttk as ttk
from tkinter.ttk import *
from tkinter.filedialog import askopenfilename
import hashlib as h
import os
from ctypes import *
# LOCAL IMPORTS
import Certificate as cert
import RSA as rsa
import ecc

# GLOBALS
ISSUING_KEYSET_RSA = None
ISSUING_KEYSET_ECC = None
ISSUING_KEYSET_CRYSTALS = None
ISSUING_RSA_PUBLIC_KEY_FILENAME = os.getcwd() + "/KEYS/issuing_public_key_rsa.pub"
ISSUING_RSA_PRIVATE_KEY_FILENAME = os.getcwd() + "/KEYS/issuing_private_key_rsa"
ISSUING_ECC_PUBLIC_KEY_FILENAME = os.getcwd() + "/KEYS/issuing_public_key_ecc.pub"
ISSUING_ECC_PRIVATE_KEY_FILENAME = os.getcwd() + "/KEYS/issuing_private_key_ecc"
ISSUING_CRYSTALS_PUBLIC_KEY_FILENAME = os.getcwd() + "/KEYS/issuing_public_key_crystals.pub"
ISSUING_CRYSTALS_PRIVATE_KEY_FILENAME = os.getcwd() + "/KEYS/issuing_private_key_crystals"
SOFT_BLUE = "#4470b8"
DARK_BLUE = "#1e2970"
WHITE = "#FFFFFF"

# This class defines the application
# Attributes:
# root -> (Tk) UI Window
# organization_name -> (StringVar) String variable for the entry_name
# organization_country -> (StringVar) String variable for the entry_country
# organization_location -> (StringVar) String variable for the entry_location
# organization_domain -> (StringVar) String variable for the entry_domain
# tls_version -> (StringVar) String variable for the tls_menu
# tls_versions -> (List) List which contains the TLS versions supported
# label_name -> (Label) Label name
# entry_name -> (Entry) Entry to insert the organization name
# label_country -> (Label) Label country
# entry_country -> (Entry) Entry to insert the organization country
# label_location -> (Label) Label location
# entry_location -> (Entry) Entry to insert the organization location
# label_domain -> (Label) Label domain
# entry_domain -> (Entry) Entry to insert the organization domain
# tls_menu -> (Combobox) Combobox to choose the TLS version
# generate_button -> (Button) This button has the function to generate a new certificate
# verify_button -> (Button) This button has the function to verify a certificate
# generate_issuing_keyset_button -> (Button) This button has the function to generate a new issuing keyset to sign the certificates
class App:
    # Builder
    def __init__(self, root):
        self.root = root
        self.root.geometry("500x190")
        self.root.resizable(0, 0)
        self.root.title("Certificates Certlu")
        self.root.configure(bg = DARK_BLUE)

        # Call to place_items() and textvariables needed
        self.organization_name = StringVar()
        self.organization_country = StringVar()
        self.organization_location = StringVar()
        self.organization_domain = StringVar()
        self.tls_version = StringVar()
        self.tls_versions = ["TLS 1.2", "TLS 1.3", "TLS 1.5", "TLS 2.0"]
        self.tls_version.set(self.tls_versions[0])
        self.place_items()

        # Read the Keys File
        if(self._read_issuing_keys_file() == -1):
            self._generate_issuing_keys_file()

    # This method places the items in the root window
    # Return: (void)
    def place_items(self):
        # Name label and entry
        self.label_name = tk.Label(self.root, text = "Organización: ", bg = DARK_BLUE, fg = WHITE)
        self.label_name.place(x = 10, y = 10)
        self.entry_name = tk.Entry(self.root, textvariable = self.organization_name)
        self.entry_name.place(x = 110, y = 10)
        # Country label and entry
        self.label_country = tk.Label(self.root, text = "País: ", bg = DARK_BLUE, fg = WHITE)
        self.label_country.place(x = 10, y = 35)
        self.entry_country = tk.Entry(self.root, textvariable = self.organization_country)
        self.entry_country.place(x = 110, y = 35)
        # Location label and entry
        self.label_location = tk.Label(self.root, text = "Localidad: ", bg = DARK_BLUE, fg = WHITE)
        self.label_location.place(x = 10, y = 60)
        self.entry_location = tk.Entry(self.root, textvariable = self.organization_location)
        self.entry_location.place(x = 110, y = 60)
        # Domain label and entry
        self.label_domain = tk.Label(self.root, text = "Dominio: ", bg = DARK_BLUE, fg = WHITE)
        self.label_domain.place(x = 10, y = 85)
        self.entry_domain = tk.Entry(self.root, textvariable = self.organization_domain)
        self.entry_domain.place(x = 110, y = 85)

        # Choosing between TLS versions
        self.tls_menu = ttk.Combobox(self.root, textvariable = self.tls_version, values = self.tls_versions)
        self.tls_menu.place(x = 10, y = 120)

        # Buttons
        self.generate_button = tk.Button(self.root, text = "Generate certificate", command = self.generate, cursor="hand1", bg = SOFT_BLUE, fg = WHITE)
        self.generate_button.place(x = 10, y = 150)
        self.verify_button = tk.Button(self.root, text = "Verify certificate", command = self.verify, cursor="hand1", bg = SOFT_BLUE, fg = WHITE)
        self.verify_button.place(x = 170, y = 150)
        self.generate_issuing_keyset_button = tk.Button(self.root, text = "Generate a new Keyset", command = self._generate_issuing_keys_file, cursor="hand1", bg = SOFT_BLUE, fg = WHITE)
        self.generate_issuing_keyset_button.place(x = 310, y = 150)

    # This method generates a certificate file. It calls the builder defined in the Certificate class
    # Return: (void)
    def generate(self):
        if(self.tls_version.get() == "TLS 1.2"):
            cert.Certificate(self.organization_name.get(), self.organization_country.get(), self.organization_location.get(), self.organization_domain.get(), self.tls_version.get(), ISSUING_KEYSET_RSA)
        elif(self.tls_version.get() == "TLS 1.3" or self.tls_version.get() == "TLS 1.5"):
            cert.Certificate(self.organization_name.get(), self.organization_country.get(), self.organization_location.get(), self.organization_domain.get(), self.tls_version.get(), ISSUING_KEYSET_ECC if (self.tls_version.get() == "TLS 1.3") else ISSUING_KEYSET_CRYSTALS)
        elif(self.tls_version.get() == "TLS 2.0"):
            cert.Certificate(self.organization_name.get(), self.organization_country.get(), self.organization_location.get(), self.organization_domain.get(), self.tls_version.get(), None)
    
    # This method verifies a certificate file. It calls the function verify defined in the Certificate class
    # Return: (void)
    def verify(self):
        # Select the certificate file and open it in read mode
        filename = askopenfilename()
        file = open(filename, "r")
        cert_content = file.readlines()
        file.close()
        if(self.tls_version.get() == "TLS 1.2"):
            verified = cert.Certificate.verify(cert_content, "{},{}".format(ISSUING_KEYSET_RSA.getN(), ISSUING_KEYSET_RSA.getE()), tls_version = self.tls_version.get())

        elif(self.tls_version.get() == "TLS 1.3" or self.tls_version.get() == "TLS 1.5"):
            verified = cert.Certificate.verify(cert_content, ISSUING_KEYSET_ECC.getPublicKey() if (self.tls_version.get() == "TLS 1.3") else ISSUING_KEYSET_CRYSTALS.getPublicKey(), tls_version = self.tls_version.get())
        
        elif(self.tls_version.get() == "TLS 2.0"):
            verified = cert.Certificate.verify(cert_content, None, "TLS 2.0")

        if(verified):
            tk.messagebox.showinfo(title = "Verification", message = "The Certificate is correct and valid")

        else:
            tk.messagebox.showerror(title = "Verification", message = "The Certificate is not correct")
            
    # This method generates a keyset file
    # Return: (int) It returns 0 if succeded, -1 if not
    def _generate_issuing_keys_file(self):
        global ISSUING_KEYSET_RSA, ISSUING_KEYSET_ECC, ISSUING_KEYSET_CRYSTALS

        # The keyset value will be used to store the keyset
        rsa_keyset = None
        ecc_keyset = None
        crystals_keyset = None

        # If the TLS version is TLS 1.2, it creates the file this way
        # Generating the RSA keyset and formatting it as a text
        rsa_keyset = rsa.RSAKeyset()
        public_key_text = "RSA\nExponente: " + str(rsa_keyset.e) + "\nModulo: " + str(rsa_keyset.getN())
        private_key_text = "RSA\n" + str(rsa_keyset.getD())

        # Writing the RSA keys into their respective file
        try:
            public_key_file = open(ISSUING_RSA_PUBLIC_KEY_FILENAME, "w")
            public_key_file.write(public_key_text)
            public_key_file.close()
        except IOError:
            return -1

        try:
            private_key_file = open(ISSUING_RSA_PRIVATE_KEY_FILENAME, "w")
            private_key_file.write(private_key_text)
            private_key_file.close()
        except IOError:
            return -1
            
        # If the TLS version is TLS 1.3, it creates the file this way
        # Generating the ECC keyset and formatting it as a text
        ecc_keyset = ecc.S256Keyset()
        public_key_text = "ECC\n" + str(ecc_keyset.getPublicKey())
        private_key_text = "ECC\n" + str(ecc_keyset.getPrivateKey())

        # Writing the ECC keys into their respective file
        try:
            public_key_file = open(ISSUING_ECC_PUBLIC_KEY_FILENAME, "w")
            public_key_file.write(public_key_text)
            public_key_file.close()
        except IOError:
            return -1

        try:
            private_key_file = open(ISSUING_ECC_PRIVATE_KEY_FILENAME, "w")
            private_key_file.write(private_key_text)
            private_key_file.close()
        except IOError:
            return -1
        
        # If the TLS version is TLS 1.5, it creates the file this way
        # Generating the ECC keyset and formatting it as a text. The encryption type is CRYSTALS, but the signing type is ECC
        crystals_keyset = ecc.S256Keyset()
        public_key_text = "ECC\n" + str(crystals_keyset.getPublicKey())
        private_key_text = "ECC\n" + str(crystals_keyset.getPrivateKey())

        # Writing the ECC keys into their respective file.
        try:
            public_key_file = open(ISSUING_CRYSTALS_PUBLIC_KEY_FILENAME, "w")
            public_key_file.write(public_key_text)
            public_key_file.close()
        except IOError:
            return -1
            
        try:
            private_key_file = open(ISSUING_CRYSTALS_PRIVATE_KEY_FILENAME, "w")
            private_key_file.write(private_key_text)
            private_key_file.close()
        except IOError:
            return -1

        # If the TLS version is TLS 2.0, it creates the file this way
        # The generate_sign_keys_dilithium.so file is assigned to deal with the keys
        generate_sign_keys_kyber_c = CDLL('SO/generate_sign_keys_dilithium.so')

        if(generate_sign_keys_kyber_c.generate_keys() != 0):
            return -1

        ISSUING_KEYSET_RSA = rsa_keyset
        ISSUING_KEYSET_ECC = ecc_keyset
        ISSUING_KEYSET_CRYSTALS = crystals_keyset

        return 0

    # This method reads a keyset file
    # Return: (int) It returns 0 if succeded, -1 if not
    def _read_issuing_keys_file(self):
        global ISSUING_KEYSET_RSA, ISSUING_KEYSET_ECC, ISSUING_KEYSET_CRYSTALS

        # Open and read the rsa files
        try:
            public_key_rsa_file = open(ISSUING_RSA_PUBLIC_KEY_FILENAME, "r")
            rsa_public_key_content = public_key_rsa_file.readlines()
            public_key_rsa_file.close()
        except IOError:
            return -1
        
        try:
            private_key_rsa_file = open(ISSUING_RSA_PRIVATE_KEY_FILENAME, "r")
            rsa_private_key_content = private_key_rsa_file.readlines()
            private_key_rsa_file.close()
        except IOError:
            return -1
        
        # Open and read the ecc files
        try:
            public_key_ecc_file = open(ISSUING_ECC_PUBLIC_KEY_FILENAME, "r")
            ecc_public_key_content = public_key_ecc_file.readlines()
            public_key_ecc_file.close()
        except IOError:
            return -1
        
        try:
            private_key_ecc_file = open(ISSUING_ECC_PRIVATE_KEY_FILENAME, "r")
            ecc_private_key_content = private_key_ecc_file.readlines()
            private_key_ecc_file.close()
        except IOError:
            return -1
        
        # Open and read the ecc files
        try:    
            public_key_crystals_file = open(ISSUING_CRYSTALS_PUBLIC_KEY_FILENAME, "r")
            crystals_public_key_content = public_key_crystals_file.readlines()
            public_key_crystals_file.close()
        except IOError:
            return -1
        
        try:
            private_key_crystals_file = open(ISSUING_CRYSTALS_PRIVATE_KEY_FILENAME, "r")
            crystals_private_key_content = private_key_crystals_file.readlines()
            private_key_crystals_file.close()
        except IOError:
            return -1
        
        # READING RSA KEYS
        # Exponent
        e = int(rsa_public_key_content[1].replace("Exponente: ", "").replace("\n", ""))
        # Module
        n = int(rsa_public_key_content[2].replace("Modulo: ", "").replace("\n", ""))
        # Private Key
        d = int(rsa_private_key_content[1])

        # Assigning the value to the ISSUING_KEYSET_RSA global
        ISSUING_KEYSET_RSA = rsa.RSAKeyset(e = e, n = n, d = d, generate = False)

        # READ ECC KEYS
        # Public Key
        ecc_public_key_line = ecc_public_key_content[1].replace("S256Point(", "").replace(")", "").split(", ")
        ecc_public_key_x = int(ecc_public_key_line[0], 16)
        ecc_public_key_y = int(ecc_public_key_line[1], 16)
        ecc_public_key = ecc.S256Point(ecc_public_key_x, ecc_public_key_y)
        # Private Key
        ecc_private_key = int(ecc_private_key_content[1])

        # Assigning the value to the ISSUING_KEYSET_ECC global
        ISSUING_KEYSET_ECC = ecc.S256Keyset(public_key = ecc_public_key, private_key = ecc_private_key, generate = False)

        # READ CRYSTALS KEYS
        # Public Key
        crystals_public_key_line = crystals_public_key_content[1].replace("S256Point(", "").replace(")", "").split(", ")
        crystals_public_key_x = int(crystals_public_key_line[0], 16)
        crystals_public_key_y = int(crystals_public_key_line[1], 16)
        crystals_public_key = ecc.S256Point(crystals_public_key_x, crystals_public_key_y)
        # Private Key
        crystals_private_key = int(crystals_private_key_content[1])

        # Assigning the value to the ISSUING_KEYSET_CRYSTALS global
        ISSUING_KEYSET_CRYSTALS = ecc.S256Keyset(public_key = crystals_public_key, private_key = crystals_private_key, generate = False)

        return 0


root = tk.Tk()
app = App(root)
root.mainloop()
