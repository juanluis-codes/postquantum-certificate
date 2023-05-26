# System utilities
import os
import sys
# Time utilities
import time
# Console writing
import pyfiglet
# RSA Encryption
import RSA as rsa
# ECC
import hashlib as h
import ECC as ecc
import ctypes
from ctypes import *
# Certificates
import Certificate
# Symmetric encryption with AES
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

ISSUING_KEYSET_RSA = None
ISSUING_KEYSET_ECC = None
ISSUING_KEYSET_CRYSTALS = None
ISSUING_RSA_PUBLIC_KEY_FILENAME = os.getcwd() + "/KEYS/issuing_public_key_rsa.pub"
ISSUING_RSA_PRIVATE_KEY_FILENAME = os.getcwd() + "/KEYS/issuing_private_key_rsa"
ISSUING_ECC_PUBLIC_KEY_FILENAME = os.getcwd() + "/KEYS/issuing_public_key_ecc.pub"
ISSUING_ECC_PRIVATE_KEY_FILENAME = os.getcwd() + "/KEYS/issuing_private_key_ecc"
ISSUING_CRYSTALS_PUBLIC_KEY_FILENAME = os.getcwd() + "/KEYS/issuing_public_key_crystals.pub"
ISSUING_CRYSTALS_PRIVATE_KEY_FILENAME = os.getcwd() + "/KEYS/issuing_private_key_crystals"

# It represents a Device
class Device:
    # Class variable. Number of total Devices
    DEVICES = 0

    # Builder
    # No arguments
    # No return
    def __init__(self):
        # DEVICES defines the device_id. Unique identifier
        self.device_id = Device.DEVICES
        self.sessions = []
        Device.DEVICES = Device.DEVICES + 1

    # It represents a generic Device.
    # No arguments
    # It returns a String representation of the object
    def __repr__(self):
        return "I am the Device number {}".format(self.getId())

    # It returns the device_id attribute
    # No arguments
    # It returns  the device_id of the selected Device
    def getId(self):
        return self.device_id

    # It prints a line of - in order to separate different messages
    # No arguments
    # Returns 0 if succeded
    def _printSeparation():
        print("------------------------------------------------")
        return 0

    # It defines a generic method to send a message
    # Arguments:
    # device_id -> device_id of the receiver
    # message -> Message to be sent
    # message_type -> Type of the message which is going to be sent
    # No return
    def sendMessage(self, device_id, message, message_type):
        pass

    # It defines a generic method to receive a message
    # Arguments:
    # device_id -> device_id of the snder
    # message -> Message to be processed
    # message_type -> Type of the message which was sent
    # No return
    def rcvMessage(self, device_id, message, message_type):
        pass

# It represents a Server
class Server(Device):
    # Builder
    # No arguments
    # No return
    def __init__(self):
        super().__init__()
        self.certificate_rsa = Certificate.Certificate("Server {}".format(self.device_id), "ES", "Almería", "server{}.com".format(self.device_id), "TLS 1.2")
        self.certificate_path_rsa = os.getcwd() + "/{}-rsa.txt".format(self.certificate_rsa.organization_domain)
        self.certificate_ecc = Certificate.Certificate("Server {}".format(self.device_id), "ES", "Almería", "server{}.com".format(self.device_id), "TLS 1.3")
        self.certificate_path_ecc = os.getcwd() + "/{}-ecc.txt".format(self.certificate_ecc.organization_domain)
        self.certificate_crystals = Certificate.Certificate("Server {}".format(self.device_id), "ES", "Almería", "server{}.com".format(self.device_id), "TLS 1.5")
        self.certificate_path_crystals = os.getcwd() + "/{}-crystals.txt".format(self.certificate_crystals.organization_domain)
        self.certificate_dilithium = Certificate.Certificate("Server {}".format(self.device_id), "ES", "Almería", "server{}.com".format(self.device_id), "TLS 2.0")
        self.certificate_path_dilithium = os.getcwd() + "/{}-dilithium.txt".format(self.certificate_dilithium.organization_domain)
        self.rsacipher = rsa.RSACipher(self.certificate_rsa.keyset)
        self.ecccipher = ecc.S256Keyset(self.certificate_ecc.keyset.getPublicKey(), self.certificate_ecc.keyset.getPrivateKey(), False)
        self.certificate_rsa.generateFile(ISSUING_KEYSET_RSA)
        self.certificate_ecc.generateFile(ISSUING_KEYSET_ECC)
        self.certificate_crystals.generateFile(ISSUING_KEYSET_CRYSTALS)
        self.certificate_dilithium.generateFile(None)

    # It represents a Server
    # No arguments
    # It returns a String representation of the object
    def __repr__(self):
        return "Server(id={})".format(self.getId())

    # It prints the Server Certificate
    # No arguments
    # No returns
    def printCertificate(self, tls_version):
        # Open and read the file
        filename = ""
        if(tls_version == "TLS 1.2"):
            filename = self.certificate_path_rsa
        elif(tls_version == "TLS 1.3"):
            filename = self.certificate_path_ecc
        elif(tls_version == "TLS 1.5"):
            filename = self.certificate_path_crystals
        else:
            filename = self.certificate_path_dilithium
        file = open(filename, "r")
        certificate_text = file.readlines()
        file.close()

        for line in certificate_text:
            print(line)

    # It defines a generic method to send a message
    # Arguments:
    # device_id -> device_id of the receiver
    # message -> Message to be sent
    # message_type -> Type of the message which is going to be sent
    # # It returns 0 if succeded
    def sendMessage(self, device_id, message, message_type):
        selected_client = None

        # Searching for the client
        for client in CLIENTS:
            if(client.getId() == device_id):
                selected_client = client

        # MESSAGE TYPE 1, SENDING THE CERTIFICATE
        if(message_type == 1):
            return selected_client.rcvMessage(self.getId(), message, 1)

        # MESSAGE TYPE 3, SENDING A ENCRYPTED MESSAGE
        if(message_type == 3):
            return selected_client.rcvMessage(self.getId(), message, 3)

    # It defines a generic method to receive a message
    # Arguments:
    # device_id -> device_id of the snder
    # message -> Message to be processed
    # message_type -> Type of the message which was sent
    # It returns 0 if succeded
    def rcvMessage(self, device_id, message, message_type, tls_version):
        # MESSAGE TYPE 0, ANSWER TO THE CLIENT HELLO
        if(message_type == 0):
            # It prints a separation
            Device._printSeparation()
            # Waiting 5s
            time.sleep(5)
            # Printing the answer to ensure the message was received
            message_to_print = "{}. Here it is my certificate.".format(self)
            print(message_to_print)
            # It prints a separation
            Device._printSeparation()
            # Waiting 5s
            time.sleep(5)
            # Printing the certificate
            self.printCertificate(tls_version)
            # Sending the certificate path
            message_to_send = ""
            if(tls_version == "TLS 1.2"):
                message_to_send = self.certificate_path_rsa
            elif(tls_version == "TLS 1.3"):
                message_to_send = self.certificate_path_ecc
            elif(tls_version == "TLS 1.5"):
                message_to_send = self.certificate_path_crystals
            else:
                message_to_send = self.certificate_path_dilithium

            self.sendMessage(device_id, message_to_send, 1)

        # MESSAGE TYPE 2, STARTING THE REAL COMMUNICATION
        if(message_type == 2):
            # It prints a separation
            Device._printSeparation()
            time.sleep(5)
            # Printing the encrypted AES key
            print("{}. AES KEY RECIEVED ENCRYPTED= {}".format(self, message))
            # Decrypting the key and parsing it to bytes
            if(tls_version == "TLS 1.2"):
                aes_key = rsa.RSACipher.decrypt(message, self.rsacipher.getRSAKeysetD(), self.rsacipher.getRSAKeysetN())
            elif(tls_version == "TLS 1.3"):
                message = message.split(" ")
                kG = ecc.S256Point(int(message[0].replace("S256Point(", "").replace(",", ""), 16), int(message[1].replace(")", ""), 16))
                q = ecc.S256Point(int(message[2].replace("S256Point(", "").replace(",", ""), 16), int(message[3].replace(")", ""), 16))
                message_decrypted = ecc.S256Point.decrypt(kG, q, self.ecccipher.getPrivateKey())
                aes_key = h.sha256()
                aes_key.update(str(message_decrypted).encode('utf-8'))
                aes_key = int(aes_key.hexdigest(), 16)
            else:
                decrypt_crystals_c = CDLL("SO/decrypt_crystals.so")
                decrypt_crystals_c.decrypt.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8)]
                decrypt_crystals_c.restype = None

                file = open("KEYS/" + "{}-crystals".format(self.certificate_crystals.organization_domain) if(tls_version == "TLS 1.5") else "KEYS/" + "{}-dilithium".format(self.certificate_dilithium.organization_domain), "r")
                lines = file.readlines()
                file.close()

                secret_key_line = lines[1].replace("]", "").replace("[", "").split(",")
                for i in range(len(secret_key_line)):
                    secret_key_line[i] = int(secret_key_line[i])
                secret_key_array = (ctypes.c_uint8 * len(secret_key_line))(*secret_key_line)

                ciphertext_line = message.split(",")
                for i in range(len(ciphertext_line)):
                    ciphertext_line[i] = int(ciphertext_line[i])
                ciphertext_array = (ctypes.c_uint8 * len(ciphertext_line))(*ciphertext_line)

                decrypt_crystals_c.decrypt(secret_key_array, ciphertext_array)
                file = open("help.txt", "r")
                line = file.readline()
                file.close()
                line = line.split(",")
                aes_line = []
                for i in range(len(line)):
                    aes_line.append(int(line[i]))
                aes_key = bytes(aes_line)
                aes_key = int.from_bytes(aes_key, byteorder=sys.byteorder)          
            aes_key = aes_key.to_bytes(32, sys.byteorder)
            # Adding the new session
            self.sessions.append(Session(self.device_id, device_id, message, tls_version))
            print("{}. AES KEY= {}".format(self, aes_key))
            # Message to send
            message_to_encrypt = b"Yo soy tu padre"
            print("{}. MESSAGE TO SEND: {}".format(self, message_to_encrypt.decode("utf-8")))
            # AES Cipher
            aes_cipher = AES.new(aes_key, AES.MODE_EAX)
            ciphertext, tag = aes_cipher.encrypt_and_digest(message_to_encrypt)
            # Message to send
            message_to_send = aes_cipher.nonce + tag + ciphertext
            # Sending the message
            print("{}. MESSAGE TO SEND ENCRYPTED: {}".format(self, message_to_send))
            self.sendMessage(device_id, message_to_send, 3)
            
        return 0
            
# It represents a Client
class Client(Device):
    # Builder
    # No arguments
    # No return
    def __init__(self, tls_version):
        super().__init__()
        self.max_tls_version_supported = tls_version

    # It represents a Client
    # No arguments
    # It returns a String representation of the object
    def __repr__(self):
        return "Client(id={})".format(self.getId())
    
    def getTLSVersion(self):
        return self.max_tls_version_supported

    # It defines a generic method to send a message
    # Arguments:
    # device_id -> device_id of the receiver
    # message -> Message to be sent
    # message_type -> Type of the message which is going to be sent
    # It returns 0 if succeded
    def sendMessage(self, device_id, message, message_type):
        selected_server = None

        # Searching for the server
        for server in SERVERS:
            if(server.getId() == device_id):
                selected_server = server
                break

        # MESSAGE TYPE 0, CLIENT HELLO
        if(message_type == 0):
            # It prints a separation
            Device._printSeparation()
            # Defining the message to send
            message_to_send = "{}. Client hello, I want to connect to server {} and I support the {} version".format(self, selected_server, self.max_tls_version_supported)
            print(message_to_send)
            # Finally sending the message
            return selected_server.rcvMessage(self.getId(), message_to_send, 0, self.max_tls_version_supported)

        # MESSAGE TYPE 2, GENERATION OF THE AES KEY
        if(message_type == 2):
            # Sending the message
            return selected_server.rcvMessage(self.getId(), message, 2, self.max_tls_version_supported)

        return 0

    # It defines a generic method to receive a message
    # Arguments:
    # device_id -> device_id of the snder
    # message -> Message to be processed
    # message_type -> Type of the message which was sent
    # It returns 0 if succeded
    def rcvMessage(self, device_id, message, message_type):
        # MESSAGE TYPE 1, PROCESSING THE CERTIFICATE OF THE SERVER
        if(message_type == 1):
            try:
                file = open(message, "r")
                cert_content = file.readlines()
                file.close()
            except:
                return -1
            # Reading the TLS version and the module (public_key)
            for line in cert_content:
                if("Modulo: " in line):
                    n = int(line.replace(" Modulo: 0x", "").replace("\n", ""), 16)
                    break
                if("Exponente: " in line):
                    e = int(line.replace(" Exponente: ", "").replace("\n", ""))
                if("Clave publica" in line):
                    if(self.max_tls_version_supported == "TLS 1.3"):
                        splitted_line = line.replace("Clave publica: S256Point(", "").replace(")\n", "").split(",")
                        public_key = ecc.S256Point(int(splitted_line[0], 16), int(splitted_line[1], 16))
                        break
    
                    elif(self.max_tls_version_supported == "TLS 1.5" or self.max_tls_version_supported == "TLS 2.0"):
                        public_key = line.replace("Clave publica: [", "").replace("]\n", "").split(",")
                        break

            # Checking the validation of the certificate
            if(self.max_tls_version_supported == "TLS 1.2"):
                verified = Certificate.Certificate.verify(cert_content, "{},{}".format(ISSUING_KEYSET_RSA.getN(), ISSUING_KEYSET_RSA.getE()), self.max_tls_version_supported)
            elif(self.max_tls_version_supported == "TLS 1.3" or self.max_tls_version_supported == "TLS 1.5"):
                verified = Certificate.Certificate.verify(cert_content, ISSUING_KEYSET_ECC.getPublicKey() if (self.max_tls_version_supported == "TLS 1.3") else ISSUING_KEYSET_CRYSTALS.getPublicKey(), tls_version = self.max_tls_version_supported)
            else:
                verified = Certificate.Certificate.verify(cert_content, None, "TLS 2.0")

            # If it is verified, the following message is sent
            if(verified):
                # It prints a separation
                Device._printSeparation()
                # Waiting 5s
                time.sleep(5)
                # Confirming that the communication is available
                print("{}. Communication available".format(self))
                # Encrypting the key
                # First we have to parse it from bytes to int
                if(self.max_tls_version_supported == "TLS 1.2"):
                    # Generating a 32 bytes length AES key
                    aes_key = get_random_bytes(32)
                    aes_key = int.from_bytes(aes_key, sys.byteorder)
                    aes_key_encrypted = rsa.RSACipher.encrypt(aes_key, n, e)
                    aes_key = aes_key.to_bytes(32, sys.byteorder)
                    # Printing the AES key in bytes
                    print("{}. AES KEY= {}".format(self, aes_key))
                    print("{}. AES KEY ENCRYPTED= {}".format(self, aes_key_encrypted))
                elif(self.max_tls_version_supported == "TLS 1.3"):
                    aes_key = h.sha256()
                    aes_key_point = ecc.S256Point.generate_random_point()
                    aes_key.update(str(aes_key_point).encode("utf-8"))
                    aes_key = aes_key.hexdigest()
                    aes_key = int(aes_key, 16).to_bytes(32, sys.byteorder)
                    aes_key_encrypted = ecc.S256Point.encrypt(aes_key_point, public_key)
                    print("{}. AES KEY= {}".format(self, aes_key))
                    print("{}. AES KEY ENCRYPTED= {}".format(self, aes_key_encrypted))
                else:
                    # CDLL Library
                    encrypt_crystals_c = CDLL("SO/encrypt_crystals.so")
                    encrypt_crystals_c.encrypt.argtypes = [ctypes.POINTER(ctypes.c_uint8)]
                    encrypt_crystals_c.restype = None

                    # Defining the CRYSTALS public key
                    for i in range(len(public_key)):
                        public_key[i] = int(public_key[i])
                    public_key_array = (ctypes.c_uint8 * len(public_key))(*public_key)

                    # Encrypts the AES key (generated in the CDLL Library)
                    encrypt_crystals_c.encrypt(public_key_array)
                    file = open("help.txt","r")
                    lines = file.readlines()
                    file.close()
                    line0 = lines[0].replace("\n", "").split(",")
                    aes_key_encrypted = str(lines[1])
                    for i in range(len(line0)):
                        line0[i] = int(line0[i])

                    aes_key = bytes(line0)
                    print("{}. AES KEY= {}".format(self, aes_key))
                    print("{}. AES KEY ENCRYPTED= {}".format(self, aes_key_encrypted))

                # Adding it to the session list of the client
                self.sessions.append(Session(device_id, self.device_id, int.from_bytes(aes_key, sys.byteorder), self.max_tls_version_supported))
                # Sending the key
                self.sendMessage(device_id, aes_key_encrypted, 2)
                # It prints a separation
                Device._printSeparation()

            else:
                return -1

        # MESSAGE TYPE 3, PROCESSING A NORMAL MESSAGE IN THE SESSION
        if(message_type == 3):
            # Getting the key of the session
            for session in self.sessions:
                if(session.id_server == device_id and session.id_server == device_id):
                    session_key = session.getKey()
            # Getting the nonce
            nonce = message[:AES.block_size]
            # Getting the tag
            tag = message[AES.block_size:AES.block_size * 2]
            # Getting the encypted text
            ciphertext = message[AES.block_size * 2:]

            # Creating the cipher again
            aescipher = AES.new(session_key.to_bytes(32, sys.byteorder), AES.MODE_EAX, nonce)

            # Decoding, decrypting and verifying
            decrypted_verified_text = aescipher.decrypt_and_verify(ciphertext, tag)
            decoded_decrypted_verified_text = decrypted_verified_text.decode("utf-8")
            Device._printSeparation()
            time.sleep(5)
            print("{}. The client received a message encrypted: {}".format(self, message))
            print("{}. The client received a message: {}".format(self, decoded_decrypted_verified_text))

        return 0

# It represents a Session between a Server and a Client
class Session:
    # Builder
    # Arguments:
    # id_server -> device_id of the server
    # id_client -> device_id of the client
    # aes_key -> The generated AES key of the client
    # No return
    def __init__(self, id_server, id_client, aes_key, tls_version):
        self.id_server = id_server
        self.id_client = id_client
        self.session_key = aes_key
        self.tls_version = tls_version

    # It returns the session_key attribute
    # No arguments
    # It returns  the session_key
    def getKey(self):
        return self.session_key

# This method reads a keyset file
# Return: (int) It returns 0 if succeded, -1 if not
def _read_issuing_keys_file():
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
    n = int(rsa_public_key_content[2].replace("Modulo: 0x", "").replace("\n", ""), 16)
    # Private Key
    d = int(rsa_private_key_content[1].replace("0x", ""), 16)

    # Assigning the value to the ISSUING_KEYSET_RSA global
    ISSUING_KEYSET_RSA = rsa.RSAKeyset(e = e, n = n, d = d, generate = False)

    # READ ECC KEYS
    # Public Key
    ecc_public_key_line = ecc_public_key_content[1].replace("S256Point(", "").replace(")", "").split(", ")
    ecc_public_key_x = int(ecc_public_key_line[0].replace("0x", ""), 16)
    ecc_public_key_y = int(ecc_public_key_line[1].replace("0x", ""), 16)
    ecc_public_key = ecc.S256Point(ecc_public_key_x, ecc_public_key_y)
    # Private Key
    ecc_private_key = int(ecc_private_key_content[1].replace("0x", ""), 16)

    # Assigning the value to the ISSUING_KEYSET_ECC global
    ISSUING_KEYSET_ECC = ecc.S256Keyset(public_key = ecc_public_key, private_key = ecc_private_key, generate = False)

    # READ CRYSTALS KEYS
    # Public Key
    crystals_public_key_line = crystals_public_key_content[1].replace("S256Point(", "").replace(")", "").split(", ")
    crystals_public_key_x = int(crystals_public_key_line[0].replace("0x", ""), 16)
    crystals_public_key_y = int(crystals_public_key_line[1].replace("0x", ""), 16)
    crystals_public_key = ecc.S256Point(crystals_public_key_x, crystals_public_key_y)
    # Private Key
    crystals_private_key = int(crystals_private_key_content[1].replace("0x", ""), 16)

    # Assigning the value to the ISSUING_KEYSET_CRYSTALS global
    ISSUING_KEYSET_CRYSTALS = ecc.S256Keyset(public_key = crystals_public_key, private_key = crystals_private_key, generate = False)

    return 0

# Printing the title
title = pyfiglet.figlet_format("TLS SIM by JL")
print(title)

# Reading the key file to get the keyset
print("Reading the issuing key file...")
if(_read_issuing_keys_file() == -1):
    print("Something went wrong... check if the file is correctly created and try it again.")
    exit(-1)
else:
    print("Ready to go.\n\n")

# [GLOBAL] Servers list
SERVERS = [Server(), Server(), Server(), Server()]
print("Servers available={}".format(SERVERS))
# [GLOBAL] Clients list
CLIENTS = [Client("TLS 1.2"), Client("TLS 1.3"), Client("TLS 1.5"), Client("TLS 1.2"), Client("TLS 2.0"), Client("TLS 1.5"), Client("TLS 2.0")]
print("Your Clients={}\n\n".format(CLIENTS))

# Inputs
selected_client = int(input("Client id="))
selected_server = int(input("Server id="))
client_validation = False
server_validation = False

# Searching for the client
for client in CLIENTS:
    if(selected_client == client.getId()):
        selected_client = client
        client_validation = True
        break

# Searching for the client
for server in SERVERS:
    if(selected_server == server.getId()):
        server_validation = True
        break

# Validating the input
if(not(client_validation)):
    print("The selected client does not exist")
    exit(-1)

if(not(server_validation)):
    print("The selected server does not exist")
    exit(-1)

# Simulation
selected_client.sendMessage(selected_server, "", 0)
