# System utilities
import os
import sys
# Time utilities
import time
# Console writing
import pyfiglet
# RSA Encryption
import RSA
# ECC
import ecc
# Certificates
import Certificate
# Symmetric encryption with AES
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

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
        self.certificate = Certificate.Certificate("Server {}".format(self.device_id), "ES", "Almería", "server{}.com".format(self.device_id), "TLS 1.2", ISSUING_KEYSET)
        self.certificate_path = os.getcwd() + "/{}.txt".format(self.certificate.organization_domain)
        self.rsacipher = RSA.RSACipher(self.certificate.keyset)

    # It represents a Server
    # No arguments
    # It returns a String representation of the object
    def __repr__(self):
        return "Server(id={})".format(self.getId())

    # It prints the Server Certificate
    # No arguments
    # No returns
    def printCertificate(self):
        # Open and read the file
        file = open(self.certificate_path, "r")
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
    def rcvMessage(self, device_id, message, message_type):
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
            self.printCertificate()
            # Sending the certificate path
            message_to_send = self.certificate_path
            self.sendMessage(device_id, message_to_send, 1)

        # MESSAGE TYPE 2, STARTING THE REAL COMMUNICATION
        if(message_type == 2):
            # It prints a separation
            Device._printSeparation()
            time.sleep(5)
            # Printing the encrypted AES key
            print("AES KEY RECIEVED ENCRYPTED= {}".format(message))
            # Decrypting the key and parsing it to bytes
            aes_key = self.rsacipher.decrypt(message)
            aes_key = aes_key.to_bytes(16, sys.byteorder)
            # Adding the new session
            self.sessions.append(Session(self.device_id, device_id, message))
            print("AES KEY= {}".format(aes_key))
            # Message to send
            message_to_encrypt = b"Yo soy tu padre"
            print("MESSAGE TO SEND: {}".format(message_to_encrypt.decode("utf-8")))
            # AES Cipher
            aes_cipher = AES.new(aes_key, AES.MODE_EAX)
            ciphertext, tag = aes_cipher.encrypt_and_digest(message_to_encrypt)
            # Message to send
            message_to_send = aes_cipher.nonce + tag + ciphertext
            # Sending the message
            self.sendMessage(device_id, message_to_send, 3)
            
        return 0
            
# It represents a Client
class Client(Device):
    # Builder
    # No arguments
    # No return
    def __init__(self):
        super().__init__()

    # It represents a Client
    # No arguments
    # It returns a String representation of the object
    def __repr__(self):
        return "Client(id={})".format(self.getId())

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
            message_to_send = "{} hello, I want to connect to server {}".format(self, selected_server)
            print(message_to_send)
            # Finally sending the message
            return selected_server.rcvMessage(self.getId(), message_to_send, 0)

        # MESSAGE TYPE 2, GENERATION OF THE AES KEY
        if(message_type == 2):
            # Sending the message
            return selected_server.rcvMessage(self.getId(), message, 2)

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
                if("TLS version" in line):
                    tls_version = line.replace("TLS version: ", "").replace("\n", "")

                if("Módulo: " in line):
                    n = int(line.replace("Módulo: 0x", "").replace("\n", ""), 16)
                    break

            # Checking the validation of the certificate
            verified = Certificate.Certificate.verify(cert_content, TRUSTED_KEY, tls_version)

            # If it is verified, the following message is sent
            if(verified):
                # It prints a separation
                Device._printSeparation()
                # Waiting 5s
                time.sleep(5)
                # Confirming that the communication is available
                print("Communication available")
                # Generating a 16 bytes length AES key
                aes_key = get_random_bytes(16)
                # Printing the AES key in bytes
                print("AES KEY= {}".format(aes_key))
                # Adding it to the session list of the client
                self.sessions.append(Session(device_id, self.device_id, aes_key))
                # Encrypting the key
                # First we have to parse it from bytes to int
                aes_key = int.from_bytes(aes_key, sys.byteorder)
                aes_key_encrypted = RSA.RSACipher.encrypt(aes_key, n)
                print("AES KEY ENCRYPTED= {}".format(aes_key_encrypted))
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
            aescipher = AES.new(session_key, AES.MODE_EAX, nonce)

            # Decoding, decrypting and verifying
            decrypted_verified_text = aescipher.decrypt_and_verify(ciphertext, tag)
            decoded_decrypted_verified_text = decrypted_verified_text.decode("utf-8")
            Device._printSeparation()
            time.sleep(5)
            print("The client received a message: {}".format(decoded_decrypted_verified_text))

        return 0

# It represents a Session between a Server and a Client
class Session:
    # Builder
    # Arguments:
    # id_server -> device_id of the server
    # id_client -> device_id of the client
    # aes_key -> The generated AES key of the client
    # No return
    def __init__(self, id_server, id_client, aes_key):
        self.id_server = id_server
        self.id_client = id_client
        self.session_key = aes_key

    # It returns the session_key attribute
    # No arguments
    # It returns  the session_key
    def getKey(self):
        return self.session_key

# Private function which reads a Keyset file
# No Arguments:
# It returns 0 if succeded
def read_issuing_keys_file():
    global ISSUING_KEYSET, TRUSTED_KEY

    # Open and read the file
    try:
        file = open(KEY_FILE, "r")
        keys_content = file.readlines()
        file.close()
    except:
        return -1
    
    tls_version = "TLS 1.2" if keys_content[0].replace("\n", "") == "RSA" else "TLS 1.3"

    # If TLS version is TLS 1.2, it reads the file this way
    if(tls_version == "TLS 1.2"):
        # Exponent
        e = int(keys_content[1].replace("Exponente: ", "").replace("\n", ""))
        # Module
        n = int(keys_content[2].replace("Módulo: ", "").replace("\n", ""))
        # Assigning the value to the TRUSTED_KEY global
        TRUSTED_KEY = n
        # Private Key
        d = int(keys_content[3].replace("Clave privada: ", ""))

        # Assigning the value to the ISSUING_KEYSET global
        ISSUING_KEYSET = RSA.RSA(e = e, n = n, d = d, generate = False)

    # If TLS version is TLS 1.3, it reads the file this way
    elif(tls_version == "TLS 1.3"):
        # Public Key
        line = keys_content[1].replace("Clave pública: S256Point(", "").replace(")\n", "").split(", ")
        public_key_x = int(line[0], 16)
        public_key_y = int(line[1], 16)
        public_key = ecc.S256Point(public_key_x, public_key_y)
        # Assigning the value to the TRUSTED_KEY global
        TRUSTED_KEY = public_key
        # Private Key
        private_key = int(keys_content[2].replace("Clave privada: ", ""))

        # Assigning the value to the ISSUING_KEYSET global
        ISSUING_KEYSET = ecc.S256EC_keyset(publicKey = public_key, privateKey = private_key, generate = False)

    return 0


# Printing the title
title = pyfiglet.figlet_format("TLS SIM by JL")
print(title)

# Key file location
KEY_FILE = os.getcwd() + "/KEYS/issuing_keys.txt"
# [GLOBAL] The trusted keyset is the keyset defined by the issuing certificate company
ISSUING_KEYSET = None
# [GLOBAL] The trusted key is the public key defined by the issuing certificate company
TRUSTED_KEY = None
# Reading the key file to get the keyset
print("Readind the Issuing key file...")
if(read_issuing_keys_file() == -1):
    print("Something went wrong... check if the file is correctly created and try it again.")
    exit(-1)
else:
    print("Ready to go.\n\n")

# [GLOBAL] Servers list
SERVERS = [Server(), Server(), Server(), Server()]
print("Servers available={}".format(SERVERS))
# [GLOBAL] Clients list
CLIENTS = [Client(), Client(), Client(), Client(), Client(), Client(), Client()]
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
