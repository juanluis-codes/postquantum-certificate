# IMPORTS
import socket
import datetime as dt
import ctypes
from ctypes import *
import hashlib as h
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import random
import struct
import os
import sys
import netifaces
import threading
import json
import datetime
# LOCAL IMPORTS
import RSA as rsa
import ECC as ecc

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

# This method verifies a certificate file
# Parameters:
# public_key -> (int, S256Point) The issuing public key to verify the certificate
# tls_version -> (String) String for the TLS version of the certificate to verify
# Return: (boolean) It returns True if the certificate is valid and False if not
def verify(content, issuing_public_key, tls_version):
    # This will be the text from which we are going to obtain the hash
    text_to_hash_sha1 = ""
    text_to_hash_sha256 = ""

    # This will be the signature obtained from the file
    signature_to_verify = 0
    sha1_to_verify = 0
    sha256_to_verify = 0

    issuing_date = None
    expiration_date = None
    extracted_date = None
    valid_dates = True
    valid_certificate = True

    # Obtaining information from the certificate file
    for i in range(0, len(content) - 2):
        # Obtaining the signature
        if("Validez" in content[i]):
            extracted_date = content[i + 1].replace(" No antes: ", "").replace("\n", "").split("-")
            issuing_date = dt.datetime(int(extracted_date[0]), int(extracted_date[1]), int(extracted_date[2]))
            extracted_date = content[i + 2].replace(" No despues: ", "").replace("\n", "").split("-")
            expiration_date = dt.datetime(int(extracted_date[0]), int(extracted_date[1]), int(extracted_date[2]))

            if((issuing_date > dt.datetime.now()) or (expiration_date < dt.datetime.now())):
                valid_dates = False
                return valid_dates

        if("Modulo:" in content[i]):
            n = content[i].replace(" Modulo: ", "").replace("\n", "")
            text_to_hash_sha1 = text_to_hash_sha1 + content[i].replace(" ", "").replace("\n", "")
            continue

        if("Clave publica:" in content[i]):
            public_key = content[i].replace(" Clave publica: ", "").replace("\n", "")
            if(tls_version == "TLS 2.0"):
                public_key = public_key.replace("[", "").replace("]", "").split(",")
                
        if("Firma:" in content[i]):
            if(tls_version == "TLS 1.2"):
                signature_to_verify = int(content[i].replace("Firma: 0x", "").replace("\n", ""), 16)
                    
            elif(tls_version == "TLS 1.3" or tls_version == "TLS 1.5"):
                signature_to_verify = content[i].replace("Firma: (S256Point(", "").replace("0x", "").replace(")", "").replace(" ", "").replace("\n", "").split(",")

            elif(tls_version == "TLS 2.0"):
                signature_to_verify = content[i].replace("Firma: ", "").replace(" ", "").replace("\n", "").replace("]", "").replace("[", "").split(",")

            text_to_hash_sha1 = text_to_hash_sha1 + content[i].replace(" ", "").replace("\n", "")
            continue

        if("Longitud de la firma: " in content[i]):
            slen = int(content[i].replace("Longitud de la firma: ", "").replace("\n", ""))

        if("Huellas digitales" in content[i]):
            text_to_hash_sha1 = text_to_hash_sha1 + "Huellasdigitales"
            text_to_hash_sha256 = text_to_hash_sha1
            continue

        if("SHA-1:" in content[i]):
            sha1_to_verify = content[i].replace("SHA-1: 0x", "").replace("\n", "").replace(" ", "")
            text_to_hash_sha1 += "SHA-1:0x"
            text_to_hash_sha256 = text_to_hash_sha1 + content[i].replace(" SHA-1: 0x", "").replace("\n", "")
            continue

        if("SHA-256" in content[i]):
            sha256_to_verify = content[i].replace("SHA-256: 0x", "").replace("\n", "").replace(" ", "")
            text_to_hash_sha256 += "SHA-256:0x"
            continue

        text_to_hash_sha1 = text_to_hash_sha1 + content[i].replace(" ", "").replace("\n", "")

    if(tls_version == "TLS 2.0"):
        sign_dilithium_c = CDLL("SO/verify_dilithium.so")
        # Define the C function prototype
        sign_dilithium_c.puts.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t, ctypes.POINTER(ctypes.c_uint8)]
            
        dilithium_keys_file = open("KEYS/issuing_public_key_dilithium.pub")
        dilithium_keys_file_content = dilithium_keys_file.readlines()
        dilithium_keys_file.close()

        dilithium_public_key = dilithium_keys_file_content[1].replace("\n", "").replace("[", "").replace("]", "").split(",")
        dilithium_uint8_array = (ctypes.c_uint8 * len(dilithium_public_key))()
        for i in range(0, len(dilithium_public_key)):
            dilithium_uint8_array[i] = int(dilithium_public_key[i])

        signature_uint8_array = (ctypes.c_uint8 * len(signature_to_verify))()
        for i in range(0, len(signature_to_verify)):
            signature_uint8_array[i] = int(signature_to_verify[i])

        public_key_uint8_array = (ctypes.c_uint8 * len(public_key))()
        for i in range(0, len(public_key)):
            public_key_uint8_array[i] = int(public_key[i])

        # Call the C function with a string argument
        valid_certificate = True if(sign_dilithium_c.verify(signature_uint8_array, slen, dilithium_uint8_array, public_key_uint8_array) == 0) else False
    # Obtaining the hash of the key
    if(tls_version == "TLS 1.2"):
        hash_key = h.sha256()
        hash_key.update(n.encode('utf-8'))
        hash_key = int(hash_key.hexdigest().replace("0x", ""), 16)
    elif(tls_version == "TLS 1.3" or tls_version == "TLS 1.5"):
        hash_key = h.sha256()
        hash_key.update(public_key.encode('utf-8'))
        hash_key = int(hash_key.hexdigest().replace("0x", ""), 16)

    # Obtaining the first hash
    hash_first_text = h.sha1()
    hash_first_text.update(text_to_hash_sha1.encode("utf-8"))
    hash_first_text = hash_first_text.hexdigest()

    # Obtaining the second hash
    hash_second_text = h.sha256()
    hash_second_text.update(text_to_hash_sha256.encode("utf-8"))
    hash_second_text = hash_second_text.hexdigest()

    if(not(hash_first_text == sha1_to_verify)):
        valid_certificate = False
        return valid_certificate

    if(not(hash_second_text == sha256_to_verify)):
        valid_certificate = False
        return valid_certificate            
        
    # Obtaining the hash from the signature
    if(tls_version == "TLS 1.2"):
        issuing_public_key = issuing_public_key.split(",")
        start_key_hash = rsa.RSASignature.verify(signature_to_verify, int(issuing_public_key[0]), int(issuing_public_key[1]))
        valid_certificate = (hash_key == start_key_hash)
    elif(tls_version == "TLS 1.3" or tls_version == "TLS 1.5"):
        valid_certificate = ecc.S256Signature.verify(hash_key, issuing_public_key, ecc.S256Point(int(signature_to_verify[0], 16), int(signature_to_verify[1], 16)), int(signature_to_verify[2], 16))
        
    return valid_certificate

# This method reads a keyset file
# Return: (int) It returns 0 if succeded, -1 if not
def readIssuingKeysFile():
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

# This method ensures that the bytes that represents the filesize is being received
# Parameters:
# sck -> (Socket) The socket
# Return: (int) It returns the filesize
def receive_file_size(sck: socket.socket):
    fmt = "<Q"
    expected_bytes = struct.calcsize(fmt)
    received_bytes = 0
    stream = bytes()

    while received_bytes < expected_bytes:
        chunk = sck.recv(expected_bytes - received_bytes)
        stream += chunk
        received_bytes += len(chunk)

    filesize = struct.unpack(fmt, stream)[0]

    return filesize

# This method receives a file
# Parameters:
# sck -> (Socket) The socket
# filename -> (String) The name of the file
# Return: (int) It returns the filesize
def receive_file(sck: socket.socket, filename):
    # First read the size
    filesize = receive_file_size(sck)
    # Write in a new file
    with open(filename, "wb") as f:
        received_bytes = 0
        # Receive the file data in blocks of 1024
        while received_bytes < filesize:
            chunk = sck.recv(1024)

            if chunk:
                f.write(chunk)
                received_bytes += len(chunk)

# This method handles a client
# Parameters:
# conn -> (Socket) The socket
# address -> (List) The list contains the origin IP address and the port of the session
# ip -> (String) Own IP address
# Return: (void)
def handleClient(conn, address, ip):
    # IP address
    ip_addr = address[0]
    # Dictionary
    failed_data = {}
    failed_data["conexiones fallidas"] = []
    accepted_data = {}
    accepted_data["conexiones"] = []

    # Receiving the certificate
    receive_file(conn, "{}.txt".format(ip_addr))
    
    # Open and read the certificate received
    file = open("{}.txt".format(ip_addr), "r")
    cert_content = file.readlines()
    file.close()

    # TLS version used
    tls_version = cert_content[0].replace("TLS version: ", "").replace("\n", "")
    target_username = cert_content[len(cert_content) - 2].replace("\n", "")
    username = cert_content[len(cert_content) - 1]

    file = open("CONF/users.txt")
    user_access = file.readlines()
    file.close()
        
    # Reading the content
    for line in cert_content:
        if("Organizacion: " in line):
            name = line.replace(" Organizacion: ", "").replace("\n", "")
        if("Dominio: " in line):
            accepted_ip = line.replace("Dominio:", "").replace(" ", "").replace("\n", "")
        if("Exponente: " in line):
            exp = int(line.replace("Exponente: ", "").replace("\n", ""))
        if("Modulo: " in line):
            n = int(line.replace("Modulo: 0x", "").replace("\n", ""), 16)
            break
        if("Clave publica" in line):
            if(tls_version == "TLS 1.3"):
                splitted_line = line.replace("Clave publica: S256Point(", "").replace(")\n", "").split(",")
                public_key = ecc.S256Point(int(splitted_line[0], 16), int(splitted_line[1], 16))
        
            elif(tls_version == "TLS 1.5" or tls_version == "TLS 2.0"):
                public_key = line.replace("Clave publica: [", "").replace("]\n", "").split(",")
            break

    # If the IP address that is sending the certificate is not the IP address of the domain, then the connection is not accepted
    # CANCELLED CONNECTION
    if(ip_addr != accepted_ip and CHECK_IP):
        with socket.create_connection((ip_addr, 6191)) as conn:
            try:
                with open('LOG/failed.json') as file:
                    failed_data = json.load(file)
            except IOError:
                    failed_data = failed_data
            
            failed_data['conexiones fallidas'].append({
                'IP': ip_addr,
                'Dominio:': accepted_ip,
                'Nombre': name,
                'Fecha': str(datetime.datetime.now()),
                'Motivo': "Conectado desde otra IP no permitida en el certificado"})
            with open('LOG/failed.json', 'w') as file:
                json.dump(failed_data, file, indent=4)

            conn.send("false 1".encode())

        return
    
    verified_certificate = False
    # Verifying the certificate depending on the TLS version
    if(tls_version == "TLS 1.2"):
        verified_certificate = verify(cert_content, "{},{}".format(ISSUING_KEYSET_RSA.getN(), ISSUING_KEYSET_RSA.getE()), tls_version = tls_version)
    elif(tls_version == "TLS 1.3" or tls_version == "TLS 1.5"):
        verified_certificate = verify(cert_content, ISSUING_KEYSET_ECC.getPublicKey() if (tls_version == "TLS 1.3") else ISSUING_KEYSET_CRYSTALS.getPublicKey(), tls_version = tls_version)
    elif(tls_version == "TLS 2.0"):
        verified_certificate = verify(cert_content, None, "TLS 2.0")

    verified_user = False
    sender_user = ""
    possible_target_users = None
    if(verified_certificate):
        for line in user_access:
            sender_user = line.replace("\n", "").split("/")
            if(sender_user[0] in username):
                possible_target_users = sender_user[1].split(",")
                if(not(target_username in possible_target_users)):
                    verified_user = False


    # If the certificate is not valid, then the connection gets cancelled
    # CANCELLED CONNECTION
    if(not(verified_certificate) and not(verified_user)):
        with socket.create_connection((ip_addr, 6191)) as conn:
            try:
                with open('LOG/failed.json') as file:
                    failed_data = json.load(file)
            except IOError:
                    failed_data = failed_data

            failed_data['conexiones fallidas'].append({
                'IP': ip_addr,
                'Dominio:': accepted_ip,
                'Nombre': name,
                'Fecha': str(datetime.datetime.now()),
                'Motivo': "Certificado no valido" if(not(verified_certificate)) else "Se conecta desde un usuario no permitido"})
            with open('LOG/failed.json', 'w') as file:
                json.dump(failed_data, file, indent=4)

            conn.send("false 2".encode())

        return

    # Sending the AES key and the nonce
    with socket.create_connection((ip_addr, 6191)) as conn:
        # Nonce
        # Random number from 1000 to 9999
        nonce = random.randint(1000, 9999)

        # Encrypting the AES key with the corresponding algorithm
        if(tls_version == "TLS 1.2"):
            aes_key = get_random_bytes(32)
            message = str(rsa.RSACipher.encrypt(int.from_bytes(aes_key, sys.byteorder), n, exp)) + " " + str(nonce)
        elif(tls_version == "TLS 1.3"):
            aes_key = h.sha256()
            aes_key_point = ecc.S256Point.generate_random_point()
            aes_key.update(str(aes_key_point).encode("utf-8"))
            aes_key = aes_key.hexdigest()
            aes_key = int(aes_key, 16).to_bytes(32, sys.byteorder)
            message = str(ecc.S256Point.encrypt(aes_key_point, public_key)) + " " + str(nonce)
        elif(tls_version == "TLS 1.5" or tls_version == "TLS 2.0"):
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
            message = str(lines[1]) + " " + str(nonce)
            for i in range(len(line0)):
                line0[i] = int(line0[i])

            aes_key = bytes(line0)
            os.remove("help.txt")

        conn.send(message.encode())

    # Waiting for the answer
    # The encrypted answer must be the nonce
    with socket.create_server((ip, 6192)) as server:
        conn, address = server.accept()
        text_received = conn.recv(1024)

    # Getting the AES nonce
    aes_nonce = text_received[:AES.block_size]
    # Getting the tag
    tag = text_received[AES.block_size:AES.block_size * 2]
    # Getting the encypted text
    ciphertext = text_received[AES.block_size * 2:]

    # Creating the cipher
    aescipher = AES.new(aes_key, AES.MODE_EAX, aes_nonce)

    # Decoding, decrypting and verifying
    decrypted_verified_text = aescipher.decrypt_and_verify(ciphertext, tag)
    decoded_decrypted_verified_text = decrypted_verified_text.decode("utf-8")

    # If the decoded_decrypted_verified_text is equal to the nonce, then send true
    if(decoded_decrypted_verified_text == str(nonce)):
        with socket.create_connection((ip_addr, 6193)) as conn:

            try:
                with open('LOG/accepted.json') as file:
                    accepted_data = json.load(file)
            except IOError:
                    accepted_data = accepted_data

            accepted_data['conexiones'].append({
                'IP': ip_addr,
                'Dominio:': accepted_ip,
                'Nombre': name,
                'Fecha': str(datetime.datetime.now())})
            with open('LOG/accepted.json', 'w') as file:
                json.dump(accepted_data, file, indent=4)

            conn.send("true".encode())
    # CANCELLED CONNECTION
    else:
        with socket.create_connection((ip_addr, 6193)) as conn:
            try:
                with open('LOG/failed.json') as file:
                    failed_data = json.load(file)
            except IOError:
                    failed_data = failed_data
            failed_data['conexiones fallidas'].append({
                'IP': ip_addr,
                'Dominio:': accepted_ip,
                'Nombre': name,
                'Fecha': str(datetime.datetime.now()),
                'Motivo': "Conectado desde otra IP no permitida en el certificado"})
            with open('LOG/failed.json', 'w') as file:
                json.dump(failed_data, file, indent=4)

            conn.send("false".encode())

    return

# Starting the communication
def main(ip_addr):
    readIssuingKeysFile()
    with socket.create_server((ip_addr, 6190)) as server:
        conn, address = server.accept()
        client_thread = threading.Thread(target=handleClient, args=(conn, address, ip_addr))
        client_thread.start()

# Getting the interface
interfaces = netifaces.interfaces()

# Filter the IPs to not to include the loopback one
filtered_ip = []

for interface in interfaces:
    addresses = netifaces.ifaddresses(interface)
    if netifaces.AF_INET in addresses:
        for address in addresses[netifaces.AF_INET]:
            if "addr" in address and not address["addr"].startswith("127."):
                filtered_ip.append(address["addr"])

CHECK_IP = False
if len(sys.argv) > 1:
    parameter = sys.argv[1]
    if(parameter == "-ip"):
        CHECK_IP = True

file = open("CONF/server.txt", "w")
file.write("The server started at {}".format(filtered_ip[0]))
file.close()

while True:
    main(filtered_ip[0])
