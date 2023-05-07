import socket
# Datetime imports
import datetime as dt
from datetime import date, timedelta
# RSA and EC Cryptography imports
import RSA as rsa
import ecc as ecc
# Hash imports
import hashlib as h
import ctypes
import struct
from ctypes import *
import os
import threading
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import random
import sys
IP = socket.gethostbyname(socket.gethostname())
PORT = 4455
ADDR = (IP, PORT)
SIZE = 1024
FORMAT = "utf-8"
ISSUING_KEYSET_RSA = None
ISSUING_KEYSET_ECC = None
ISSUING_KEYSET_CRYSTALS = None
ISSUING_RSA_PUBLIC_KEY_FILENAME = os.getcwd() + "/KEYS/issuing_public_key_rsa.pub"
ISSUING_RSA_PRIVATE_KEY_FILENAME = os.getcwd() + "/KEYS/issuing_private_key_rsa"
ISSUING_ECC_PUBLIC_KEY_FILENAME = os.getcwd() + "/KEYS/issuing_public_key_ecc.pub"
ISSUING_ECC_PRIVATE_KEY_FILENAME = os.getcwd() + "/KEYS/issuing_private_key_ecc"
ISSUING_CRYSTALS_PUBLIC_KEY_FILENAME = os.getcwd() + "/KEYS/issuing_public_key_crystals.pub"
ISSUING_CRYSTALS_PRIVATE_KEY_FILENAME = os.getcwd() + "/KEYS/issuing_private_key_crystals"



























def verify(content, public_key, tls_version):
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

        
    # Obtaining information from the certificate file
    for i in range(0, len(content)):
        if("Dominio" in content[i]):
            domain = content[i].replace("Dominio: ", "").replace("\n", "").replace(" ", "")
        # Obtaining the signature
        if("Validez" in content[i]):
            extracted_date = content[i + 1].replace(" No antes: ", "").replace("\n", "").split("-")
            issuing_date = dt.datetime(int(extracted_date[0]), int(extracted_date[1]), int(extracted_date[2]))
            extracted_date = content[i + 2].replace(" No despues: ", "").replace("\n", "").split("-")
            expiration_date = dt.datetime(int(extracted_date[0]), int(extracted_date[1]), int(extracted_date[2]))

            if((issuing_date > dt.datetime.now()) or (expiration_date < dt.datetime.now())):
                valid_dates = False

        if("Modulo:" in content[i]):
            n = content[i].replace(" Modulo: ", "").replace("\n", "")
            text_to_hash_sha1 = text_to_hash_sha1 + content[i].replace(" ", "").replace("\n", "")
            continue

        if("Clave publica:" in content[i]):
            publicKey = content[i].replace(" Clave publica: ", "").replace("\n", "")
            if(tls_version == "TLS 2.0"):
                publicKey = publicKey.replace("[", "").replace("]", "").split(",")
                
        if("Firma:" in content[i]):
            if(tls_version == "TLS 1.2"):
                signature_to_verify = int(content[i].replace("Firma: 0x", "").replace("\n", ""), 16)
                    
            elif(tls_version == "TLS 1.3" or tls_version == "TLS 1.5"):
                signature_to_verify = content[i].replace("Firma: (S256Point(", "").replace(")", "").replace(" ", "").replace("\n", "").replace("0x", "").split(",")

            elif(tls_version == "TLS 2.0"):
                signature_to_verify = content[i].replace("Firma: ", "").replace(" ", "").replace("\n", "").replace("]", "").split(".")

            text_to_hash_sha1 = text_to_hash_sha1 + content[i].replace(" ", "").replace("\n", "")
            continue

        if("Longitud de la firma: " in content[i]):
            slen = int(content[i].replace("Longitud de la firma: ", "").replace("\n", ""))

        if("Huellas digitales" in content[i]):
            text_to_hash_sha1 = text_to_hash_sha1 + "Huellasdigitales"
            text_to_hash_sha256 = text_to_hash_sha1
            continue

        if("SHA-1:" in content[i]):
            sha1_to_verify = content[i].replace("SHA-1: ", "").replace("\n", "").replace(" ", "")
            text_to_hash_sha1 += "SHA-1:"
            text_to_hash_sha256 = text_to_hash_sha1 + content[i].replace(" SHA-1: ", "").replace("\n", "")
            continue

        if("SHA-256" in content[i]):
            sha256_to_verify = content[i].replace("SHA-256: ", "").replace("\n", "").replace(" ", "")
            text_to_hash_sha256 += "SHA-256:"
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
        public_key_uint8_array = (ctypes.c_uint8 * len(publicKey))()
        for i in range(0, len(publicKey)):
            public_key_uint8_array[i] = int(publicKey[i])

        # Call the C function with a string argument
        valid_certificate = True if(sign_dilithium_c.verify(signature_uint8_array, slen, dilithium_uint8_array, public_key_uint8_array) == 0) else False

    # Obtaining the hash of the key
    if(tls_version == "TLS 1.2"):
        hash_key = h.sha256()
        hash_key.update(n.encode('utf-8'))
        hash_key = int(hash_key.hexdigest().replace("0x", ""), 16)
    elif(tls_version == "TLS 1.3" or tls_version == "TLS 1.5"):
        hash_key = h.sha256()
        hash_key.update(publicKey.encode('utf-8'))
        hash_key = int(hash_key.hexdigest().replace("0x", ""), 16)

    # Obtaining the first hash
    hash_first_text = h.sha1()
    hash_first_text.update(text_to_hash_sha1.encode("utf-8"))
    hash_first_text = hash_first_text.hexdigest()

    # Obtaining the second hash
    hash_second_text = h.sha256()
    hash_second_text.update(text_to_hash_sha256.encode("utf-8"))
    hash_second_text = hash_second_text.hexdigest()

    if(not(valid_dates)):
        valid_certificate = False
        return valid_certificate

    if(not(hash_first_text == sha1_to_verify)):
        valid_certificate = False
        return valid_certificate

    if(not(hash_second_text == sha256_to_verify)):
        valid_certificate = False
        return valid_certificate            

    # Obtaining the hash from the signature
    if(tls_version == "TLS 1.2"):
        public_key = public_key.split(",")
        start_key_hash = rsa.RSASignature.verify(signature_to_verify, int(public_key[0]), int(public_key[1]))
        valid_certificate = (hash_key == start_key_hash)

    elif(tls_version == "TLS 1.3" or tls_version == "TLS 1.5"):
        valid_certificate = ecc.S256Signature.verify(hash_key, public_key, ecc.S256Point(int(signature_to_verify[0], 16), int(signature_to_verify[1], 16)), int(signature_to_verify[2], 16))
        

    return valid_certificate





















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




























def receive_file_size(sck: socket.socket):
    # Esta función se asegura de que se reciban los bytes
    # que indican el tamaño del archivo que será enviado,
    # que es codificado por el cliente vía struct.pack(),
    # función la cual genera una secuencia de bytes que
    # representan el tamaño del archivo.
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

def receive_file(sck: socket.socket, filename):
    # Leer primero del socket la cantidad de 
    # bytes que se recibirán del archivo.
    filesize = receive_file_size(sck)
    # Abrir un nuevo archivo en donde guardar
    # los datos recibidos.
    with open(filename, "wb") as f:
        received_bytes = 0
        # Recibir los datos del archivo en bloques de
        # 1024 bytes hasta llegar a la cantidad de
        # bytes total informada por el cliente.
        while received_bytes < filesize:
            chunk = sck.recv(1024)
            if chunk:
                f.write(chunk)
                received_bytes += len(chunk)


def rcv_connection():
    pass

def send():
    pass

def handle_client(conn, address):
    print(f"{address[0]}:{address[1]} conectado.")
    print("Recibiendo archivo...")
    receive_file(conn, "cert-recibida.txt")
    
    file = open("cert-recibida.txt", "r")
    cert_content = file.readlines()
    file.close()

    tls_version = cert_content[0].replace("TLS version: ", "").replace("\n", "")

    for line in cert_content:
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
                public_key = line.replace("Clave publica: ", "").replace("]\n", "").split(",")

    if(address[0] != accepted_ip):
        with socket.create_connection(("localhost", 6191)) as conn:
            print("Conectado al servidor.")
            print("Enviando archivo...")
            conn.send("false".encode())
            print("Enviado falso.")
        print("Conexión cerrada.")
        return
    print("Archivo recibido.")

    if(tls_version == "TLS 1.2"):
        verified = verify(cert_content, "{},{}".format(ISSUING_KEYSET_RSA.getN(), ISSUING_KEYSET_RSA.getE()), tls_version = tls_version)

    elif(tls_version == "TLS 1.3" or tls_version == "TLS 1.5"):
        verified = verify(cert_content, ISSUING_KEYSET_ECC.getPublicKey() if (tls_version == "TLS 1.3") else ISSUING_KEYSET_CRYSTALS.getPublicKey(), tls_version = tls_version)
        
    elif(tls_version == "TLS 2.0"):
        verified = verify(cert_content, None, "TLS 2.0")

    if(verified):
        print("Okey")
        #os.system("sshpass -p '1180' ssh juanlu-pruebas@127.0.0.1")
        with socket.create_connection(("localhost", 6191)) as conn:
            print("Conectado al servidor.")
            print("Enviando archivo...")
            nonce = random.randint(1000, 9999)
            if(tls_version == "TLS 1.2"):
                aes_key = get_random_bytes(32)
                message = str(rsa.RSACipher.encrypt(int.from_bytes(aes_key, sys.byteorder), n, exp)) + " " + str(nonce)
                print(message)
            elif(tls_version == "TLS 1.3"):
                aes_key = h.sha256()
                aes_key_point = ecc.S256Point.generate_random_point()
                aes_key.update(str(aes_key_point).encode("utf-8"))
                aes_key = aes_key.hexdigest()
                aes_key = int(aes_key, 16).to_bytes(32, sys.byteorder)
                message = str(ecc.S256Point.encrypt(aes_key_point, public_key)) + " " + str(nonce)
            elif(tls_version == "TLS 1.5" or tls_version == "TLS 2.0"):
                aes_key = get_random_bytes(32)
                encrypt_crystals_c = CDLL("SO/encrypt_crystals.so")
                key_array = (ctypes.c_uint8 * len(aes_key))(*aes_key)
                encrypt_crystals_c.encrypt.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8)]
                encrypt_crystals_c.restype = None
                for i in range(len(public_key)):
                    public_key[i] = int(public_key[i])
                public_key_array = (ctypes.c_uint8 * len(public_key))(*public_key)
                ciphertext = (ctypes.c_uint8 * 1568)()
                encrypt_crystals_c.encrypt(public_key_array, key_array, ciphertext)
                result = bytes(ciphertext[:1568])





                decrypt_crystals_c = CDLL("SO/decrypt_crystals.so")
                key_array = (ctypes.c_uint8 * len(aes_key))(*aes_key)
                decrypt_crystals_c.decrypt.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8)]
                decrypt_crystals_c.restype = None

                file = open("KEYS/127.0.0.1-crystals", "r")
                lines = file.readlines()
                file.close()

                secret_key_line = lines[1].replace("]", "").split(",")

                for i in range(len(secret_key_line)):
                    secret_key_line[i] = int(secret_key_line[i])

                secret_key_array = (ctypes.c_uint8 * len(secret_key_line))(*secret_key_line)
                shared_secret = (ctypes.c_uint8 * 32)()
                decrypt_crystals_c.decrypt(secret_key_array, shared_secret, ciphertext)
                result = bytes(shared_secret[:32])
                print("\n-------------------\n")
                for i in result:
                    print(i, end = "")
                print("\n--------------------------\n")
                for i in aes_key:
                    print(i, end="")

                return

                

            conn.send(message.encode())
            #conn.send("true".encode())
            print("Enviado.")
        print("Conexión cerrada.")
    else:
        print("False")
        with socket.create_connection(("localhost", 6191)) as conn:
            print("Conectado al servidor.")
            print("Enviando archivo...")
            conn.send("false".encode())
            print("Enviado.")
        print("Conexión cerrada.")

    with socket.create_server(("localhost", 6192)) as server:
        print("Esperando al cliente...")
        conn, address = server.accept()
        text_received = conn.recv(1024)
        print("Archivo recibido.")
    print("Conexión cerrada.")
    # Getting the nonce
    noncee = text_received[:AES.block_size]
    # Getting the tag
    tag = text_received[AES.block_size:AES.block_size * 2]
    # Getting the encypted text
    ciphertext = text_received[AES.block_size * 2:]

    # Creating the cipher again
    aescipher = AES.new(aes_key, AES.MODE_EAX, noncee)
    # Decoding, decrypting and verifying
    decrypted_verified_text = aescipher.decrypt_and_verify(ciphertext, tag)
    decoded_decrypted_verified_text = decrypted_verified_text.decode("utf-8")
    if(decoded_decrypted_verified_text == str(nonce)):
        with socket.create_connection(("localhost", 6193)) as conn:
            print("Conectado al servidor.")
            print("Enviando archivo...")
            conn.send("true".encode())
            print("Enviado.")
        print("Conexión cerrada.")
    else:
        with socket.create_connection(("localhost", 6193)) as conn:
            print("Conectado al servidor.")
            print("Enviando archivo...")
            conn.send("true".encode())
            print("Enviado.")
        print("Conexión cerrada.")


def main():
    _read_issuing_keys_file()
    with socket.create_server(("localhost", 6190)) as server:
        print("Esperando al cliente...")
        conn, address = server.accept()
        client_thread = threading.Thread(target=handle_client, args=(conn, address))
        client_thread.start()

while True:
    main()
