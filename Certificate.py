# IMPORTS
import datetime as dt
from datetime import date, timedelta
import hashlib as h
import ctypes
from ctypes import *
# LOCAL IMPORTS
import RSA as rsa
import ECC as ecc

# GLOBALS
ISSUING_NAME = "Certlu"
ISSUING_COUNTRY = "ES"

# This class defines an electronic certificate
# Attributes:
# organization_name -> (String) String for the organization name
# organization_country -> (String) String for the organization country
# organization_location -> (String) String for the organization location
# organization_domain -> (String) String for the organization domain
# issue_date -> (Datetime) Issue date of the certificate
# expiration_date -> (Datetime) Expiration date of the certificate
# tls_version -> (String) String for the TLS version of the certificate
# keyset -> (RSAKeyset, S256Keyset) Keyset of the certificate. Its type depends on the TLS version
# file -> (File) File for the certificate
# public_key_file -> (File) File for the public key of the certificate
# private_key_file -> (File) File for the private key of the certificate
class Certificate:
    # Builder
    def __init__(self, organization_name, organization_country, organization_location, organization_domain, tls_version):
        self.organization_name = organization_name
        self.organization_country = organization_country
        self.organization_location = organization_location
        self.organization_domain = organization_domain
        self.issue_date = date.today()
        self.expiration_date = self.issue_date + timedelta(365/2)
        self.tls_version = tls_version

        if(self.tls_version == "TLS 1.2"):
            self.keyset = rsa.RSAKeyset()
        elif(self.tls_version == "TLS 1.3" or self.tls_version == "TLS 1.5"):
            self.keyset = ecc.S256Keyset()
        elif(self.tls_version == "TLS 2.0"):
            self.keyset = None

    # This method creates the certificate file
    # Parameters:
    # issuing_keyset -> (RSAKeyset, S256Keyset) The issuing keyset to sign the certificate
    # Return: (int) It returns 0 if succeded, -1 if not
    def generateFile(self, issuing_keyset):
        text = ("TLS version: " + self.tls_version +
                         "\n Informacion sobre la organizacion\n Organizacion: " + self.organization_name +
                         "\n Pais: " + self.organization_country +
                         "\n Localidad: " + self.organization_location +
                         "\n Dominio: " + self.organization_domain +
                         "\nInformacion sobre la organizacion emisora\n Organizacion certificadora: " + ISSUING_NAME +
                         "\n Pais: " + ISSUING_COUNTRY +
                         "\nValidez\n No antes: " + str(self.issue_date) +
                         "\n No despues: " + str(self.expiration_date) +
                         "\nInformacion de clave publica\n Algoritmo: ")

        # Writting the text to the file
        filename = ""
        try:
            if(self.tls_version == "TLS 1.2"):
                filename = "{}-rsa.txt".format(self.organization_domain)
            elif(self.tls_version == "TLS 1.3"):
                filename = "{}-ecc.txt".format(self.organization_domain)
            elif(self.tls_version == "TLS 1.5"):
                filename = "{}-crystals.txt".format(self.organization_domain)
            else:
                filename = "{}-dilithium.txt".format(self.organization_domain)
            self.file = open(filename, "w")
            self.file.write(text)
            self.file.close()
        except IOError:
            return -1

        # Creating the hash object for the signature and the Fingerprints
        public_key_to_sign_hash = h.sha256()
        first_fingerprint_sha1 = h.sha1()
        second_fingerprint_sha256 = h.sha256()

        # Text that will be signed
        text_to_sign = ""
        
        # If the TLS VERSION is 1.2
        if(self.tls_version == "TLS 1.2"):
            # Adding the public key to the certificate file
            text = "RSA\n Tamano de la clave: 2048\n Exponente: 65537\n Modulo: " + hex(self.keyset.getN()) + "\nFirma: "

            # Text that will be signed
            text_to_sign = hex(self.keyset.getN())

            # Hashing the text and signing it
            public_key_to_sign_hash.update(text_to_sign.encode("utf-8"))
            public_key_to_sign_hash = int(public_key_to_sign_hash.hexdigest().replace("0x", ""), 16)
            signature = rsa.RSASignature(rsa_keyset = issuing_keyset)
            signature.sign(public_key_to_sign_hash)

            # Adding the Signature to the certificate file
            text = text + str(hex(signature.getSignature()))
            # Writting the new text into the certificate
            try:
                self.file = open(filename, "a")
                self.file.write(text)
                self.file.close()
            except IOError:
                return -1
            
            # Writting the keys in their respective file
            try:
                self.public_key_file = open("KEYS/{}-rsa.pub".format(self.organization_domain), "w")
                self.public_key_file.write("RSA\n{}".format(hex(self.keyset.getN())))
                self.public_key_file.close()
            except IOError:
                return -1
            
            try:
                self.private_key_file = open("KEYS/{}-rsa".format(self.organization_domain), "w")
                self.private_key_file.write("- - - - RSA PRIVATE KEY BEGINS - - - -\n{}\n- - - - RSA PRIVATE KEY ENDS - - - -".format(hex(self.keyset.getD())))
                self.private_key_file.close()
            except IOError:
                return -1
        # If the TLS VERSION is 1.3
        elif(self.tls_version == "TLS 1.3"):
            # Adding the public key to the certificate file
            text = "ECC\n Clave publica: " + str(self.keyset.getPublicKey()) + "\nFirma: "

            # Text that will be signed
            text_to_sign = str(self.keyset.getPublicKey())

            # Hashing the text and signing it
            public_key_to_sign_hash.update(text_to_sign.encode("utf-8"))
            public_key_to_sign_hash = int(public_key_to_sign_hash.hexdigest().replace("0x", ""), 16)
            signature = ecc.S256Signature(s256_keyset = issuing_keyset)
            signature.sign(public_key_to_sign_hash)

            # Adding the Signature to the certificate file
            text = (text + "(" + str(signature.getR()) + "," + hex(signature.getS()) + ")")
            # Writting the new text into the certificate
            try:
                self.file = open(filename, "a")
                self.file.write(text)
                self.file.close()
            except IOError:
                return -1
            
            # Writting the keys in their respective file
            try:
                self.public_key_file = open("KEYS/{}-ecc.pub".format(self.organization_domain), "w")
                self.public_key_file.write("ECDSA\n{}".format(self.keyset.getPublicKey()))
                self.public_key_file.close()
            except IOError:
                return -1

            try:
                self.private_key_file = open("KEYS/{}-ecc".format(self.organization_domain), "w")
                self.private_key_file.write("- - - - ECDSA PRIVATE KEY BEGINS - - - -\n{}\n- - - - ECDSA PRIVATE KEY ENDS - - - -".format(hex(self.keyset.getPrivateKey())))
                self.private_key_file.close()
            except IOError:
                return -1
        # If the TLS VERSION is 1.5
        elif(self.tls_version == "TLS 1.5"):
            # CDLL Library
            generate_encryption_keys_kyber_c = CDLL('SO/generate_encryption_keys_crystals.so')
            # generate_keys() argtypes
            generate_encryption_keys_kyber_c.generateKeys.argtypes = [ctypes.c_char_p]
            # arg for generate_keys()
            keys_filename = "KEYS/{}-crystals".format(self.organization_domain)
            # Calling the CDLL Library
            if(not(generate_encryption_keys_kyber_c.generateKeys(keys_filename.encode("utf-8")) == 0)):
                return -1

            # Read the generated Crystals keys
            try:
                file = open(keys_filename + ".pub", "r")
                generate_encryption_keys_kyber_file_content = file.readlines()
                file.close()
            except IOError:
                return -1
            
            # Adding the public key to the certificate file
            text = "CRYSTALS\n Clave publica: " + str(generate_encryption_keys_kyber_file_content[1]) + "\nFirma: "
            # Text that will be signed
            text_to_sign = str(generate_encryption_keys_kyber_file_content[1])

            # Hashing the text and signing it
            public_key_to_sign_hash.update(text_to_sign.encode("utf-8"))
            public_key_to_sign_hash = int(public_key_to_sign_hash.hexdigest().replace("0x", ""), 16)
            signature = ecc.S256Signature(s256_keyset = issuing_keyset)
            signature.sign(public_key_to_sign_hash)

            # Adding the Signature to the certificate file
            text = (text + "(" + str(signature.getR()) + "," + hex(signature.getS()) + ")")

            # Writting the new text into the certificate
            try:
                self.file = open(filename, "a")
                self.file.write(text)
                self.file.close()
            except IOError:
                return -1
        # If the TLS VERSION is 2.0
        elif(self.tls_version == "TLS 2.0"):
            # CDLL Library
            generate_encryption_keys_kyber_c = CDLL("SO/generate_encryption_keys_crystals.so")
            # generate_keys() argtypes
            generate_encryption_keys_kyber_c.generateKeys.argtypes = [ctypes.c_char_p]
            # arg for generate_keys()
            keys_filename = "KEYS/{}-dilithium".format(self.organization_domain)

            # Calling the CDLL Library
            if(not(generate_encryption_keys_kyber_c.generateKeys(keys_filename.encode("utf-8")) == 0)):
                return -1

            # Read the generated Crystals keys
            try:
                file = open(keys_filename + ".pub", "r")
                generate_encryption_keys_kyber_file_content = file.readlines()
                file.close()
            except IOError:
                return -1
            
            # Adding the public key to the certificate file
            text = "CRYSTALS\n Clave publica: " + str(generate_encryption_keys_kyber_file_content[1]) + "\nFirma: "
            
            try:
                self.file = open(filename, "a")
                self.file.write(text)
                self.file.close()
            except IOError:
                return -1
            
            # CDLL Library
            sign_dilithium_c = CDLL("SO/sign_dilithium.so")

            # sign() argtypes
            sign_dilithium_c.sign.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8)]
            
            # Reading the dilithium private sign key
            try:
                dilithium_keys_file = open("KEYS/issuing_private_key_dilithium")
                dilithium_keys_file_content = dilithium_keys_file.readlines()
                dilithium_keys_file.close()
            except IOError:
                return -1
            
            # Defining the dilithium private key
            dilithium_private_key = dilithium_keys_file_content[1].replace("\n", "").replace("[", "").replace("]", "").split(",")
            dilithium_uint8_array = (ctypes.c_uint8 * len(dilithium_private_key))()
            for i in range(0, len(dilithium_private_key)):
                dilithium_uint8_array[i] = int(dilithium_private_key[i])

            # Defining the crystals public key
            crystals_public_key = generate_encryption_keys_kyber_file_content[1].replace("\n", "").replace("[", "").replace("]", "").split(",")
            crystals_uint8_array = (ctypes.c_uint8 * len(crystals_public_key))()
            for i in range(0, len(crystals_public_key)):
                crystals_uint8_array[i] = int(crystals_public_key[i])

            # Sign the crystals public key
            string = filename.encode('utf-8')
            sign_dilithium_c.sign(string, dilithium_uint8_array, crystals_uint8_array)

        # Calculating and adding the fingerprints
        self.file = open(filename, "r")
        file_content = self.file.readlines()
        self.file.close()

        text_to_sha1 = ""
        text_to_sha256 = ""

        for line in file_content:
            text_to_sha1 = text_to_sha1 + line.strip().replace("\n", "").replace(" ", "")

        text_to_sha1 = text_to_sha1 + "HuellasdigitalesSHA-1:0x"
        first_fingerprint_sha1.update(text_to_sha1.encode("utf-8"))

        text_to_sha256 = text_to_sha1 + first_fingerprint_sha1.hexdigest() + "SHA-256:0x"
        second_fingerprint_sha256.update(text_to_sha256.encode("utf-8"))
        text = text + second_fingerprint_sha256.hexdigest()

        # Writing the new text into the certificate
        text = "\nHuellas digitales\n SHA-1: 0x" + first_fingerprint_sha1.hexdigest() + "\n SHA-256: 0x" + second_fingerprint_sha256.hexdigest() 
        self.file = open(filename, "a")
        self.file.write(text)
        self.file.close()

        return 0

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
        
    
