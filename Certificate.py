# Datetime imports
import datetime as dt
from datetime import date, timedelta
# RSA and EC Cryptography imports
import RSA as rsa
import ecc as ecc
# Hash imports
import hashlib as h

# Globals
ISSUING_NAME = "Certlu"
ISSUING_COUNTRY = "ES"

class Certificate:
    # Builder
    def __init__(self, organization_name, organization_country, organization_location, organization_domain, tls_version, issuing_keyset):
        # Attributes
        self.organization_name = organization_name
        self.organization_country = organization_country
        self.organization_location = organization_location
        self.organization_domain = organization_domain
        self.issue_date = date.today()
        self.expiration_date = self.issue_date + timedelta(365/2)
        self.tls_version = tls_version
        self.keyset = rsa.RSA() if(self.tls_version == "TLS 1.2") else ecc.S256EC_keyset()

        self.generateFile(issuing_keyset)

    # Creates the Certificate file
    def generateFile(self, issuing_keyset):
        text = ("TLS version: " + self.tls_version +
                         "\n Información sobre la organización\n Organización: " + self.organization_name +
                         "\n País: " + self.organization_country +
                         "\n Localidad: " + self.organization_location +
                         "\n Dominio: " + self.organization_domain +
                         "\nInformación sobre la organización emisora\n Organización: " + ISSUING_NAME +
                         "\n País: " + ISSUING_COUNTRY +
                         "\nValidez\n No antes: " + str(self.issue_date) +
                         "\n No despues: " + str(self.expiration_date) +
                         "\nInformación de clave pública\n Algoritmo: ")

        # Creating the hash object for the signature and the Fingerprints
        public_key_to_sign_hash = h.sha256()
        first_fingerprint_sha1 = h.sha1()
        second_fingerprint_sha256 = h.sha256()
        
        if(self.tls_version == "TLS 1.2"):
            text = text + ("RSA\n Tamaño de la clave: 2048\n Exponente: 65537\n Módulo: " + hex(self.keyset.n) +
                         "\nFirma: ")

            # Text that will be signed
            # We delete \n and blanks
            text_to_sign = hex(self.keyset.n)
            # Hashing the text and signing it
            public_key_to_sign_hash.update(text_to_sign.encode("utf-8"))
            public_key_to_sign_hash = int(public_key_to_sign_hash.hexdigest().replace("0x", ""), 16)
            self.signature = rsa.RSASignature(rsakeyset = issuing_keyset)
            self.signature.sign(public_key_to_sign_hash)
            # Adding the Signature to the certificate file
            text = text + str(hex(self.signature.signature))
                         
        elif(self.tls_version == "TLS 1.3"):
            text = text + ("ECC\n Clave pública: " + str(self.keyset.publicKey) + "\nFirma: ")

            text_to_sign = str(self.keyset.publicKey)

            # Hashing the text and signing it
            public_key_to_sign_hash.update(text_to_sign.encode("utf-8"))
            public_key_to_sign_hash = int(public_key_to_sign_hash.hexdigest().replace("0x", ""), 16)
            self.signature = ecc.S256EC_signature(s256keyset = issuing_keyset)
            self.signature.sign(public_key_to_sign_hash)
            text = (text + "(" + str(self.signature.R) + "," + hex(self.signature.s) + ")")
                         
        # Calculating and adding the fingerprints
        text_to_sha1 = text.replace("\n", "").replace(" ", "") + "HuellasdigitalesSHA-1:"
        first_fingerprint_sha1.update(text_to_sha1.encode("utf-8"))
        text = text + "\nHuellas digitales\n SHA-1: " + first_fingerprint_sha1.hexdigest() + "\n SHA-256: "
        text_to_sha256 = text.replace(" ", "").replace("\n", "")
        second_fingerprint_sha256.update(text_to_sha256.encode("utf-8"))
        text = text + second_fingerprint_sha256.hexdigest()
        
        self.file = open("{}.txt".format(self.organization_domain), "w")
        self.file.write(text)
        self.file.close()

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
            # Obtaining the signature
            if("Validez" in content[i]):
                extracted_date = content[i + 1].replace(" No antes: ", "").replace("\n", "").split("-")
                issuing_date = dt.datetime(int(extracted_date[0]), int(extracted_date[1]), int(extracted_date[2]))
                extracted_date = content[i + 2].replace(" No despues: ", "").replace("\n", "").split("-")
                expiration_date = dt.datetime(int(extracted_date[0]), int(extracted_date[1]), int(extracted_date[2]))

                if((issuing_date > dt.datetime.now()) or (expiration_date < dt.datetime.now())):
                    valid_dates = False

            if("Módulo:" in content[i]):
                n = content[i].replace(" Módulo: ", "").replace("\n", "")
                text_to_hash_sha1 = text_to_hash_sha1 + content[i].replace(" ", "").replace("\n", "")
                continue

            if("Clave pública:" in content[i]):
                publicKey = content[i].replace(" Clave pública: ", "").replace("\n", "")
                
            if("Firma:" in content[i]):
                if(tls_version == "TLS 1.2"):
                    signature_to_verify = int(content[i].replace("Firma: 0x", "").replace("\n", ""), 16)
                    
                else:
                    signature_to_verify = content[i].replace("Firma: (S256Point(", "").replace(")", "").replace(" ", "").replace("\n", "").replace("0x", "").split(",")

                text_to_hash_sha1 = text_to_hash_sha1 + content[i].replace(" ", "").replace("\n", "")
                continue

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
            

        # Obtaining the hash of the key
        if(tls_version == "TLS 1.2"):
            hash_key = h.sha256()
            hash_key.update(n.encode('utf-8'))
            hash_key = int(hash_key.hexdigest().replace("0x", ""), 16)
        else:
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
            start_key_hash = rsa.RSASignature.verify(signature_to_verify, public_key)
            valid_certificate = (hash_key == start_key_hash)
        else:          
            valid_certificate = ecc.S256EC_signature.verify(hash_key, public_key, ecc.S256Point(int(signature_to_verify[0], 16), int(signature_to_verify[1], 16)), int(signature_to_verify[2], 16))
        

        return valid_certificate
        
    
