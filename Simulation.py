import os
import ecc
import Certificate

class Device:
    DEVICES = 0
    def __init__(self):
        self.device_id = Device.DEVICES
        Device.DEVICES = Device.DEVICES + 1

    def __repr__(self):
        return "I am the Device number {}".format(self.getId())

    def getId(self):
        return self.device_id

    def sendMessage(self, device_id, message, message_type)
        pass

    def rcvMessage(self, device_id, message, message_type)
        pass

class Server(Device):
    def __init__(self):
        super().__init__()
        self.certificate = os.getcwd() + "/cert.txt"
        
    def __repr__(self):
        return "I am a Server (id={})".format(self.getId())

    def printCertificate(self):
        # Open and read the file
        file = open(self.certificate, "r")
        certificate_text = file.readlines()
        file.close()

        for line in certificate_text:
            print(line)

    def rcvMessage(self, device_id, message, message_type):
        if(message_type == 1):
            message_to_send = "{}. Here it is my certificate.".format(self)
            print(message_to_send)
            self.printCertificate()
            
            
    
class Client(Device):
    def __init__(self):
        super().__init__()
        
    def __repr__(self):
        return "I am a Client (id={})".format(self.getId())

    def sendMessage(self, device_id, message, message_type):
        selected_server = None
        
        for server in SERVERS:
            if(server.getId() == device_id):
                selected_server = server
                
        if(message_type == 0):
            message_to_send = "Client hello, I want to connect to server {}".format(device_id)
            print(message_to_send)
            selected_server.rcvMessage(1)

    def rcvMessage():
        

# Read the Issuing Public Key
def readKeyFile():
        # Modify the TRUSTED_KEY Global var
        global TRUSTED_KEY

        # Open and read the file
        file = open(KEY_FILE, "r")
        keys_content = file.readlines()
        file.close()

        # TLS Version
        tls_version = "TLS 1.2" if keys_content[0].replace("\n", "") == "RSA" else "TLS 1.3"

        # If TLS version is TLS 1.2, it reads the file this way
        if(tls_version == "TLS 1.2"):
            # Exponent
            e = int(keys_content[1].replace("Exponente: ", "").replace("\n", ""))
            # Module
            n = int(keys_content[2].replace("Módulo: ", "").replace("\n", ""))

            # Assigning the value to the ISSUING_KEYSET global
            TRUSTED_KEY = [e, n]

        # If TLS version is TLS 1.3, it reads the file this way
        elif(tls_version == "TLS 1.3"):
            # Public Key
            line = keys_content[1].replace("Clave pública: S256Point(", "").replace(")\n", "").split(", ")
            publicKey_x = int(line[0], 16)
            publicKey_y = int(line[1], 16)

            # Assigning the value to the ISSUING_KEYSET global
            TRUSTED_KEY = ecc.S256Point(publicKey_x, publicKey_y)
    

SERVERS = [Server()]
KEY_FILE = os.getcwd() + "/KEYS/issuing_keys.txt"
TRUSTED_KEY = None
readKeyFile()

        
