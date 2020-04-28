from cryptography.hazmat.backends import  default_backend
from cryptography.hazmat.primitives.asymmetric import rsa,padding
from cryptography.hazmat.primitives import serialization ,hashes
import os
from base64 import b64encode
class CryptoRSA:
    PRIVATE_KEY_FILE = "private_key.pem"
    PUBLIC_KEY_FILE = "public_key.pem"
    def __init__(self):
        return
    def __save_file(self, contents, file_name):
        f = open(file_name, 'wb')
        f.write(contents)
        f.close()
# read file ,and dserialize the public and private portions of the RSA key pair separately to strings
    def read_file(self,filepath,name_key):
            with open(filepath,"rb") as key_file:
                if name_key=="public":
                    public_key = serialization.load_pem_public_key(
                            key_file.read(),
                            backend=default_backend()
                        )
                    return public_key
                elif name_key=="private":
                    private_key = serialization.load_pem_private_key(
                        key_file.read(),
                        password=None,
                        backend=default_backend()

                    )
                    return private_key


    def generate_random(self):
        return os.urandom()
    def generate_keys(self): #generate the key pairs
        private_key=rsa.generate_private_key(key_size=4096,
                                             public_exponent=65537,
                                             backend=default_backend() )
        #generate the public key from the private key
        public_key =private_key.public_key()
        #storing the keys
        pem_private=private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        pem_public=public_key.public_bytes(
            encoding =serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.__save_file(pem_private,self.PRIVATE_KEY_FILE)
        self.__save_file(pem_public,self.PUBLIC_KEY_FILE)
        print ("Public & Private Keys generated and saved sucessfully!")
    def encrypt(self,cleartext):
        public_key=self.read_file("public_key.pem","public") #load the public 
        encrypted=public_key.encrypt(
                cleartext,
                padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA512()),
                algorithm=hashes.SHA512(),
                label=None
                )
            )
        return encrypted
    def decrypt(self,ciphertext): 
        private_key=self.read_file("private_key.pem","private") #load the private key after serialization
        decrypted=private_key.decrypt(
                ciphertext,
                padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA512()),
                algorithm=hashes.SHA512(),
                label=None
                )
            )
        return decrypted

CryptoRSA().generate_keys() #create a new instance of the class

encrypted_data = CryptoRSA().encrypt(b'I love cryptography') 
#encrypt  the message
print("[+]Encrypting....{}\n")
print("the encrypted message is {}".format(b64encode(encrypted_data)))
#Decrypt the message 
decrypted_data=CryptoRSA().decrypt(encrypted_data)
print("[+]Decrypting....\n")
print("the decrypted message is {}".format(decrypted_data))
