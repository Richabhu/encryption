#!/usr/bin/python3
import os
import os.path
import time
import uuid

from Crypto import Random
from Crypto.Cipher import AES
from ellipticcurve.ecdsa import Ecdsa
from ellipticcurve.privateKey import PrivateKey


class Encryptor:
    """
    AES encrption
    """
    def __init__(self, key):
        self.key = key

    def pad(self, s):
        return s + b"\0" * (AES.block_size - len(s) % AES.block_size)   #pad to make 128 bit

    def encrypt(self, message, key, key_size=256):
        message = self.pad(message)
        iv = Random.new().read(AES.block_size)  #generates cryptographically random bytes
        cipher = AES.new(key, AES.MODE_CBC, iv)  #generates new cipher key
        return iv + cipher.encrypt(message)

    def encrypt_file(self, file_name):
        with open(file_name, 'rb') as fo:
            plaintext = fo.read()
        enc = self.encrypt(plaintext, self.key)
        with open(file_name + ".enc", 'wb') as fo:
            fo.write(enc)
        os.remove(file_name)

    def decrypt(self, ciphertext, key):
        iv = ciphertext[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext[AES.block_size:])
        return plaintext.rstrip(b"\0")

    def decrypt_file(self, file_name):
        with open(file_name, 'rb') as fo:
            ciphertext = fo.read()
        dec = self.decrypt(ciphertext, self.key)
        with open(file_name[:-4], 'wb') as fo:
            fo.write(dec)
        os.remove(file_name)

    # def getAllFiles(self):
    #     dir_path = os.path.dirname(os.path.realpath(__file__))
    #     dirs = []
    #     for dirName, subdirList, fileList in os.walk(dir_path):
    #         for fname in fileList:
    #             if (fname != 'script.py' and fname != 'data.txt.enc'):
    #                 dirs.append(dirName + "\\" + fname)
    #     return dirs
    #
    # def encrypt_all_files(self):
    #     dirs = self.getAllFiles()
    #     for file_name in dirs:
    #         self.encrypt_file(file_name)
    #
    # def decrypt_all_files(self):
    #     dirs = self.getAllFiles()
    #     for file_name in dirs:
    #         self.decrypt_file(file_name)


aes_key = b'[EX\xc8\xd5\xbfI{\xa2$\x05(\xd5\x18\xbf\xc0\x85)\x10nc\x94\x02)j\xdf\xcb\xc4\x94\x9d(\x9e'


enc = Encryptor(aes_key)
clear = lambda: os.system('cls')

if os.path.isfile('data.txt.enc'):
    while True:
        password = str(input("Enter password: "))
        enc.decrypt_file("data.txt.enc")
        p = ''
        with open("data.txt", "r") as f:
            p = f.readlines()
        if p[0] == password:
            enc.encrypt_file("data.txt")
            break

    current_directory = os.getcwd()
    final_directory = os.path.join(current_directory)
    if not os.path.exists(final_directory):
        os.makedirs(final_directory)
    mac_addr = None
    with open('{}/mac.txt'.format(final_directory), 'w') as f:
        mac_addr = ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff)
                             for ele in range(0, 8 * 6, 8)][::-1])
        f.write(mac_addr)

    enc.encrypt_file('mac.txt')
    # encrypted mac address is in mac.txt.enc

    #ECDSA algo
    ecdsa_private_key = PrivateKey()    #Private key generation
    ecdsa_public_key = ecdsa_private_key.publicKey()    #public key generation
    signature = Ecdsa.sign(mac_addr, ecdsa_private_key)     #Signature gen using msg and private key

    enc.decrypt_file('mac.txt.enc')
    with open('{}/mac.txt'.format(final_directory), 'r') as f:
        decrypted_msg = f.read()

    print(Ecdsa.verify(decrypted_msg, signature, ecdsa_public_key))
    print("The decrypted msg is")
    print(decrypted_msg)



else:
    while True:
        clear()
        password = str(input("Setting up stuff. Enter a password that will be used for decryption: "))
        repassword = str(input("Confirm password: "))
        if password == repassword:
            break
        else:
            print("Passwords Mismatched!")
    f = open("data.txt", "w+")
    f.write(password)
    f.close()
    enc.encrypt_file("data.txt")
    print("Please restart the program to complete the setup")
    time.sleep(15)
