# -*- coding: utf-8 -*-
from Crypto.PublicKey import RSA
import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES,PKCS1_OAEP
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.asymmetric import padding as a_padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes, hmac, padding
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
import string
import random
import os
import json
from Crypto.Hash import HMAC, SHA256


def encryption(plaintext,publicKey):
   
    # Initializes the iv and creates aesKey
    key = os.urandom(32)
    IV = 16 * '\x00'
    mode = AES.MODE_CBC
    encryptor = AES.new(key, mode, IV=IV)
    
    #need padding because IV only works for code in multiples of 16
    padder = padding.PKCS7(128).padder()
    plaintext = plaintext.encode('utf-8')
    plaintext = padder.update(plaintext)+padder.finalize()
    
   
    
    
    ##encrpyt plaintext with AES
    ciphertext = encryptor.encrypt(plaintext)
    
    #creating HMAC key 
    secret = os.urandom(32)
    
    h = hmac.HMAC(secret, hashes.SHA256(), backend=default_backend())
    h.update(ciphertext)
    #get tag to return
    tag = h.finalize()
    
    #holds aes and hmac key
    combinedKey = key + secret
    
    #Encrypt using concatenated keys using RSA
    cipher_rsa = PKCS1_OAEP.new(publicKey)
    RSACipher = cipher_rsa.encrypt(combinedKey)

    return(b64encode(RSACipher).decode('utf-8'),b64encode(ciphertext).decode('utf-8'), b64encode(tag).decode('utf-8'),IV)
    
    
def decryption(RSAC, ct, tg, IV, pathtoPrivate):
    RSACipher = b64decode(RSAC)
    ciphertext = b64decode(ct)
    tag = b64decode(tg)
 
    #Decrypt RSA combined'
    cipher_rsa = PKCS1_OAEP.new(pathtoPrivate)
    combinedKey = cipher_rsa.decrypt(RSACipher)
    
    #The first 32 are the key for AES last is the HMAC
    key = combinedKey[0:32]
    HMACkey = combinedKey[32:64]
    
    #First need to compare tag to ensure authenticity
    h = hmac.HMAC(HMACkey, hashes.SHA256(), backend = default_backend())
    h.update(ciphertext)
    #test tag to prove it works ;)
    badTag =("well this is blatantly wrong")
    badTag = bytes(badTag, 'utf-8')
    h.verify(tag)
    #If it passes it won't say anything however if it doesn't
    #it won't continue with the code instead it stops and 
    #says "Signature did not match digest"
    #print("Tag verified! Signature matches! No shenanigans going on here.")
    
    #Decrypt AES
    mode = AES.MODE_CBC
    decryptor = Cipher(algorithms.AES(key),modes.CBC(IV.encode()),default_backend()).decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    #Unpadding plaintext
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(plaintext) + unpadder.finalize()
    
    finaltext = plaintext.decode("utf-8")
    return (finaltext)
    
    


def RSAKeyGen (pathPrivateKey, pathPublicKey):
    #genereates private key
    private_key = rsa.generate_private_key(public_exponent=65537,key_size=2048,backend=default_backend())
    pem = private_key.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.TraditionalOpenSSL,encryption_algorithm=serialization.NoEncryption())
    #generates public key
    public_key = private_key.public_key()
    pub_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
    
    #creates a private pem called Private PEM. Writes private key as bytes
    with open(pathPrivateKey, 'wb') as privatePEM:
        privatePEM.write(pem)
    #creates a public pem called Public PEM. Writes key as bytes example: b'asdflkasl;kfj'
    with open(pathPublicKey, 'wb') as publicPEM:
        publicPEM.write(pub_pem)
        
    #closes writing
    privatePEM.close()
    publicPEM.close()
    
def writeToJSONFile(path, fileName, data):
    filePathNameWExt = './' + path + '/' + fileName + '.json'
    with open(filePathNameWExt, 'w') as fp:
        json.dump(data, fp)

def getJSON(filePathAndName):
    with open(filePathAndName, 'r') as fp:
        return json.load(fp)

