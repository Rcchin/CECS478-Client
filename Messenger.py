# -*- coding: utf-8 -*-
"""
Created on Mon Dec 10 11:15:46 2018

@author: Raymond Chin & Michael Ly
"""
import EncryptDecrypt
import os
import sys
import requests
import json


#from EncryptDecrypt import encryption
#from EncryptDecrypt import decryption
#from EncryptDecrypt import RSAKeyGen

def main():
    EncryptDecrypt.RSAKeyGen("private.pem","public.pem")
    print("Welcome to Game of Thread's messenging app")
    choice = input("Please enter a number for your choice:\n1. Login\n2. Register\n3. Quit\n")
    
    if(choice == "1"):
        login()
    if(choice == "2"):
        register()
    if(choice == "3"):
        sys.exit(0)
    else:
        main()
        return
        
def login():
    username = input("Please enter your username:")
    password = input("Please enter your password:")
    payload = {'name':username, 'password':password}
    
    request = requests.post(url = "https://raychin.me/api/authenticate",data = payload)
    
    if(request.status_code == 200):
        jsonData = request.json()
        if(jsonData['success']==False):
            print("Invalid Username/Password\n")
            return
        token = jsonData['token']
        messenger(token)
    
   
    else:
        print("Couldn't connnect")
        return
        
def register():
    username = input("Please enter your username:")
    password = input("Please enter your password:")
    payload = {'name':username, 'password':password}

    request = requests.post(url = "https://raychin.me/setup",data = payload)
    
    if(request.status_code == 200):
        jsonData = request.json()
        if(jsonData['success']==False):
            print("User already exists")
            return   
   
    else:
        print("Couldn't connnect")
        return
        
def messenger(token):
    print("Welcome to Game of Thread's messenging app")
    choice = input("Please enter a number for your choice:\n1. Read\n2. Send\n3. Quit\n")
    tokenparam = {'token': token}
    if(choice == "1"):
        requestMessage = requests.get(url = "https://raychin.me/api/message", params = tokenparam)
        data = requestMessage.json()
        privateKlocation = input("Please enter your private key file name:(Default private.pem)")
        if(privateKlocation == ""):
            privateKlocation = "private.pem"
        try:
            f = open(privateKlocation,"r")
        except:
            print("Couldn't find privateKey file! \n")
            messenger(token)
        privateKey = EncryptDecrypt.RSA.importKey(f.read())
        print("\n Messages \n-------------------------------\n")
        for x in data:
            sendervar = x['sender']
            textvar = x['text']
            RSACiphervar = x['RSACipher']
            tagvar = x['tag']
            IVvar = x['IV']
            try:
                decryptedtext = EncryptDecrypt.decryption(RSACiphervar, textvar, tagvar, IVvar, privateKey)
                print(sendervar + ": " + decryptedtext)
            except:
                print(": Failed to decrypt message sent by " + sendervar)
        print("\n")
    if(choice == "2"):
        receiver = input("Who do you want to send a message to? \n")
        text = input("Please enter your message:")
        #Encrypt our message
        publicKlocation = input("Please enter their publicKey filename:")
        try:
            f = open(publicKlocation,"r")
        except:
            print("Couldn't find publicKey file! \n")
            messenger(token)
        publicKey = EncryptDecrypt.RSA.importKey(f.read())
        RSACipher,ciphertext,tag,IV = EncryptDecrypt.encryption(text,publicKey)
        payload = {'receiver': receiver, 'text': ciphertext, 'RSACipher': RSACipher, 'tag': tag, 'IV': IV}
        requestMessage = requests.post(url = "https://raychin.me/api/message", params = tokenparam, data = payload)
    if(choice == "3"):
        sys.exit(0)
        
    messenger(token)    
    return

main()