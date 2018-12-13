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
    #method for logging in    
def login():
    username = input("Please enter your username:")
    password = input("Please enter your password:")
    payload = {'name':username, 'password':password}
    
    #post request to api
    request = requests.post(url = "https://raychin.me/api/authenticate",data = payload)
    #api checks if user/pass is valid 
    if(request.status_code == 200):
        jsonData = request.json()
        #if false respond with this
        if(jsonData['success']==False):
            print("Invalid Username/Password\n")
            return
        #otherwise they get a token :D
        token = jsonData['token']
        messenger(token)
    
   
    else:
        #if this pops up the server must be down D:
        print("Couldn't connnect")
        return
     #method for registering   
def register():
    username = input("Please enter your username:")
    password = input("Please enter your password:")
    payload = {'name':username, 'password':password}
    #post request api, url is important must be correct
    request = requests.post(url = "https://raychin.me/setup",data = payload)
    #adds to user to server 
    if(request.status_code == 200):
        jsonData = request.json()
        #if username is taken then choose another
        if(jsonData['success']==False):
            print("User already exists")
            return   
   
    else:
        #coudln't connect server must be down D:
        print("Couldn't connnect")
        return
        #method for our messenging
def messenger(token):
    print("Welcome to Game of Thread's messenging app")
    choice = input("Please enter a number for your choice:\n1. Read\n2. Send\n3. Quit\n")
    tokenparam = {'token': token}
    #receives messages sent to you
    if(choice == "1"):
        #get request to check if user has any messages
        requestMessage = requests.get(url = "https://raychin.me/api/message", params = tokenparam)
        #data is the encrypted message 
        data = requestMessage.json()
        #checks for private key since to verify identity and to decrypt message
        #without it the message is unreadable
        privateKlocation = input("Please enter your private key file name:(Default private.pem)")
        if(privateKlocation == ""):
            privateKlocation = "private.pem"
        try:
            f = open(privateKlocation,"r")
        except:
            print("Couldn't find privateKey file! \n")
            messenger(token)
        
        privateKey = EncryptDecrypt.RSA.importKey(f.read())
        #With the private key user will be able to decrypt the message
        #getting the following values
        print("\n Messages \n-------------------------------\n")
        for x in data:
            sendervar = x['sender']
            textvar = x['text']
            RSACiphervar = x['RSACipher']
            tagvar = x['tag']
            IVvar = x['IV']
            #decrypts the message using method from EncryptionDecryption
            try:
                decryptedtext = EncryptDecrypt.decryption(RSACiphervar, textvar, tagvar, IVvar, privateKey)
                print(sendervar + ": " + decryptedtext)
            except:
                print(": Failed to decrypt message sent by " + sendervar)
        print("\n")
        #sending a messsage
    if(choice == "2"):
        #gotta get the receiver
        receiver = input("Who do you want to send a message to? \n")
        text = input("Please enter your message:")
        #Encrypt our message
        #have to have your public key info for RSA
        publicKlocation = input("Please enter their publicKey filename:")
        try:
            f = open(publicKlocation,"r")
        except:
            print("Couldn't find publicKey file! \n")
            messenger(token)
        publicKey = EncryptDecrypt.RSA.importKey(f.read())
        #once you have it you can encrypt using the encryption method from EncryptDecrypt
        RSACipher,ciphertext,tag,IV = EncryptDecrypt.encryption(text,publicKey)
        payload = {'receiver': receiver, 'text': ciphertext, 'RSACipher': RSACipher, 'tag': tag, 'IV': IV}
        #post request to send message
        requestMessage = requests.post(url = "https://raychin.me/api/message", params = tokenparam, data = payload)
    if(choice == "3"):
        sys.exit(0)
        
    messenger(token)    
    return

main()