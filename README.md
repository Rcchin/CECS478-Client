# CECS478-Client
Welcome! This is the client side code for our End to End Encryption Chat application. Everything related to the client can be found here. This will cover all design and documentation.

## Contributors
* Raymond Chin
* Michael Ly

## Getting Started

This document will help you understand what we have built here and the limitations of our implementation. 

## Prerequisites

For this code you must have both files in the same directory. Also this code won't be working in the future since we will be shutting down the server soon. However if you want to test or use this code you will be able to find our server code [here](https://github.com/Rcchin/CECS478-Server)

## End to End Chat

Built this project from multiple steps. Ultimate goal is to create a end to end encrption chat. Therefore even the server is an adversary. However was not able to implement 

### Client Side
Our UI is very basic. It can be run from command line or from your favorite IDE. We created this mostly on Spyder. But here we focused mainly on being able to encrypt and decrypt messages using client server code. GET and POST requests are made to the RESTful API to exchange these encrypted messages to then later be decrypted on receivers end. However our way of exchanging Private and Public Keys is cumbersome to users as it must be physcial. Must look for better alternatives in the future.

By using libraries we were able to easily use AES, OAEP, PKCS7, SHA256,and RSA. This phase of the project we followed PGP principles to design our encapsulation and decapsulation of messages.The encrypted message hashed andsent with AESkey concatenated with HMAC key, the latter is encrypted with sender’s publickey. Once received the message is split, the is key decrypted using the receiver’s private key and separated into AESkey and HMAC key.. HMAC is used to verify the tags while AES used to
decrypt.

We had to create a new model, routes, and controllers for messages. The model had many
attributes: sender, receiver, text, RSACipher,tag, and IV. This was necessary because we had to
pass these parameters to our encrypt method. The sender and receiver were important for the
program to know who to send the message too. Also because we couldn’t implement a better
solution in time we have our users exchange public private keys in person. Although it can be
cumbersome it is safe. Text is our encrypted and hashed message. RSACipher is our AESkey
and HMAC key concatenated then encrypted with public key of sender gets decrypted with
private key of receiver. Tag is needed to verify the integrity of the message and IV is used with
the key to decrypt. Basically we had our users making GET and POST requests to our RESTful
API to exchange these packages of encrypted messages. Encryption and decryption was done
client side. The receiver then would use the get request to get the information in json format. The
program would then unpackage it and use the decrypt method to decrypt the message.

## Adversary Model and Attack Surfaces
For our adversary model we wanted to prevent outsiders with low computational power and that are active. However our implementation can be better since we made a mistake with entering passwords. Because there is a infinite amount of tries and it doesn't have any input lag therefore brute forcing becomes a better option than it should. 

In our attack surfaces we are vulnerable to bruteforce of password because of the reason stated above. We are also vulnerable to man in the middle attacks since we weren't able to combine Diffie Hellman and RSA. Eavesdroppers are hard to prevent therefore we couldn't do much. Server related attacks we depend on AWS security and we are sure they are quite reliable. We were able to prevent rainbow attack since we salt and hash our passwords in the database. 


## Built With
'''
* Python
* RESTful API created on AWS Ubuntu

'''



