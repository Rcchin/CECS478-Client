# CECS478-Client
Welcome! This is the client side code for our End to End Encryption Chat application. Everything related to the client can be found here. This will cover all design and documentation.

## Contributors
* Raymond Chin
* Michael Ly

## Getting Started

This document will help you understand what we have built here and the limitations of our implementation. 

## Prerequisites

For this code you must have both files in the same directory. Also this code won't be working in the future since we will be shutting down the server soon. However if you want to test or use this code you will be able to find our server code here](https://github.com/Rcchin/CECS478-Server)

##End to End Chat

Built this project from multiple steps. Ultimate goal is to create a end to end encrption chat. Therefore even the server is an adversary. 

###Client Side
Our UI is very basic. It can be run from command line or from your favorite IDE. We created this mostly on Spyder. But here we focused mainly on being able to encrypt and decrypt messages using client server code. GET and POST requests are made to the RESTful API to exchange these encrypted messages to then later be decrypted on receivers end. However our way of exchanging Private and Public Keys is cumbersome to users as it must be physcial. Must look for better alternatives in the future.

## Built With
'''
* Python
* RESTful API created on AWS Ubuntu
'''



