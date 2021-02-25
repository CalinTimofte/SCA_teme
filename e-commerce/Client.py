import socket, os
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

aes_key = b'$P\xb5I8\xcb\xd2y\xa7\xad\x8c\xb3\xb7Se\xed\xe1|\xeeu\x9e\x8f\x0f8{\xa9{sO\xc1\xfdL'
aes_iv = b'\xcd!9\xae\xc1\xd0/Yv\xc8\x02x\xdc\x89\xa9\xa6'


def send_message_1(client_socket):
    pass


def recv_message_2(client_socket):
    pass


def send_message_3(client_socket):
    pass


def recv_message_6(client_socket):
    pass


def client_program():
    host = socket.gethostname()  # as both code is running on same pc
    port = 5000  # socket server port number

    merchant_socket = socket.socket()  # instantiate
    merchant_socket.connect((host, port))  # connect to the server

    # Setup sub-protocol
    send_message_1(merchant_socket)
    recv_message_2(merchant_socket)

    # Exchange sub-protocol
    send_message_3(merchant_socket)
    recv_message_6(merchant_socket)

    merchant_socket.close()  # close the connection

# if __name__ == '__main__':
#     client_program()
