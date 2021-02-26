import socket
import socket_functions
import crypto_lib
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import random

# RSA keys
with open("Keys/merchant_rsa_priv_key.txt", "rb") as key_file:
    private_key_rsa = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
    )

with open("Keys/merchant_rsa_pub_key.txt", "rb") as key_file:
    public_key_rsa = serialization.load_pem_public_key(
        key_file.read()
    )


def generate_SID():
    SID = random.randint(100000, 10000000000)
    return crypto_lib.int_to_bytes(SID)


def recv_message_1(client_conn):
    message = socket_functions.socket_recv(client_conn)
    client_certificate, aes_key, aes_iv = socket_functions.split_message(message)
    aes_key = crypto_lib.decrypt_RSA(aes_key, private_key_rsa)
    aes_iv = crypto_lib.decrypt_RSA(aes_iv, private_key_rsa)
    client_certificate = crypto_lib.decrypt_AES(client_certificate, aes_key, aes_iv)
    client_certificate = crypto_lib.deserialize_cert(client_certificate)
    return client_certificate, aes_key, aes_iv


def send_message_2(client_conn):
    pass


def recv_message_3(client_conn):
    pass


def send_message_4(pg_socket):
    pass


def recv_message_5(pg_socket):
    pass


def send_message_6(client_conn):
    pass


def server_program():
    # get the hostname
    host = socket.gethostname()
    port = 5000  # initiate port no above 1024
    pg_port = 5001  # initiate port no above 1024

    server_socket = socket.socket()  # get instance
    # look closely. The bind() function takes tuple as argument
    server_socket.bind((host, port))  # bind host address and port together

    # configure how many client the server can listen simultaneously
    server_socket.listen(2)
    client_conn, client_address = server_socket.accept()  # accept new connection
    print("Connection from: " + str(client_address))

    # Setup sub-protocol
    recv_message_1(client_conn)
    send_message_2(client_conn)

    # Exchange sub-protocol
    # Open connection to PG
    # pg_socket = socket.socket()  # instantiate
    # pg_socket.connect((host, pg_port))  # connect to the server
    #
    # recv_message_3(client_conn)
    # send_message_4(pg_socket)
    # recv_message_5(pg_socket)
    # send_message_6(client_conn)

    # pg_socket.close()
    client_conn.close()  # close the connection

if __name__ == '__main__':
    server_program()
