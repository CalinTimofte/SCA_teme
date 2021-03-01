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
with open("Keys/client_rsa_pub_key.txt", "rb") as key_file:
    public_key_rsa_client = serialization.load_pem_public_key(
        key_file.read()
    )

with open("Keys/pg_rsa_pub_key.txt", "rb") as key_file:
    public_key_rsa_pg = serialization.load_pem_public_key(
        key_file.read()
    )

# AES keys
aes_key_merchant_pg = b'\xce\x05S\x94\xd2\xf9\xffs\x1d\xb9\xe2\xdc\x14a(\xb5\xac!\xe9\xa2\xc1d\xc1"\x9f\xb3\x9c\x99\xc5\x91\xb9\x9a'
aes_iv_merchant_pg = b'\xa8ff\xd1y\x97\xdaNP\xaf\xe1\xb5GS\xec\xed'


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


def send_message_2(client_conn, aes_key, aes_iv):
    SID = generate_SID()
    print(crypto_lib.bytes_to_int(SID))
    SID_signature = crypto_lib.sign(SID, private_key_rsa)
    message_to_send = socket_functions.concat_messages(SID, SID_signature)
    encrypted_message_to_send = crypto_lib.encrypt_AES(message_to_send, aes_key, aes_iv)
    socket_functions.socket_send(client_conn, encrypted_message_to_send)
    return SID


def recv_message_3(client_conn, aes_key, aes_iv):
    message = socket_functions.socket_recv(client_conn)
    message = crypto_lib.decrypt_AES(message, aes_key, aes_iv)
    PM, OrderDesc, SID, amount, NC, sig_PO, aes_key_client_PG_encrypted, aes_iv_client_PG_encrypted = socket_functions.split_message(
        message)
    checkSid = socket_functions.concat_messages(OrderDesc, SID, amount, NC)
    if crypto_lib.verify_signature_is_valid(sig_PO, checkSid, public_key_rsa_client):
        print("The signature is from the client ")
    else:
        print("The signature is invalid")
    return PM, amount, aes_key_client_PG_encrypted, aes_iv_client_PG_encrypted


def send_message_4(pg_socket, PM, SID, amount, client_certificate, aes_key_client_PG_encrypted, aes_iv_client_PG_encrypted):
    sigM = crypto_lib.sign(socket_functions.concat_messages(SID, client_certificate, amount), private_key_rsa)
    message_to_send = socket_functions.concat_messages(PM, sigM, aes_key_client_PG_encrypted, aes_iv_client_PG_encrypted)
    encrypted_aes_key_PG = crypto_lib.encrypt_RSA(aes_key_merchant_pg, public_key_rsa_pg)
    encrypted_aes_iv_PG = crypto_lib.encrypt_RSA(aes_iv_merchant_pg, public_key_rsa_pg)
    message_to_send = crypto_lib.encrypt_AES(message_to_send, aes_key_merchant_pg, aes_iv_merchant_pg)
    message_to_send = socket_functions.concat_messages(message_to_send, encrypted_aes_key_PG, encrypted_aes_iv_PG)
    socket_functions.socket_send(pg_socket, message_to_send)


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
    client_certificate, aes_key_client_merchant, aes_iv_client_merchant = recv_message_1(client_conn)
    SID = send_message_2(client_conn, aes_key_client_merchant, aes_iv_client_merchant)

    # Exchange sub-protocol
    # Open connection to PG
    pg_socket = socket.socket()  # instantiate
    pg_socket.connect((host, pg_port))  # connect to the server
    #
    PM, amount, aes_key_client_PG_encrypted,  aes_iv_client_PG_encrypted = recv_message_3(client_conn, aes_key_client_merchant, aes_iv_client_merchant)
    send_message_4(pg_socket, PM, SID, amount, client_certificate, aes_key_client_PG_encrypted, aes_iv_client_PG_encrypted)

    # recv_message_5(pg_socket)
    # send_message_6(client_conn)

    pg_socket.close()
    client_conn.close()  # close the connection


if __name__ == '__main__':
    server_program()
