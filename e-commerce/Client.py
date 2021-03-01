import random
import socket
import datetime
import crypto_lib
import socket_functions
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

# AES keys
aes_key = b'$P\xb5I8\xcb\xd2y\xa7\xad\x8c\xb3\xb7Se\xed\xe1|\xeeu\x9e\x8f\x0f8{\xa9{sO\xc1\xfdL'
aes_iv = b'\xcd!9\xae\xc1\xd0/Yv\xc8\x02x\xdc\x89\xa9\xa6'

# RSA keys
with open("Keys/client_rsa_priv_key.txt", "rb") as key_file:
    private_key_rsa = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
    )

with open("Keys/client_rsa_pub_key.txt", "rb") as key_file:
    public_key_rsa = serialization.load_pem_public_key(
        key_file.read()
    )

with open("Keys/merchant_rsa_pub_key.txt", "rb") as key_file:
    public_key_rsa_merchant = serialization.load_pem_public_key(
        key_file.read()
    )

with open("Keys/pg_rsa_pub_key.txt", "rb") as key_file:
    public_key_rsa_pg = serialization.load_pem_public_key(
        key_file.read()
    )

def generate_cert_client():
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"mysite.com"),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        # Our certificate will be valid for 10 days
        datetime.datetime.utcnow() + datetime.timedelta(days=10)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False
    ).public_key(public_key_rsa).sign(private_key_rsa, hashes.SHA256())

    return cert


def send_message_1(client_socket):
    client_temporary_cert = generate_cert_client()
    cert_to_send = crypto_lib.serialize_cert(client_temporary_cert)
    encrypted_cert_to_send = crypto_lib.encrypt_AES(cert_to_send, aes_key, aes_iv)
    encrypted_aes_key = crypto_lib.encrypt_RSA(aes_key, public_key_rsa_merchant)
    encrypted_aes_iv = crypto_lib.encrypt_RSA(aes_iv, public_key_rsa_merchant)
    message_to_send = socket_functions.concat_messages(encrypted_cert_to_send, encrypted_aes_key, encrypted_aes_iv)
    socket_functions.socket_send(client_socket, message_to_send)


def recv_message_2(client_socket):
    message = socket_functions.socket_recv(client_socket)
    message = crypto_lib.decrypt_AES(message, aes_key, aes_iv)
    merchant_SID, merchant_SID_signature = socket_functions.split_message(message)
    print(crypto_lib.bytes_to_int(merchant_SID))
    if crypto_lib.verify_signature_is_valid(merchant_SID_signature, merchant_SID, public_key_rsa_merchant):
        print("The signature is from the merchant")
    else:
        print("The signature is invalid")
    return merchant_SID


def send_message_3(client_socket, merchant_SID):
    NC = random.randint(100000, 10000000000)
    PI= socket_functions.concat_messages(b"123456789101", b"11/22", b"123", merchant_SID, b"500", crypto_lib.serialize_pub_RSA_key(public_key_rsa), crypto_lib.int_to_bytes(NC), b"Merchant name")
    SIG_PI= crypto_lib.sign(PI, private_key_rsa)
    PM = socket_functions.concat_messages(PI , SIG_PI)
    encripted_PM = crypto_lib.encrypt_RSA(PM, public_key_rsa_pg)
    PO = socket_functions.concat_messages(b"5 morcovi la 10 lei kg", merchant_SID, b"500", crypto_lib.int_to_bytes(NC),crypto_lib.sign(socket_functions.concat_messages(b"5 morcovi la 10 lei kg", merchant_SID, b"500", NC), private_key_rsa))
    message_to_send=crypto_lib.encrypt_AES(socket_functions.concat_messages(encripted_PM,PO),aes_key,aes_iv)
    socket_functions.socket_send(client_socket, message_to_send)

def recv_message_6(client_socket):
    pass


def client_program():
    host = socket.gethostname()  # as both code is running on same pc
    port = 5000  # socket server port number
    merchant_socket = socket.socket()  # instantiate
    merchant_socket.connect((host, port))  # connect to the server
    print(type(public_key_rsa))
    # Setup sub-protocol
    send_message_1(merchant_socket)
    merchant_SID = recv_message_2(merchant_socket)

    # Exchange sub-protocol
    send_message_3(merchant_socket, merchant_SID)
    recv_message_6(merchant_socket)

    merchant_socket.close()  # close the connection


if __name__ == '__main__':
    client_program()

