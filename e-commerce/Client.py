import socket, datetime
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

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


def pad_data_for_AES(data):
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(data)
    padded_data += padder.finalize()
    return padded_data


def unpad_data_for_AES(padded_data):
    unpadder = sym_padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data)
    data += unpadder.finalize()
    return data


def encrypt_AES(plaintext):
    plaintext = pad_data_for_AES(plaintext)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(aes_iv))
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def decrypt_AES(ciphertext):
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(aes_iv))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return unpad_data_for_AES(padded_plaintext)


def encrypt_RSA(plaintext, key):
    ciphertext = key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext


def decrypt_RSA(ciphertext, key):
    plaintext = key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext


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


def serialize_cert(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


def deserialize_client_cert(cert):
    return x509.load_pem_x509_certificate(cert, default_backend())


def send_message_1(client_socket):
    client_temporary_cert = generate_cert_client()
    cert_to_send = serialize_cert(client_temporary_cert)
    encrypted_cert_to_send = encrypt_AES(cert_to_send)
    # I use the b"END" to be able to split concatenated strings on arrival
    message_to_send = encrypted_cert_to_send + b"END"
    encrypted_aes_key = encrypt_RSA(aes_key, public_key_rsa)
    message_to_send += encrypted_aes_key
    return message_to_send

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
